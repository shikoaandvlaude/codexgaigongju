#!/usr/bin/env python3
"""
Change Monitor — 变化检测 + 通知模块
定期扫描目标，检测新资产/新端点/新JS文件，通知猎人第一时间测试

核心能力：
1. 子域名变化检测（新增子域名）
2. HTTP 响应变化（页面内容/状态码改变）
3. JS 文件变化（新增/修改的 JS bundle）
4. 新 API 端点发现
5. 证书透明度监控（新签发证书→新子域名）
6. Webhook 通知（飞书/钉钉/Telegram/Discord/微信）

用法:
    monitor = ChangeMonitor(config={
        "targets": ["target.com"],
        "check_interval": 3600,  # 每小时检查一次
        "webhook_url": "https://hooks.slack.com/...",
        "db_path": "~/.bai-agent/monitor.db",
    })
    
    # 单次检查
    changes = await monitor.check_all()
    
    # 持续监控（后台运行）
    await monitor.run_forever()
"""

import asyncio
import hashlib
import json
import os
import time
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class Change:
    """检测到的变化"""
    change_type: str = ""       # new_subdomain/new_endpoint/js_changed/status_changed
    target: str = ""
    value: str = ""
    old_value: str = ""
    severity: str = "info"      # critical/high/medium/low/info
    timestamp: float = 0.0
    details: str = ""


# ═══════════════════════════════════════════════════════════════
# Change Monitor
# ═══════════════════════════════════════════════════════════════

class ChangeMonitor:
    """变化检测 + 通知"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.targets = self.config.get("targets", [])
        self.check_interval = self.config.get("check_interval", 3600)
        self.webhook_url = self.config.get("webhook_url", "")
        self.webhook_type = self.config.get("webhook_type", "generic")  # generic/feishu/dingtalk/telegram/discord
        self.db_path = os.path.expanduser(self.config.get("db_path", "~/.bai-agent/monitor.db"))

        # 确保目录存在
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        # 初始化数据库
        self._init_db()

    def _init_db(self):
        """初始化 SQLite 数据库"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS subdomains (
            target TEXT, subdomain TEXT, first_seen REAL, last_seen REAL,
            PRIMARY KEY (target, subdomain)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS page_hashes (
            url TEXT PRIMARY KEY, hash TEXT, status_code INTEGER,
            content_length INTEGER, last_check REAL
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS js_files (
            url TEXT PRIMARY KEY, hash TEXT, size INTEGER,
            first_seen REAL, last_modified REAL
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS api_endpoints (
            target TEXT, method TEXT, url TEXT, first_seen REAL,
            PRIMARY KEY (target, method, url)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            change_type TEXT, target TEXT, value TEXT,
            old_value TEXT, severity TEXT, timestamp REAL, details TEXT
        )""")

        conn.commit()
        conn.close()

    # ─── 主入口 ────────────────────────────────────────────────

    async def check_all(self) -> list[Change]:
        """执行一次完整检查"""
        all_changes = []

        for target in self.targets:
            changes = await self._check_target(target)
            all_changes.extend(changes)

        # 保存变化记录
        self._save_changes(all_changes)

        # 发送通知
        if all_changes and self.webhook_url:
            await self._send_notification(all_changes)

        return all_changes

    async def run_forever(self):
        """持续监控（后台运行）"""
        while True:
            try:
                changes = await self.check_all()
                if changes:
                    print(f"[{datetime.now().isoformat()}] 检测到 {len(changes)} 个变化")
            except Exception as e:
                print(f"[Error] 监控异常: {e}")

            await asyncio.sleep(self.check_interval)

    # ─── 检查逻辑 ──────────────────────────────────────────────

    async def _check_target(self, target: str) -> list[Change]:
        """检查单个目标"""
        changes = []

        if not HAS_HTTPX:
            return changes

        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
            # 1. 子域名变化检测（用 crt.sh）
            subdomain_changes = await self._check_subdomains(target, client)
            changes.extend(subdomain_changes)

            # 2. 主页响应变化
            page_changes = await self._check_page_changes(target, client)
            changes.extend(page_changes)

            # 3. JS 文件变化
            js_changes = await self._check_js_changes(target, client)
            changes.extend(js_changes)

        return changes

    async def _check_subdomains(self, target: str, client) -> list[Change]:
        """通过 crt.sh 检查新子域名"""
        changes = []

        try:
            resp = await client.get(
                f"https://crt.sh/?q=%.{target}&output=json",
                timeout=30,
            )

            if resp.status_code != 200:
                return changes

            certs = resp.json()
            current_subs = set()

            for cert in certs:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and sub.endswith(target) and "*" not in sub:
                        current_subs.add(sub)

            # 对比数据库
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            c.execute("SELECT subdomain FROM subdomains WHERE target = ?", (target,))
            known_subs = set(row[0] for row in c.fetchall())

            new_subs = current_subs - known_subs
            now = time.time()

            for sub in new_subs:
                c.execute(
                    "INSERT OR REPLACE INTO subdomains (target, subdomain, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                    (target, sub, now, now)
                )
                changes.append(Change(
                    change_type="new_subdomain",
                    target=target,
                    value=sub,
                    severity="medium",
                    timestamp=now,
                    details=f"新发现子域名: {sub}",
                ))

            # 更新已知子域名的 last_seen
            for sub in current_subs & known_subs:
                c.execute(
                    "UPDATE subdomains SET last_seen = ? WHERE target = ? AND subdomain = ?",
                    (now, target, sub)
                )

            conn.commit()
            conn.close()

        except Exception as e:
            pass

        return changes

    async def _check_page_changes(self, target: str, client) -> list[Change]:
        """检查页面内容变化"""
        changes = []
        urls_to_check = [
            f"https://{target}",
            f"https://{target}/robots.txt",
            f"https://{target}/sitemap.xml",
        ]

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        for url in urls_to_check:
            try:
                resp = await client.get(url, timeout=10)
                current_hash = hashlib.md5(resp.content).hexdigest()
                current_status = resp.status_code
                current_length = len(resp.content)

                c.execute("SELECT hash, status_code, content_length FROM page_hashes WHERE url = ?", (url,))
                row = c.fetchone()

                if row is None:
                    # 首次记录
                    c.execute(
                        "INSERT INTO page_hashes (url, hash, status_code, content_length, last_check) VALUES (?, ?, ?, ?, ?)",
                        (url, current_hash, current_status, current_length, now)
                    )
                else:
                    old_hash, old_status, old_length = row

                    if old_status != current_status:
                        changes.append(Change(
                            change_type="status_changed",
                            target=target,
                            value=f"{url} → {current_status}",
                            old_value=f"{old_status}",
                            severity="high" if current_status == 200 and old_status in (403, 404) else "medium",
                            timestamp=now,
                            details=f"页面状态码变化: {old_status} → {current_status}",
                        ))

                    elif old_hash != current_hash:
                        length_diff = abs(current_length - old_length)
                        if length_diff > 100:  # 忽略微小变化
                            changes.append(Change(
                                change_type="content_changed",
                                target=target,
                                value=url,
                                severity="low",
                                timestamp=now,
                                details=f"页面内容变化: 长度差异 {length_diff} bytes",
                            ))

                    c.execute(
                        "UPDATE page_hashes SET hash=?, status_code=?, content_length=?, last_check=? WHERE url=?",
                        (current_hash, current_status, current_length, now, url)
                    )

            except Exception:
                pass

        conn.commit()
        conn.close()
        return changes

    async def _check_js_changes(self, target: str, client) -> list[Change]:
        """检查 JS 文件变化"""
        changes = []

        try:
            # 获取首页 HTML
            resp = await client.get(f"https://{target}", timeout=10)
            if resp.status_code != 200:
                return changes

            # 提取 JS 文件 URL
            import re
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
            js_urls = [
                url if url.startswith("http") else f"https://{target}{url}" if url.startswith("/") else f"https://{target}/{url}"
                for url in js_urls
            ]

            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            now = time.time()

            for js_url in js_urls[:20]:  # 最多检查 20 个
                try:
                    js_resp = await client.get(js_url, timeout=10)
                    if js_resp.status_code != 200:
                        continue

                    current_hash = hashlib.md5(js_resp.content).hexdigest()
                    current_size = len(js_resp.content)

                    c.execute("SELECT hash, size FROM js_files WHERE url = ?", (js_url,))
                    row = c.fetchone()

                    if row is None:
                        # 新 JS 文件
                        c.execute(
                            "INSERT INTO js_files (url, hash, size, first_seen, last_modified) VALUES (?, ?, ?, ?, ?)",
                            (js_url, current_hash, current_size, now, now)
                        )
                        changes.append(Change(
                            change_type="new_js_file",
                            target=target,
                            value=js_url,
                            severity="medium",
                            timestamp=now,
                            details=f"新 JS 文件: {js_url} ({current_size} bytes)",
                        ))
                    else:
                        old_hash, old_size = row
                        if old_hash != current_hash:
                            c.execute(
                                "UPDATE js_files SET hash=?, size=?, last_modified=? WHERE url=?",
                                (current_hash, current_size, now, js_url)
                            )
                            changes.append(Change(
                                change_type="js_changed",
                                target=target,
                                value=js_url,
                                severity="high",
                                timestamp=now,
                                details=f"JS 文件内容变化: {js_url} (旧{old_size}B → 新{current_size}B)",
                            ))

                except Exception:
                    pass

            conn.commit()
            conn.close()

        except Exception:
            pass

        return changes

    # ─── 通知 ─────────────────────────────────────────────────

    async def _send_notification(self, changes: list[Change]):
        """发送通知"""
        if not self.webhook_url or not changes:
            return

        message = self._format_notification(changes)

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                if self.webhook_type == "feishu":
                    payload = {"msg_type": "text", "content": {"text": message}}
                elif self.webhook_type == "dingtalk":
                    payload = {"msgtype": "text", "text": {"content": message}}
                elif self.webhook_type == "discord":
                    payload = {"content": message}
                elif self.webhook_type == "telegram":
                    # webhook_url should be: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>
                    payload = {"text": message, "parse_mode": "Markdown"}
                else:
                    payload = {"text": message}

                await client.post(self.webhook_url, json=payload)

        except Exception:
            pass

    def _format_notification(self, changes: list[Change]) -> str:
        """格式化通知消息"""
        lines = [f"🔔 Bai-Agent 变化检测 ({datetime.now().strftime('%Y-%m-%d %H:%M')})"]
        lines.append(f"发现 {len(changes)} 个变化:\n")

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        changes.sort(key=lambda c: severity_order.get(c.severity, 5))

        for change in changes[:20]:  # 最多显示 20 条
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(change.severity, "⚪")
            lines.append(f"{icon} [{change.change_type}] {change.details}")

        if len(changes) > 20:
            lines.append(f"\n... 还有 {len(changes) - 20} 条变化")

        return "\n".join(lines)

    # ─── 持久化 ────────────────────────────────────────────────

    def _save_changes(self, changes: list[Change]):
        """保存变化记录到数据库"""
        if not changes:
            return

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        for change in changes:
            c.execute(
                "INSERT INTO changes (change_type, target, value, old_value, severity, timestamp, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (change.change_type, change.target, change.value, change.old_value,
                 change.severity, change.timestamp, change.details)
            )

        conn.commit()
        conn.close()

    def get_recent_changes(self, limit: int = 50) -> list[dict]:
        """获取最近的变化记录"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM changes ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()

        return [
            {"id": r[0], "type": r[1], "target": r[2], "value": r[3],
             "old_value": r[4], "severity": r[5], "timestamp": r[6], "details": r[7]}
            for r in rows
        ]

    def get_known_subdomains(self, target: str) -> list[str]:
        """获取已知子域名"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT subdomain FROM subdomains WHERE target = ? ORDER BY first_seen DESC", (target,))
        subs = [row[0] for row in c.fetchall()]
        conn.close()
        return subs
