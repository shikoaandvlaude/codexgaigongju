#!/usr/bin/env python3
"""
DB Store — SQLite 持久化存储
跨次运行保留历史数据，支持对比分析和去重

存储内容：
1. 目标信息（域名、scope、技术栈）
2. 发现的资产（子域名、存活主机、URL、JS文件）
3. 漏洞发现（类型、状态、证据、提交状态）
4. 扫描历史（每次运行的摘要）
5. 请求/响应记录（用于回溯分析）

用法:
    db = DBStore("~/.bai-agent/hunt.db")
    db.save_findings(target, findings)
    history = db.get_target_history(target)
    new_urls = db.get_new_urls(target, url_list)  # 只返回之前没见过的
"""

import os
import json
import time
import sqlite3
import hashlib
from datetime import datetime
from typing import Optional


class DBStore:
    """SQLite 持久化存储"""

    def __init__(self, db_path: str = "~/.bai-agent/hunt.db"):
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        conn = self._connect()
        c = conn.cursor()

        # 目标表
        c.execute("""CREATE TABLE IF NOT EXISTS targets (
            domain TEXT PRIMARY KEY,
            company_name TEXT DEFAULT '',
            tech_stack TEXT DEFAULT '{}',
            first_seen REAL,
            last_scan REAL,
            notes TEXT DEFAULT ''
        )""")

        # 子域名表
        c.execute("""CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            ip TEXT DEFAULT '',
            status_code INTEGER DEFAULT 0,
            title TEXT DEFAULT '',
            tech TEXT DEFAULT '',
            first_seen REAL,
            last_seen REAL,
            UNIQUE(target, subdomain)
        )""")

        # URL 表
        c.execute("""CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            status_code INTEGER DEFAULT 0,
            content_type TEXT DEFAULT '',
            params TEXT DEFAULT '',
            first_seen REAL,
            last_seen REAL,
            UNIQUE(target, url, method)
        )""")

        # 漏洞发现表
        c.execute("""CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            url TEXT DEFAULT '',
            param TEXT DEFAULT '',
            severity TEXT DEFAULT 'medium',
            confidence REAL DEFAULT 0.0,
            status TEXT DEFAULT 'new',
            evidence TEXT DEFAULT '',
            payload TEXT DEFAULT '',
            reproduction_steps TEXT DEFAULT '',
            submitted_to TEXT DEFAULT '',
            submitted_at REAL DEFAULT 0,
            created_at REAL,
            updated_at REAL
        )""")

        # 扫描历史表
        c.execute("""CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            mode TEXT DEFAULT 'auto',
            started_at REAL,
            finished_at REAL,
            phases_completed TEXT DEFAULT '[]',
            findings_count INTEGER DEFAULT 0,
            subdomains_count INTEGER DEFAULT 0,
            urls_count INTEGER DEFAULT 0,
            summary TEXT DEFAULT ''
        )""")

        # JS 文件表
        c.execute("""CREATE TABLE IF NOT EXISTS js_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            url TEXT NOT NULL,
            content_hash TEXT DEFAULT '',
            size INTEGER DEFAULT 0,
            secrets_found TEXT DEFAULT '[]',
            endpoints_found TEXT DEFAULT '[]',
            first_seen REAL,
            last_modified REAL,
            UNIQUE(target, url)
        )""")

        # 请求记录表（最近 N 条）
        c.execute("""CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            method TEXT,
            url TEXT,
            status_code INTEGER,
            response_length INTEGER,
            elapsed REAL,
            timestamp REAL,
            notes TEXT DEFAULT ''
        )""")

        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # ─── 目标管理 ──────────────────────────────────────────────

    def save_target(self, domain: str, **kwargs):
        """保存/更新目标"""
        conn = self._connect()
        c = conn.cursor()
        now = time.time()

        c.execute("SELECT domain FROM targets WHERE domain = ?", (domain,))
        if c.fetchone():
            updates = []
            values = []
            for key, val in kwargs.items():
                if key in ("company_name", "tech_stack", "notes"):
                    updates.append(f"{key} = ?")
                    values.append(json.dumps(val) if isinstance(val, (dict, list)) else val)
            updates.append("last_scan = ?")
            values.append(now)
            values.append(domain)
            c.execute(f"UPDATE targets SET {', '.join(updates)} WHERE domain = ?", values)
        else:
            c.execute(
                "INSERT INTO targets (domain, company_name, tech_stack, first_seen, last_scan) VALUES (?, ?, ?, ?, ?)",
                (domain, kwargs.get("company_name", ""),
                 json.dumps(kwargs.get("tech_stack", {})), now, now)
            )

        conn.commit()
        conn.close()

    def get_target(self, domain: str) -> Optional[dict]:
        """获取目标信息"""
        conn = self._connect()
        c = conn.cursor()
        c.execute("SELECT * FROM targets WHERE domain = ?", (domain,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "domain": row[0], "company_name": row[1],
            "tech_stack": json.loads(row[2]) if row[2] else {},
            "first_seen": row[3], "last_scan": row[4], "notes": row[5]
        }

    # ─── 资产保存 ──────────────────────────────────────────────

    def save_subdomains(self, target: str, subdomains: list[str]):
        """保存子域名（自动去重）"""
        conn = self._connect()
        c = conn.cursor()
        now = time.time()

        for sub in subdomains:
            c.execute(
                """INSERT INTO subdomains (target, subdomain, first_seen, last_seen)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(target, subdomain) DO UPDATE SET last_seen = ?""",
                (target, sub, now, now, now)
            )

        conn.commit()
        conn.close()

    def save_urls(self, target: str, urls: list[str]):
        """保存 URL（自动去重）"""
        conn = self._connect()
        c = conn.cursor()
        now = time.time()

        for url in urls:
            c.execute(
                """INSERT INTO urls (target, url, first_seen, last_seen)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(target, url, method) DO UPDATE SET last_seen = ?""",
                (target, url, now, now, now)
            )

        conn.commit()
        conn.close()

    def save_finding(self, target: str, finding: dict) -> int:
        """保存漏洞发现，返回 ID"""
        conn = self._connect()
        c = conn.cursor()
        now = time.time()

        c.execute(
            """INSERT INTO findings
               (target, vuln_type, url, param, severity, confidence, status, evidence, payload, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (target, finding.get("type", ""), finding.get("url", ""),
             finding.get("param", ""), finding.get("severity", "medium"),
             finding.get("confidence", 0.0), "new",
             finding.get("evidence", "")[:2000], finding.get("payload", "")[:1000],
             now, now)
        )

        finding_id = c.lastrowid
        conn.commit()
        conn.close()
        return finding_id

    def save_findings_batch(self, target: str, findings: list[dict]):
        """批量保存漏洞发现"""
        for finding in findings:
            self.save_finding(target, finding)

    # ─── 查询/对比 ─────────────────────────────────────────────

    def get_new_urls(self, target: str, urls: list[str]) -> list[str]:
        """返回之前未见过的 URL（用于增量扫描）"""
        conn = self._connect()
        c = conn.cursor()
        c.execute("SELECT url FROM urls WHERE target = ?", (target,))
        known = set(row[0] for row in c.fetchall())
        conn.close()
        return [u for u in urls if u not in known]

    def get_new_subdomains(self, target: str, subdomains: list[str]) -> list[str]:
        """返回之前未见过的子域名"""
        conn = self._connect()
        c = conn.cursor()
        c.execute("SELECT subdomain FROM subdomains WHERE target = ?", (target,))
        known = set(row[0] for row in c.fetchall())
        conn.close()
        return [s for s in subdomains if s not in known]

    def get_target_history(self, target: str) -> dict:
        """获取目标的历史数据摘要"""
        conn = self._connect()
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM subdomains WHERE target = ?", (target,))
        sub_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM urls WHERE target = ?", (target,))
        url_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,))
        finding_count = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM scan_history WHERE target = ?", (target,))
        scan_count = c.fetchone()[0]

        c.execute("SELECT MAX(finished_at) FROM scan_history WHERE target = ?", (target,))
        last_scan = c.fetchone()[0]

        conn.close()

        return {
            "subdomains": sub_count,
            "urls": url_count,
            "findings": finding_count,
            "total_scans": scan_count,
            "last_scan": last_scan,
        }

    def get_findings(self, target: str, status: str = None) -> list[dict]:
        """获取漏洞发现"""
        conn = self._connect()
        c = conn.cursor()

        if status:
            c.execute("SELECT * FROM findings WHERE target = ? AND status = ? ORDER BY created_at DESC", (target, status))
        else:
            c.execute("SELECT * FROM findings WHERE target = ? ORDER BY created_at DESC", (target,))

        rows = c.fetchall()
        conn.close()

        return [
            {"id": r[0], "target": r[1], "vuln_type": r[2], "url": r[3],
             "param": r[4], "severity": r[5], "confidence": r[6], "status": r[7],
             "evidence": r[8], "payload": r[9], "created_at": r[12]}
            for r in rows
        ]

    # ─── 扫描历史 ──────────────────────────────────────────────

    def start_scan(self, target: str, mode: str = "auto") -> int:
        """记录扫描开始"""
        conn = self._connect()
        c = conn.cursor()
        c.execute(
            "INSERT INTO scan_history (target, mode, started_at) VALUES (?, ?, ?)",
            (target, mode, time.time())
        )
        scan_id = c.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def end_scan(self, scan_id: int, findings: dict):
        """记录扫描结束"""
        conn = self._connect()
        c = conn.cursor()
        c.execute(
            """UPDATE scan_history SET
               finished_at = ?, findings_count = ?, subdomains_count = ?,
               urls_count = ?, summary = ?
               WHERE id = ?""",
            (time.time(),
             len(findings.get("vulnerabilities", [])),
             len(findings.get("subdomains", [])),
             len(findings.get("urls", [])),
             json.dumps({"keys": list(findings.keys())}),
             scan_id)
        )
        conn.commit()
        conn.close()

    # ─── 请求日志 ──────────────────────────────────────────────

    def log_request(self, target: str, method: str, url: str,
                    status_code: int, response_length: int, elapsed: float):
        """记录请求日志"""
        conn = self._connect()
        c = conn.cursor()
        c.execute(
            """INSERT INTO request_log (target, method, url, status_code, response_length, elapsed, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (target, method, url, status_code, response_length, elapsed, time.time())
        )
        conn.commit()
        conn.close()

    def cleanup_old_logs(self, days: int = 30):
        """清理旧日志"""
        conn = self._connect()
        c = conn.cursor()
        cutoff = time.time() - (days * 86400)
        c.execute("DELETE FROM request_log WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()

    def get_stats(self) -> dict:
        """获取整体统计"""
        conn = self._connect()
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM targets")
        targets = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM subdomains")
        subs = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM urls")
        urls = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings")
        findings = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM scan_history")
        scans = c.fetchone()[0]

        conn.close()

        return {
            "targets": targets, "subdomains": subs,
            "urls": urls, "findings": findings, "scans": scans,
            "db_path": self.db_path,
        }
