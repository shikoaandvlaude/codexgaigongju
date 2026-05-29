#!/usr/bin/env python3
"""
Proxy Rotator — 代理池管理 + IP 自动轮换 + 健康检查

功能：
1. 多源代理池（SOCKS5/HTTP/Tor/Residential）
2. 自动健康检查（延迟/存活/匿名性验证）
3. 智能轮换策略（随机/顺序/权重/地域优先）
4. 被封自动切换（检测 403/429 自动换 IP）
5. Tor 电路刷新（自动 NEWNYM）
6. 代理链（多跳代理）
7. 与 stealth_http / traffic_controller 集成

用法：
    from proxy_rotator import ProxyRotator

    rotator = ProxyRotator(config)
    await rotator.initialize()         # 初始化并检查所有代理
    proxy = rotator.get_next()         # 获取下一个可用代理
    rotator.mark_failed(proxy)         # 标记代理失败（自动切换）
    rotator.mark_banned(proxy)         # 标记被封（移入冷却池）
"""

import asyncio
import random
import time
import socket
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class ProxyInfo:
    """代理信息"""
    url: str = ""                    # socks5://ip:port 或 http://ip:port
    protocol: str = "socks5"         # socks5/http/https
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    # 状态
    alive: bool = True
    last_check: float = 0
    latency_ms: int = 9999           # 延迟（毫秒）
    fail_count: int = 0
    success_count: int = 0
    # 冷却
    banned_until: float = 0          # 被封冷却到期时间
    cooldown_until: float = 0        # 普通冷却到期时间
    # 元信息
    region: str = ""                 # 地区
    anonymous: bool = True           # 高匿
    source: str = ""                 # 来源标签
    weight: float = 1.0              # 权重（越高越优先）

    @property
    def is_available(self) -> bool:
        """是否可用"""
        now = time.time()
        if not self.alive:
            return False
        if self.banned_until > now:
            return False
        if self.cooldown_until > now:
            return False
        if self.fail_count >= 5:
            return False
        return True

    @property
    def score(self) -> float:
        """综合评分（用于权重轮换）"""
        if not self.is_available:
            return 0
        # 延迟越低、成功率越高 → 分数越高
        total = self.success_count + self.fail_count
        success_rate = self.success_count / max(total, 1)
        latency_score = max(0, 1.0 - self.latency_ms / 5000)
        return (success_rate * 0.6 + latency_score * 0.3 + self.weight * 0.1)


# ═══════════════════════════════════════════════════════════════
# 轮换策略
# ═══════════════════════════════════════════════════════════════

class RotationStrategy:
    """轮换策略基类"""
    def select(self, proxies: List[ProxyInfo]) -> Optional[ProxyInfo]:
        raise NotImplementedError


class RandomStrategy(RotationStrategy):
    """随机选择"""
    def select(self, proxies: List[ProxyInfo]) -> Optional[ProxyInfo]:
        available = [p for p in proxies if p.is_available]
        return random.choice(available) if available else None


class RoundRobinStrategy(RotationStrategy):
    """顺序轮换"""
    def __init__(self):
        self._index = 0

    def select(self, proxies: List[ProxyInfo]) -> Optional[ProxyInfo]:
        available = [p for p in proxies if p.is_available]
        if not available:
            return None
        self._index = self._index % len(available)
        proxy = available[self._index]
        self._index += 1
        return proxy


class WeightedStrategy(RotationStrategy):
    """加权随机（评分高的优先）"""
    def select(self, proxies: List[ProxyInfo]) -> Optional[ProxyInfo]:
        available = [p for p in proxies if p.is_available]
        if not available:
            return None
        scores = [p.score for p in available]
        total = sum(scores)
        if total == 0:
            return random.choice(available)
        # 加权随机
        r = random.uniform(0, total)
        cumulative = 0
        for proxy, score in zip(available, scores):
            cumulative += score
            if r <= cumulative:
                return proxy
        return available[-1]


class LeastUsedStrategy(RotationStrategy):
    """最少使用优先"""
    def select(self, proxies: List[ProxyInfo]) -> Optional[ProxyInfo]:
        available = [p for p in proxies if p.is_available]
        if not available:
            return None
        return min(available, key=lambda p: p.success_count + p.fail_count)


# ═══════════════════════════════════════════════════════════════
# 代理轮换器
# ═══════════════════════════════════════════════════════════════

class ProxyRotator:
    """代理池管理 + IP 自动轮换"""

    STRATEGIES = {
        "random": RandomStrategy,
        "round_robin": RoundRobinStrategy,
        "weighted": WeightedStrategy,
        "least_used": LeastUsedStrategy,
    }

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.proxies: List[ProxyInfo] = []
        self.current: Optional[ProxyInfo] = None
        self._lock = asyncio.Lock()

        # 配置
        self.check_url = self.config.get("check_url", "https://httpbin.org/ip")
        self.check_timeout = self.config.get("check_timeout", 10)
        self.max_fails = self.config.get("max_fails", 5)
        self.ban_cooldown = self.config.get("ban_cooldown", 300)      # 被封冷却 5 分钟
        self.fail_cooldown = self.config.get("fail_cooldown", 60)     # 失败冷却 1 分钟
        self.health_interval = self.config.get("health_interval", 120) # 健康检查间隔 2 分钟
        self.auto_tor_newnym = self.config.get("auto_tor_newnym", True)
        self.tor_control_port = self.config.get("tor_control_port", 9051)

        # 轮换策略
        strategy_name = self.config.get("strategy", "weighted")
        strategy_cls = self.STRATEGIES.get(strategy_name, WeightedStrategy)
        self.strategy = strategy_cls()

        # 统计
        self.total_requests = 0
        self.total_bans = 0
        self.rotations = 0

    # ─── 初始化 ───────────────────────────────────────────────

    async def initialize(self):
        """初始化代理池"""
        # 从配置加载代理
        self._load_proxies()

        if not self.proxies:
            print("[!] ProxyRotator: 没有配置代理，将使用直连")
            return

        # 并发健康检查
        print(f"[*] ProxyRotator: 检查 {len(self.proxies)} 个代理...")
        await self._health_check_all()

        alive = len([p for p in self.proxies if p.alive])
        print(f"[+] ProxyRotator: {alive}/{len(self.proxies)} 个代理存活")

        # 选择第一个代理
        self.current = self.strategy.select(self.proxies)
        if self.current:
            print(f"[+] 当前代理: {self.current.url} (延迟: {self.current.latency_ms}ms)")

    def _load_proxies(self):
        """从配置加载代理列表"""
        proxy_list = self.config.get("proxies", [])

        for item in proxy_list:
            if isinstance(item, str):
                proxy = self._parse_proxy_url(item)
            elif isinstance(item, dict):
                proxy = ProxyInfo(
                    url=item.get("url", ""),
                    protocol=item.get("protocol", "socks5"),
                    host=item.get("host", ""),
                    port=item.get("port", 0),
                    username=item.get("username", ""),
                    password=item.get("password", ""),
                    region=item.get("region", ""),
                    source=item.get("source", "config"),
                    weight=item.get("weight", 1.0),
                )
                if not proxy.url and proxy.host:
                    auth = f"{proxy.username}:{proxy.password}@" if proxy.username else ""
                    proxy.url = f"{proxy.protocol}://{auth}{proxy.host}:{proxy.port}"
            else:
                continue

            if proxy and proxy.url:
                self.proxies.append(proxy)

        # 加载 Tor（如果配置了）
        if self.config.get("use_tor", False):
            tor_port = self.config.get("tor_socks_port", 9050)
            self.proxies.append(ProxyInfo(
                url=f"socks5://127.0.0.1:{tor_port}",
                protocol="socks5",
                host="127.0.0.1",
                port=tor_port,
                source="tor",
                region="random",
                anonymous=True,
                weight=0.8,  # Tor 慢一些，权重稍低
            ))

        # 从文件加载
        proxy_file = self.config.get("proxy_file", "")
        if proxy_file and Path(proxy_file).exists():
            for line in Path(proxy_file).read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    proxy = self._parse_proxy_url(line)
                    if proxy:
                        self.proxies.append(proxy)

    def _parse_proxy_url(self, url: str) -> Optional[ProxyInfo]:
        """解析代理 URL"""
        url = url.strip()
        if not url:
            return None

        # 自动添加协议前缀
        if not url.startswith(("socks5://", "socks4://", "http://", "https://")):
            url = f"socks5://{url}"

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return ProxyInfo(
                url=url,
                protocol=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port or 1080,
                username=parsed.username or "",
                password=parsed.password or "",
                source="config",
            )
        except Exception:
            return None

    # ─── 代理获取 ─────────────────────────────────────────────

    def get_next(self) -> Optional[str]:
        """获取下一个可用代理 URL（供 curl/httpx 使用）"""
        proxy = self.strategy.select(self.proxies)
        if proxy:
            self.current = proxy
            return proxy.url
        return None

    def get_current(self) -> Optional[str]:
        """获取当前代理 URL"""
        if self.current and self.current.is_available:
            return self.current.url
        # 当前不可用，自动轮换
        return self.get_next()

    def get_for_curl(self) -> List[str]:
        """获取 curl 代理参数"""
        proxy_url = self.get_current()
        if not proxy_url:
            return []
        if "socks5" in proxy_url:
            return ["-x", proxy_url.replace("socks5://", "socks5h://")]
        return ["-x", proxy_url]

    def get_for_env(self) -> Dict[str, str]:
        """获取环境变量格式的代理配置"""
        proxy_url = self.get_current()
        if not proxy_url:
            return {}
        return {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
        }

    # ─── 状态反馈 ─────────────────────────────────────────────

    def mark_success(self, proxy_url: str = None):
        """标记请求成功"""
        proxy = self._find_proxy(proxy_url)
        if proxy:
            proxy.success_count += 1
            proxy.fail_count = max(0, proxy.fail_count - 1)  # 成功减少失败计数
        self.total_requests += 1

    def mark_failed(self, proxy_url: str = None):
        """标记请求失败"""
        proxy = self._find_proxy(proxy_url)
        if proxy:
            proxy.fail_count += 1
            if proxy.fail_count >= self.max_fails:
                proxy.cooldown_until = time.time() + self.fail_cooldown
                print(f"  [!] 代理冷却: {proxy.url} (连续失败 {proxy.fail_count} 次)")
                # 自动切换
                self.rotate()
        self.total_requests += 1

    def mark_banned(self, proxy_url: str = None):
        """标记被封（429/403/IP 封禁）"""
        proxy = self._find_proxy(proxy_url)
        if proxy:
            proxy.banned_until = time.time() + self.ban_cooldown
            proxy.fail_count += 3
            self.total_bans += 1
            print(f"  [!!] IP 被封: {proxy.url} (冷却 {self.ban_cooldown}s)")
            # 立即切换
            self.rotate()

    def rotate(self) -> Optional[str]:
        """强制轮换到新代理"""
        new_proxy = self.strategy.select(self.proxies)
        if new_proxy and new_proxy != self.current:
            old = self.current.url if self.current else "direct"
            self.current = new_proxy
            self.rotations += 1
            print(f"  [*] IP 轮换: {old} → {new_proxy.url}")
            return new_proxy.url
        return None

    # ─── Tor 管理 ─────────────────────────────────────────────

    async def tor_new_circuit(self):
        """请求 Tor 新电路（换出口 IP）"""
        if not self.auto_tor_newnym:
            return False
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", self.tor_control_port)
            writer.write(b'AUTHENTICATE ""\r\n')
            await writer.drain()
            await reader.readline()
            writer.write(b"SIGNAL NEWNYM\r\n")
            await writer.drain()
            response = await reader.readline()
            writer.close()
            await writer.wait_closed()
            if b"250" in response:
                print("  [*] Tor 电路已刷新")
                return True
        except Exception as e:
            pass
        return False

    # ─── 健康检查 ──────────────────────────────────────────────

    async def _health_check_all(self):
        """并发检查所有代理"""
        tasks = [self._check_proxy(p) for p in self.proxies]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_proxy(self, proxy: ProxyInfo):
        """检查单个代理"""
        try:
            start = time.time()
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-m", str(self.check_timeout),
                "-x", proxy.url.replace("socks5://", "socks5h://"),
                "-o", "/dev/null", "-w", "%{http_code}",
                self.check_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.check_timeout + 3)
            latency = int((time.time() - start) * 1000)
            status = stdout.decode().strip()

            if status == "200":
                proxy.alive = True
                proxy.latency_ms = latency
                proxy.last_check = time.time()
            else:
                proxy.alive = False
        except Exception:
            proxy.alive = False

    async def periodic_health_check(self):
        """定期健康检查（后台任务）"""
        while True:
            await asyncio.sleep(self.health_interval)
            await self._health_check_all()
            alive = len([p for p in self.proxies if p.alive])
            if alive == 0:
                print("[!!] 所有代理失效！等待冷却恢复...")

    # ─── 工具方法 ─────────────────────────────────────────────

    def _find_proxy(self, proxy_url: str = None) -> Optional[ProxyInfo]:
        """查找代理对象"""
        if proxy_url is None:
            return self.current
        for p in self.proxies:
            if p.url == proxy_url:
                return p
        return self.current

    def get_stats(self) -> Dict:
        """获取统计信息"""
        alive = [p for p in self.proxies if p.alive]
        available = [p for p in self.proxies if p.is_available]
        banned = [p for p in self.proxies if p.banned_until > time.time()]
        return {
            "total_proxies": len(self.proxies),
            "alive": len(alive),
            "available": len(available),
            "banned": len(banned),
            "current": self.current.url if self.current else "direct",
            "total_requests": self.total_requests,
            "total_bans": self.total_bans,
            "rotations": self.rotations,
        }

    def print_status(self):
        """打印代理池状态"""
        stats = self.get_stats()
        print(f"\n{'─'*50}")
        print(f"  代理池状态")
        print(f"{'─'*50}")
        print(f"  总数: {stats['total_proxies']} | "
              f"存活: {stats['alive']} | "
              f"可用: {stats['available']} | "
              f"被封: {stats['banned']}")
        print(f"  当前: {stats['current']}")
        print(f"  请求: {stats['total_requests']} | "
              f"轮换: {stats['rotations']} | "
              f"封禁: {stats['total_bans']}")
        print(f"{'─'*50}\n")

    # ─── 代理链 ───────────────────────────────────────────────

    def get_chain(self, length: int = 2) -> List[str]:
        """获取代理链（多跳）"""
        available = [p for p in self.proxies if p.is_available]
        if len(available) < length:
            return [p.url for p in available]
        selected = random.sample(available, length)
        return [p.url for p in selected]

    def get_proxychains_config(self) -> str:
        """生成 proxychains4 配置内容"""
        lines = [
            "# Auto-generated by ProxyRotator",
            "random_chain",
            f"chain_len = 2",
            "proxy_dns",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "",
            "[ProxyList]",
        ]
        for proxy in self.proxies:
            if proxy.is_available:
                auth = ""
                if proxy.username:
                    auth = f" {proxy.username} {proxy.password}"
                lines.append(f"{proxy.protocol} {proxy.host} {proxy.port}{auth}")
        return "\n".join(lines)

    def save_proxychains_config(self, path: str = "/tmp/proxychains_hunt.conf"):
        """保存 proxychains 配置文件"""
        config = self.get_proxychains_config()
        Path(path).write_text(config)
        return path
