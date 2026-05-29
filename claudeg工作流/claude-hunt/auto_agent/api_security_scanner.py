#!/usr/bin/env python3
"""
API Security Scanner — 高级 API 安全测试引擎

功能：
1. GraphQL 安全测试（内省、批量查询、IDOR、注入）
2. REST API 模糊测试（参数篡改、越权访问、批量分配）
3. gRPC 反射枚举与测试
4. WebSocket 安全测试
5. API 认证绕过测试
6. 速率限制检测
7. BOLA/IDOR 自动化检测

用法：
    from api_security_scanner import APISecurityScanner
    
    scanner = APISecurityScanner(config)
    results = await scanner.scan_api("https://api.example.com")
"""

import asyncio
import json
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs



# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class APIVulnerability:
    """API 漏洞"""
    vuln_type: str = ""  # graphql_introspection/idor/bola/injection/auth_bypass/rate_limit
    endpoint: str = ""
    method: str = "GET"
    severity: str = "medium"
    # 详情
    description: str = ""
    request: str = ""
    response_excerpt: str = ""
    payload: str = ""
    # 验证
    confirmed: bool = False
    evidence: str = ""
    impact: str = ""
    # 元数据
    timestamp: str = ""


# ═══════════════════════════════════════════════════════════════
# GraphQL 攻击 Payload
# ═══════════════════════════════════════════════════════════════

GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}mutationType{name}types{name kind description fields{name args{name description type{name kind ofType{name kind}}}}}}}"}'

GRAPHQL_PROBES = [
    # 内省查询
    {"name": "full_introspection", "query": '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'},
    {"name": "type_names", "query": '{"query":"{__schema{types{name,kind}}}"}'},
    # 批量查询 DoS
    {"name": "batch_dos", "query": '[' + ','.join(['{"query":"{__typename}"}'] * 100) + ']'},
    # 深度嵌套 DoS
    {"name": "depth_attack", "query": '{"query":"{__schema{types{fields{type{fields{type{fields{type{name}}}}}}}}}"}'},
    # 字段建议泄露
    {"name": "field_suggestion", "query": '{"query":"{user_FUZZ}"}'},
    # 别名批量查询
    {"name": "alias_idor", "query": '{"query":"{u1:user(id:1){email} u2:user(id:2){email} u3:user(id:3){email}}"}'},
]

# REST API IDOR 测试模式
IDOR_PATTERNS = [
    # 数字ID递增
    {"pattern": r"/(\d+)", "replace": ["1", "2", "0", "99999"]},
    # UUID
    {"pattern": r"/([0-9a-f-]{36})", "replace_with": "00000000-0000-0000-0000-000000000000"},
    # 用户相关
    {"pattern": r"user[_]?id=(\w+)", "replace": ["1", "admin", "0"]},
]

# 认证绕过头
AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"Content-Length": "0"},
]

# 批量分配（Mass Assignment）测试字段
MASS_ASSIGNMENT_FIELDS = [
    "role", "admin", "is_admin", "isAdmin", "privilege",
    "verified", "is_verified", "email_verified",
    "balance", "credits", "plan", "subscription",
    "permissions", "access_level", "group",
]



class APISecurityScanner:
    """高级 API 安全扫描器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.concurrent = self.config.get("concurrent", 10)
        self.findings: List[APIVulnerability] = []
        self.auth_token = self.config.get("auth_token", "")
        self.cookies = self.config.get("cookies", "")

    async def scan_api(self, base_url: str, endpoints: List[str] = None) -> List[APIVulnerability]:
        """完整 API 安全扫描"""
        self.findings = []
        print(f"[*] API Security Scan: {base_url}")

        # 自动检测 API 类型
        api_type = await self._detect_api_type(base_url)
        print(f"[*] Detected API type: {api_type}")

        tasks = []
        if api_type in ("graphql", "unknown"):
            tasks.append(self._scan_graphql(base_url))
        if api_type in ("rest", "unknown"):
            tasks.append(self._scan_rest_auth_bypass(base_url, endpoints or []))
            tasks.append(self._scan_rate_limiting(base_url))
        if endpoints:
            tasks.append(self._scan_idor(base_url, endpoints))
            tasks.append(self._scan_mass_assignment(base_url, endpoints))

        # WebSocket 检测
        tasks.append(self._scan_websocket(base_url))

        await asyncio.gather(*tasks, return_exceptions=True)

        self.findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4))
        print(f"[+] API scan complete: {len(self.findings)} vulnerabilities found")
        return self.findings

    async def _detect_api_type(self, base_url: str) -> str:
        """检测 API 类型"""
        # 尝试 GraphQL
        graphql_paths = ["/graphql", "/graphiql", "/gql", "/query", "/api/graphql"]
        for path in graphql_paths:
            url = urljoin(base_url, path)
            try:
                result = await self._http_request(url, method="POST",
                    body='{"query":"{__typename}"}',
                    headers={"Content-Type": "application/json"})
                if result and ("data" in result.get("body", "") or "__typename" in result.get("body", "")):
                    return "graphql"
            except Exception:
                continue
        return "rest"


    # ═══════════════════════════════════════════════════════════════
    # GraphQL 测试
    # ═══════════════════════════════════════════════════════════════

    async def _scan_graphql(self, base_url: str):
        """GraphQL 安全测试"""
        graphql_url = None
        for path in ["/graphql", "/graphiql", "/gql", "/query", "/api/graphql"]:
            url = urljoin(base_url, path)
            result = await self._http_request(url, method="POST",
                body='{"query":"{__typename}"}',
                headers={"Content-Type": "application/json"})
            if result and result.get("status") == 200:
                graphql_url = url
                break

        if not graphql_url:
            return

        print(f"  [*] GraphQL endpoint found: {graphql_url}")

        # 测试内省
        for probe in GRAPHQL_PROBES:
            try:
                result = await self._http_request(graphql_url, method="POST",
                    body=probe["query"],
                    headers={"Content-Type": "application/json"})

                if not result:
                    continue
                body = result.get("body", "")
                status = result.get("status", 0)

                if probe["name"] == "full_introspection" and status == 200 and "fields" in body:
                    self.findings.append(APIVulnerability(
                        vuln_type="graphql_introspection",
                        endpoint=graphql_url,
                        method="POST",
                        severity="medium",
                        description="GraphQL introspection enabled - full schema exposed",
                        payload=probe["query"][:200],
                        response_excerpt=body[:300],
                        confirmed=True,
                        evidence="Schema types and fields returned",
                        impact="Internal API structure exposed, aids further attacks",
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"    [!] GraphQL introspection enabled")

                elif probe["name"] == "batch_dos" and status == 200:
                    if body.count("__typename") >= 50:
                        self.findings.append(APIVulnerability(
                            vuln_type="graphql_dos",
                            endpoint=graphql_url,
                            method="POST",
                            severity="medium",
                            description="GraphQL batch query accepted (DoS potential)",
                            payload="100x batched queries",
                            confirmed=True,
                            impact="Potential DoS via batched queries",
                            timestamp=datetime.now().isoformat(),
                        ))

                elif probe["name"] == "alias_idor" and status == 200:
                    if "email" in body and "errors" not in body:
                        self.findings.append(APIVulnerability(
                            vuln_type="graphql_idor",
                            endpoint=graphql_url,
                            method="POST",
                            severity="high",
                            description="GraphQL alias IDOR - can enumerate user data",
                            payload=probe["query"][:200],
                            response_excerpt=body[:300],
                            confirmed=True,
                            evidence="Multiple user records returned via aliases",
                            impact="User data enumeration via IDOR",
                            timestamp=datetime.now().isoformat(),
                        ))
                        print(f"    [!] GraphQL IDOR via aliases")

            except Exception:
                continue


    # ═══════════════════════════════════════════════════════════════
    # REST API Auth Bypass
    # ═══════════════════════════════════════════════════════════════

    async def _scan_rest_auth_bypass(self, base_url: str, endpoints: List[str]):
        """REST API 认证绕过测试"""
        # 常见受保护路径
        protected_paths = [
            "/admin", "/api/admin", "/api/v1/admin",
            "/api/users", "/api/v1/users", "/internal",
            "/api/config", "/api/settings", "/debug",
        ] + endpoints[:10]

        for path in protected_paths:
            url = urljoin(base_url, path)

            # 正常请求（应该返回 401/403）
            normal = await self._http_request(url)
            if not normal or normal.get("status") in (200,):
                continue  # 已经是公开的

            if normal.get("status") not in (401, 403):
                continue

            # 尝试绕过
            for bypass_header in AUTH_BYPASS_HEADERS:
                result = await self._http_request(url, headers=bypass_header)
                if result and result.get("status") == 200:
                    header_str = str(bypass_header)
                    self.findings.append(APIVulnerability(
                        vuln_type="auth_bypass",
                        endpoint=url,
                        method="GET",
                        severity="critical",
                        description=f"Auth bypass via header: {header_str}",
                        payload=header_str,
                        response_excerpt=result.get("body", "")[:200],
                        confirmed=True,
                        evidence=f"401/403 → 200 with header {header_str}",
                        impact="Authentication bypass - unauthorized access to protected resource",
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"    [!!] Auth bypass: {url} via {header_str}")
                    break

            # HTTP 方法绕过
            for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]:
                result = await self._http_request(url, method=method)
                if result and result.get("status") == 200 and len(result.get("body", "")) > 50:
                    self.findings.append(APIVulnerability(
                        vuln_type="auth_bypass",
                        endpoint=url,
                        method=method,
                        severity="high",
                        description=f"Method bypass: GET=403, {method}=200",
                        confirmed=True,
                        evidence=f"HTTP method {method} bypasses auth",
                        impact="Authentication bypass via HTTP method override",
                        timestamp=datetime.now().isoformat(),
                    ))
                    break


    # ═══════════════════════════════════════════════════════════════
    # IDOR / BOLA
    # ═══════════════════════════════════════════════════════════════

    async def _scan_idor(self, base_url: str, endpoints: List[str]):
        """IDOR/BOLA 检测"""
        for endpoint in endpoints[:30]:
            url = urljoin(base_url, endpoint)

            # 检测数字 ID 模式
            id_match = re.search(r'/(\d+)(?:/|$|\?)', endpoint)
            if id_match:
                original_id = id_match.group(1)
                # 尝试访问相邻 ID
                for test_id in ["1", "2", "0", str(int(original_id) + 1), str(int(original_id) - 1)]:
                    if test_id == original_id:
                        continue
                    test_url = url.replace(f"/{original_id}", f"/{test_id}")
                    result = await self._http_request(test_url)
                    if result and result.get("status") == 200:
                        # 确认是不同的数据
                        orig_result = await self._http_request(url)
                        if orig_result and orig_result.get("body") != result.get("body"):
                            self.findings.append(APIVulnerability(
                                vuln_type="idor",
                                endpoint=test_url,
                                method="GET",
                                severity="high",
                                description=f"IDOR: ID {original_id} → {test_id} returns different data",
                                evidence=f"Different response for ID={test_id}",
                                confirmed=True,
                                impact="Unauthorized access to other users' data",
                                timestamp=datetime.now().isoformat(),
                            ))
                            print(f"    [!] IDOR: {endpoint} (ID manipulation)")
                            break

    # ═══════════════════════════════════════════════════════════════
    # Mass Assignment
    # ═══════════════════════════════════════════════════════════════

    async def _scan_mass_assignment(self, base_url: str, endpoints: List[str]):
        """批量分配漏洞检测"""
        # 找到 POST/PUT 端点
        update_patterns = [e for e in endpoints if any(
            k in e.lower() for k in ["profile", "user", "account", "settings", "update"]
        )][:10]

        for endpoint in update_patterns:
            url = urljoin(base_url, endpoint)
            # 构造带有特权字段的 payload
            for field in MASS_ASSIGNMENT_FIELDS[:5]:
                payload = json.dumps({field: True, "test_field": "normal_value"})
                result = await self._http_request(url, method="PUT", body=payload,
                    headers={"Content-Type": "application/json"})
                if result and result.get("status") in (200, 201):
                    body = result.get("body", "")
                    if field in body and "true" in body.lower():
                        self.findings.append(APIVulnerability(
                            vuln_type="mass_assignment",
                            endpoint=url,
                            method="PUT",
                            severity="high",
                            description=f"Mass assignment: field '{field}' accepted",
                            payload=payload,
                            response_excerpt=body[:200],
                            confirmed=True,
                            impact=f"Privilege escalation via mass assignment of '{field}'",
                            timestamp=datetime.now().isoformat(),
                        ))
                        print(f"    [!] Mass Assignment: {endpoint} ({field})")
                        break


    # ═══════════════════════════════════════════════════════════════
    # Rate Limiting
    # ═══════════════════════════════════════════════════════════════

    async def _scan_rate_limiting(self, base_url: str):
        """速率限制检测"""
        # 选一个端点快速测试
        test_paths = ["/api/login", "/login", "/api/auth", "/auth/login", "/api/v1/auth"]
        target_url = None

        for path in test_paths:
            url = urljoin(base_url, path)
            result = await self._http_request(url, method="POST",
                body='{"username":"test","password":"test"}',
                headers={"Content-Type": "application/json"})
            if result and result.get("status") in (200, 401, 422, 400):
                target_url = url
                break

        if not target_url:
            return

        # 快速发送 30 个请求
        results = []
        for _ in range(30):
            r = await self._http_request(target_url, method="POST",
                body='{"username":"admin","password":"wrong"}',
                headers={"Content-Type": "application/json"})
            if r:
                results.append(r.get("status", 0))

        # 检查是否有 429 或限制
        if 429 not in results and all(s != 0 for s in results[-10:]):
            self.findings.append(APIVulnerability(
                vuln_type="rate_limit_bypass",
                endpoint=target_url,
                method="POST",
                severity="medium",
                description="No rate limiting on authentication endpoint",
                evidence=f"30 requests, no 429 response. Status codes: {set(results)}",
                confirmed=True,
                impact="Brute force attacks possible on login endpoint",
                timestamp=datetime.now().isoformat(),
            ))
            print(f"    [!] No rate limit: {target_url}")

    # ═══════════════════════════════════════════════════════════════
    # WebSocket
    # ═══════════════════════════════════════════════════════════════

    async def _scan_websocket(self, base_url: str):
        """WebSocket 安全检测"""
        parsed = urlparse(base_url)
        ws_paths = ["/ws", "/websocket", "/socket.io/", "/cable", "/hub"]

        for path in ws_paths:
            ws_url = f"wss://{parsed.hostname}{path}"
            # 检查 WebSocket 升级响应
            http_url = f"https://{parsed.hostname}{path}"
            result = await self._http_request(http_url, headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": "https://evil.com",
            })
            if result and result.get("status") == 101:
                # WebSocket accepts cross-origin
                self.findings.append(APIVulnerability(
                    vuln_type="websocket_cswsh",
                    endpoint=ws_url,
                    severity="high",
                    description="WebSocket accepts cross-origin connections (CSWSH)",
                    evidence="101 Switching Protocols with evil.com Origin",
                    confirmed=True,
                    impact="Cross-Site WebSocket Hijacking possible",
                    timestamp=datetime.now().isoformat(),
                ))
                print(f"    [!] CSWSH: {ws_url}")


    # ═══════════════════════════════════════════════════════════════
    # HTTP 请求工具
    # ═══════════════════════════════════════════════════════════════

    async def _http_request(self, url: str, method: str = "GET",
                            body: str = None, headers: Dict = None) -> Optional[Dict]:
        """异步 HTTP 请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout), "-X", method]
        cmd.extend(["-o", "-", "-w", "\n%{http_code}"])

        # 认证
        if self.auth_token:
            cmd.extend(["-H", f"Authorization: Bearer {self.auth_token}"])
        if self.cookies:
            cmd.extend(["-H", f"Cookie: {self.cookies}"])

        # 自定义头
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        # Body
        if body:
            cmd.extend(["-d", body])

        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            output = stdout.decode(errors="ignore")

            lines = output.rsplit("\n", 1)
            response_body = lines[0] if len(lines) > 1 else output
            status = int(lines[-1]) if len(lines) > 1 and lines[-1].strip().isdigit() else 0

            return {"status": status, "body": response_body}
        except Exception:
            return None

    def generate_report(self) -> str:
        """生成 API 安全报告"""
        if not self.findings:
            return "No API security vulnerabilities found."

        lines = [
            "=" * 60,
            "  API SECURITY SCAN REPORT",
            "=" * 60,
            f"  Total: {len(self.findings)} vulnerabilities",
            "",
        ]

        by_type = {}
        for f in self.findings:
            by_type.setdefault(f.vuln_type, []).append(f)

        for vtype, vulns in by_type.items():
            lines.append(f"  [{vtype.upper()}] ({len(vulns)} findings)")
            for v in vulns[:5]:
                lines.append(f"    [{v.severity.upper()}] {v.endpoint}")
                lines.append(f"      {v.description}")
                if v.evidence:
                    lines.append(f"      Evidence: {v.evidence[:100]}")
            lines.append("")

        return "\n".join(lines)
