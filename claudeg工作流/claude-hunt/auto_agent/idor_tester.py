#!/usr/bin/env python3
"""
IDOR Tester — 系统性越权测试模块
不再是简单的 cookie 互换，而是完整的越权测试框架

测试维度：
1. 水平越权 — 用 A 的 token 访问 B 的资源
2. 垂直越权 — 普通用户访问管理员接口
3. ID 枚举 — 遍历数字/可预测 ID
4. 方法变换 — GET/POST/PUT/DELETE/PATCH
5. API 版本降级 — v2 有权限，v1 可能没有
6. GraphQL node() — 通过全局 ID 绕过
7. 参数污染 — 添加 user_id/org_id 等参数
8. 响应体深度对比 — 确认是否真的拿到了别人的数据

核心原则：只有"拿到了不属于自己的数据"才是 IDOR，
公开接口返回相同数据不算。
"""

import asyncio
import re
import json
import hashlib
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from typing import Optional

from http_engine import HttpEngine, HttpResponse


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class IDORFinding:
    """IDOR 发现"""
    url: str = ""
    method: str = "GET"
    vuln_type: str = ""  # horizontal/vertical/id_enum
    severity: str = "high"
    confidence: float = 0.0
    evidence: str = ""
    # 请求详情
    original_id: str = ""
    tested_id: str = ""
    attacker_cookies: dict = field(default_factory=dict)
    victim_cookies: dict = field(default_factory=dict)
    # 响应对比
    attacker_status: int = 0
    attacker_body_hash: str = ""
    victim_status: int = 0
    victim_body_hash: str = ""
    # 是否确认
    confirmed: bool = False
    is_public_data: bool = False


@dataclass
class IDORTarget:
    """IDOR 测试目标"""
    url: str = ""
    method: str = "GET"
    id_param: str = ""  # 包含 ID 的参数名/路径位置
    id_value: str = ""  # 原始 ID 值
    id_location: str = "path"  # path/query/body/header


# ═══════════════════════════════════════════════════════════════
# IDOR Tester
# ═══════════════════════════════════════════════════════════════

class IDORTester:
    """
    系统性 IDOR 越权测试
    
    用法:
        tester = IDORTester(http_engine, {
            "cookie_a": {"session": "attacker_token"},
            "cookie_b": {"session": "victim_token"},
            "cookie_admin": {"session": "admin_token"},  # 可选
        })
        
        findings = await tester.test_url("https://target.com/api/user/123/profile")
        findings = await tester.test_endpoints(url_list)
    """

    def __init__(self, http_engine: HttpEngine, config: dict = None):
        self.http = http_engine
        self.config = config or {}
        
        # 账号配置
        self.cookie_a = self.config.get("cookie_a", {})  # 攻击者
        self.cookie_b = self.config.get("cookie_b", {})  # 受害者
        self.cookie_admin = self.config.get("cookie_admin", {})  # 管理员（可选）
        self.cookie_unauth = {}  # 未认证
        
        # Token 形式的认证
        self.token_a = self.config.get("token_a", "")
        self.token_b = self.config.get("token_b", "")
        self.token_header = self.config.get("token_header", "Authorization")
        
        # 配置
        self.id_range = self.config.get("id_range", 5)  # 测试 ID ±N
        self.test_methods = self.config.get("test_methods", ["GET", "PUT", "PATCH", "DELETE"])
        self.test_api_versions = self.config.get("test_api_versions", True)
        
        self.findings: list[IDORFinding] = []

    # ─── 主入口 ────────────────────────────────────────────────

    async def test_url(self, url: str, method: str = "GET") -> list[IDORFinding]:
        """
        对单个 URL 进行全面 IDOR 测试
        """
        findings = []

        # 1. 提取 URL 中的 ID
        targets = self._extract_ids(url, method)
        
        if not targets:
            return findings

        for target in targets:
            # 2. 水平越权测试
            horizontal = await self._test_horizontal(target)
            findings.extend(horizontal)

            # 3. 未认证访问测试
            unauth = await self._test_unauth(target)
            findings.extend(unauth)

            # 4. HTTP 方法变换测试
            method_findings = await self._test_method_variation(target)
            findings.extend(method_findings)

        # 5. API 版本降级测试
        if self.test_api_versions:
            version_findings = await self._test_api_version(url)
            findings.extend(version_findings)

        # 6. 参数污染测试
        param_findings = await self._test_param_pollution(url)
        findings.extend(param_findings)

        self.findings.extend(findings)
        return findings

    async def test_endpoints(self, urls: list[str]) -> list[IDORFinding]:
        """批量测试多个端点"""
        all_findings = []
        for url in urls:
            findings = await self.test_url(url)
            all_findings.extend(findings)
        return all_findings

    async def test_graphql(
        self,
        graphql_url: str,
        known_ids: list[str] = None,
    ) -> list[IDORFinding]:
        """
        GraphQL IDOR 测试
        通过 node() 查询绕过对象级权限
        """
        findings = []

        if not known_ids:
            known_ids = ["1", "2", "3"]

        # 测试 node() 全局查询
        for id_val in known_ids:
            # 尝试不同的 ID 编码方式
            encoded_ids = [
                base64.b64encode(f"User:{id_val}".encode()).decode(),
                base64.b64encode(f"user:{id_val}".encode()).decode(),
                id_val,
            ]

            for encoded_id in encoded_ids:
                query = f'{{ node(id: "{encoded_id}") {{ ... on User {{ id email name phone }} }} }}'
                
                resp = await self.http.post(
                    graphql_url,
                    json_data={"query": query},
                    cookies=self.cookie_a,
                )

                if resp.status_code == 200 and resp.body:
                    try:
                        data = json.loads(resp.body)
                        if data.get("data", {}).get("node"):
                            node_data = data["data"]["node"]
                            if node_data and any(v for v in node_data.values() if v):
                                findings.append(IDORFinding(
                                    url=graphql_url,
                                    method="POST",
                                    vuln_type="graphql_node_idor",
                                    severity="high",
                                    confidence=0.8,
                                    evidence=f"GraphQL node()查询返回数据: {json.dumps(node_data)[:200]}",
                                    original_id="attacker",
                                    tested_id=encoded_id,
                                    confirmed=True,
                                ))
                    except json.JSONDecodeError:
                        pass

        # 测试 introspection
        introspection_query = '{ __schema { types { name fields { name type { name } } } } }'
        resp = await self.http.post(
            graphql_url,
            json_data={"query": introspection_query},
            cookies=self.cookie_a,
        )

        if resp.status_code == 200 and "__schema" in resp.body:
            findings.append(IDORFinding(
                url=graphql_url,
                method="POST",
                vuln_type="graphql_introspection",
                severity="medium",
                confidence=0.9,
                evidence="GraphQL introspection 开启，可枚举所有 type 和 field",
                confirmed=True,
            ))

        self.findings.extend(findings)
        return findings

    # ─── 测试方法 ──────────────────────────────────────────────

    async def _test_horizontal(self, target: IDORTarget) -> list[IDORFinding]:
        """水平越权：用 A 的 token 访问 B 的资源"""
        findings = []

        if not self.cookie_a or not self.cookie_b:
            # 没有两组 cookie，用 ID 枚举替代
            return await self._test_id_enum(target)

        # 1. 用 B 的 cookie 正常访问（获取受害者的正常响应）
        victim_url = self._replace_id(target.url, target.id_param, target.id_value, target.id_location)
        victim_resp = await self.http.request(
            target.method, victim_url, cookies=self.cookie_b
        )

        # 2. 用 A 的 cookie 访问 B 的资源
        attacker_resp = await self.http.request(
            target.method, victim_url, cookies=self.cookie_a
        )

        # 3. 分析结果
        if attacker_resp.status_code == 200 and victim_resp.status_code == 200:
            # 两个都是 200，需要深入对比
            if attacker_resp.body_hash == victim_resp.body_hash:
                # 响应完全相同 — 可能是公开数据
                # 但也可能是真 IDOR！需要进一步检查
                if self._contains_private_data(attacker_resp.body):
                    findings.append(IDORFinding(
                        url=victim_url,
                        method=target.method,
                        vuln_type="horizontal_idor",
                        severity="high",
                        confidence=0.7,
                        evidence="攻击者可访问受害者资源（含敏感字段），响应相同可能因为是同一条数据",
                        original_id=target.id_value,
                        tested_id=target.id_value,
                        attacker_cookies=self.cookie_a,
                        attacker_status=attacker_resp.status_code,
                        attacker_body_hash=attacker_resp.body_hash,
                        victim_status=victim_resp.status_code,
                        victim_body_hash=victim_resp.body_hash,
                    ))
            else:
                # 响应不同 + 攻击者也能访问 = 更可能是真 IDOR
                findings.append(IDORFinding(
                    url=victim_url,
                    method=target.method,
                    vuln_type="horizontal_idor",
                    severity="high",
                    confidence=0.85,
                    evidence=(
                        f"攻击者可访问受害者资源，响应体不同"
                        f"(攻击者hash={attacker_resp.body_hash[:8]}, "
                        f"受害者hash={victim_resp.body_hash[:8]})，很可能是真IDOR"
                    ),
                    original_id=target.id_value,
                    tested_id=target.id_value,
                    attacker_cookies=self.cookie_a,
                    attacker_status=attacker_resp.status_code,
                    attacker_body_hash=attacker_resp.body_hash,
                    victim_status=victim_resp.status_code,
                    victim_body_hash=victim_resp.body_hash,
                    confirmed=True,
                ))
        elif attacker_resp.status_code in (401, 403):
            # 有权限控制，不是 IDOR
            pass

        return findings

    async def _test_unauth(self, target: IDORTarget) -> list[IDORFinding]:
        """未认证访问测试"""
        findings = []

        url = self._replace_id(target.url, target.id_param, target.id_value, target.id_location)
        
        # 不带任何认证信息访问
        resp = await self.http.request(target.method, url)

        if resp.status_code == 200:
            if self._contains_private_data(resp.body):
                findings.append(IDORFinding(
                    url=url,
                    method=target.method,
                    vuln_type="unauth_access",
                    severity="critical",
                    confidence=0.9,
                    evidence=f"无需认证即可访问，响应包含敏感数据",
                    confirmed=True,
                ))

        return findings

    async def _test_id_enum(self, target: IDORTarget) -> list[IDORFinding]:
        """ID 枚举测试：遍历相邻 ID"""
        findings = []

        try:
            original_id = int(target.id_value)
        except (ValueError, TypeError):
            return findings  # 非数字 ID，跳过枚举

        # 测试相邻 ID
        test_ids = []
        for offset in range(1, self.id_range + 1):
            test_ids.append(str(original_id + offset))
            test_ids.append(str(original_id - offset))

        responses = {}
        for test_id in test_ids:
            url = self._replace_id(target.url, target.id_param, test_id, target.id_location)
            resp = await self.http.request(target.method, url, cookies=self.cookie_a)
            
            if resp.status_code == 200 and resp.body:
                responses[test_id] = resp

        # 分析：如果能访问多个不同 ID 的数据，且数据不同
        if len(responses) >= 2:
            body_hashes = set(r.body_hash for r in responses.values())
            if len(body_hashes) > 1:
                # 不同 ID 返回不同数据 → IDOR
                findings.append(IDORFinding(
                    url=target.url,
                    method=target.method,
                    vuln_type="id_enumeration",
                    severity="high",
                    confidence=0.8,
                    evidence=(
                        f"可枚举 {len(responses)} 个不同ID的数据，"
                        f"有 {len(body_hashes)} 种不同响应"
                    ),
                    original_id=target.id_value,
                    tested_id=", ".join(list(responses.keys())[:3]),
                    confirmed=True,
                ))

        return findings

    async def _test_method_variation(self, target: IDORTarget) -> list[IDORFinding]:
        """HTTP 方法变换测试"""
        findings = []

        url = self._replace_id(target.url, target.id_param, target.id_value, target.id_location)

        for method in self.test_methods:
            if method == target.method:
                continue

            resp = await self.http.request(method, url, cookies=self.cookie_a)

            # 写操作成功 = 高危
            if method in ("PUT", "PATCH", "DELETE") and resp.status_code in (200, 204):
                findings.append(IDORFinding(
                    url=url,
                    method=method,
                    vuln_type="method_variation_idor",
                    severity="critical",
                    confidence=0.85,
                    evidence=f"{method} 请求返回 {resp.status_code}，可能可以修改/删除他人数据",
                    original_id=target.id_value,
                    confirmed=True,
                ))
            # GET 被拒绝但其他方法通过
            elif target.method == "GET" and resp.status_code == 200:
                findings.append(IDORFinding(
                    url=url,
                    method=method,
                    vuln_type="method_bypass",
                    severity="high",
                    confidence=0.7,
                    evidence=f"GET可能受限但 {method} 返回200",
                ))

        return findings

    async def _test_api_version(self, url: str) -> list[IDORFinding]:
        """API 版本降级测试"""
        findings = []

        # 检测 URL 中的版本号
        version_match = re.search(r'(/api/)v(\d+)/', url)
        if not version_match:
            version_match = re.search(r'(/v)(\d+)/', url)
        
        if not version_match:
            return findings

        prefix = version_match.group(1)
        current_ver = int(version_match.group(2))

        # 测试更低版本
        for v in range(1, current_ver):
            old_url = url.replace(f"{prefix}{current_ver}/", f"{prefix}{v}/")
            resp = await self.http.request("GET", old_url, cookies=self.cookie_a)

            if resp.status_code == 200:
                findings.append(IDORFinding(
                    url=old_url,
                    method="GET",
                    vuln_type="api_version_downgrade",
                    severity="high",
                    confidence=0.7,
                    evidence=f"旧版API (v{v}) 可访问，可能缺少权限检查",
                ))

        return findings

    async def _test_param_pollution(self, url: str) -> list[IDORFinding]:
        """参数污染测试：添加 user_id/org_id 等参数"""
        findings = []

        pollution_params = [
            ("user_id", "1"),
            ("uid", "1"),
            ("userId", "1"),
            ("account_id", "1"),
            ("org_id", "1"),
            ("team_id", "1"),
            ("admin", "true"),
            ("role", "admin"),
            ("is_admin", "1"),
        ]

        # 先获取正常响应
        baseline = await self.http.request("GET", url, cookies=self.cookie_a)

        for param_name, param_value in pollution_params:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param_name] = [param_value]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            resp = await self.http.request("GET", test_url, cookies=self.cookie_a)

            if resp.status_code == 200 and resp.body_hash != baseline.body_hash:
                length_diff = abs(resp.content_length - baseline.content_length)
                if length_diff > 50:
                    findings.append(IDORFinding(
                        url=test_url,
                        method="GET",
                        vuln_type="param_pollution",
                        severity="high",
                        confidence=0.6,
                        evidence=(
                            f"添加参数 {param_name}={param_value} 后响应变化"
                            f"(长度差异={length_diff})"
                        ),
                    ))

        return findings

    # ─── 辅助方法 ──────────────────────────────────────────────

    def _extract_ids(self, url: str, method: str) -> list[IDORTarget]:
        """从 URL 中提取所有可能的 ID 参数"""
        targets = []
        parsed = urlparse(url)

        # 1. 路径中的数字 ID: /api/user/123/profile
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if re.match(r'^\d+$', part):
                targets.append(IDORTarget(
                    url=url,
                    method=method,
                    id_param=str(i),  # 路径索引
                    id_value=part,
                    id_location="path",
                ))
            # UUID 格式
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.I):
                targets.append(IDORTarget(
                    url=url,
                    method=method,
                    id_param=str(i),
                    id_value=part,
                    id_location="path",
                ))

        # 2. 查询参数中的 ID
        qs = parse_qs(parsed.query, keep_blank_values=True)
        id_param_names = [
            "id", "user_id", "uid", "userId", "account_id",
            "order_id", "orderId", "invoice_id", "msg_id",
            "project_id", "file_id", "doc_id", "item_id",
        ]
        for param_name, values in qs.items():
            if param_name.lower() in [p.lower() for p in id_param_names]:
                targets.append(IDORTarget(
                    url=url,
                    method=method,
                    id_param=param_name,
                    id_value=values[0] if values else "",
                    id_location="query",
                ))
            elif values and re.match(r'^\d+$', values[0]):
                # 任何数字参数都可能是 ID
                targets.append(IDORTarget(
                    url=url,
                    method=method,
                    id_param=param_name,
                    id_value=values[0],
                    id_location="query",
                ))

        return targets

    def _replace_id(self, url: str, id_param: str, new_id: str, location: str) -> str:
        """替换 URL 中的 ID"""
        if location == "path":
            parsed = urlparse(url)
            parts = parsed.path.split("/")
            idx = int(id_param)
            if 0 <= idx < len(parts):
                parts[idx] = new_id
            new_path = "/".join(parts)
            return urlunparse(parsed._replace(path=new_path))
        elif location == "query":
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[id_param] = [new_id]
            new_query = urlencode(qs, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        return url

    def _contains_private_data(self, body: str) -> bool:
        """检查响应是否包含敏感数据"""
        private_patterns = [
            r'"email"\s*:\s*"[^"]+@[^"]+"',
            r'"phone"\s*:\s*"[\d\-\+]+"',
            r'"password"\s*:',
            r'"token"\s*:\s*"[^"]+"',
            r'"secret"\s*:',
            r'"address"\s*:',
            r'"ssn"\s*:',
            r'"credit_card"\s*:',
            r'"bank_account"\s*:',
            r'"id_card"\s*:',
            r'"real_name"\s*:',
        ]
        for pattern in private_patterns:
            if re.search(pattern, body, re.I):
                return True
        return False

    def get_findings_summary(self) -> dict:
        """获取发现汇总"""
        return {
            "total": len(self.findings),
            "confirmed": len([f for f in self.findings if f.confirmed]),
            "by_type": {
                t: len([f for f in self.findings if f.vuln_type == t])
                for t in set(f.vuln_type for f in self.findings)
            },
        }
