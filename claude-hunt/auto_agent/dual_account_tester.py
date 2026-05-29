#!/usr/bin/env python3
"""
Dual Account Tester — 双账号权限差异系统性测试

核心逻辑：
1. 用账号A正常使用目标应用，收集所有请求中的业务对象ID
2. 用账号B的凭证去访问账号A的资源
3. 对比响应差异，识别真正的IDOR/越权

与之前单点IDOR测试的区别：
- 不是对单个URL做cookie互换，而是系统性地收集并测试所有业务对象
- 自动从响应中提取ID模式，生成枚举候选
- 分层测试：读 → 写 → 删除，逐步升级
- 集成 lead_collector: 所有发现都保存为线索

依赖: auth_manager.py, endpoint_classifier.py, lead_collector.py
"""

import asyncio
import json
import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse



@dataclass
class DualAccountResult:
    """双账号测试单条结果"""
    url: str = ""
    method: str = "GET"
    id_param: str = ""
    id_value: str = ""
    # 响应对比
    account_a_status: int = 0
    account_a_body_hash: str = ""
    account_a_body_length: int = 0
    account_b_status: int = 0
    account_b_body_hash: str = ""
    account_b_body_length: int = 0
    no_auth_status: int = 0
    no_auth_body_hash: str = ""
    # 判定
    verdict: str = ""       # idor_confirmed / public_data / access_denied / needs_review
    severity: str = ""
    confidence: float = 0.0
    evidence: str = ""
    # 敏感数据检测
    contains_private_data: bool = False
    private_fields_found: list = field(default_factory=list)


@dataclass
class IDPattern:
    """从响应中提取的ID模式"""
    field_name: str = ""
    sample_value: str = ""
    pattern_type: str = ""    # numeric / uuid / alphanumeric
    found_in_url: str = ""
    context: str = ""         # 出现在哪种业务对象中



class DualAccountTester:
    """
    双账号权限差异系统性测试

    用法:
        tester = DualAccountTester(http_engine, {
            "account_a": {"cookies": {...}, "headers": {...}},
            "account_b": {"cookies": {...}, "headers": {...}},
        })
        results = await tester.test_endpoints(url_list)
        results = await tester.discover_and_test(base_url)
    """

    # 敏感字段模式 — 在响应中出现这些说明有隐私数据
    PRIVATE_FIELD_PATTERNS = [
        r'"email"\s*:\s*"[^"]+@[^"]+"',
        r'"phone"\s*:\s*"[\d\+\-\s]{7,}"',
        r'"password"\s*:\s*"[^"]+"',
        r'"ssn"\s*:\s*"[^"]+"',
        r'"address"\s*:\s*"[^"]+"',
        r'"credit_card"\s*:\s*"[^"]+"',
        r'"bank_account"\s*:\s*"[^"]+"',
        r'"token"\s*:\s*"[^"]{20,}"',
        r'"secret"\s*:\s*"[^"]+"',
        r'"api_key"\s*:\s*"[^"]+"',
        r'"real_name"\s*:\s*"[^"]+"',
        r'"id_number"\s*:\s*"[^"]+"',
        r'"salary"\s*:\s*[\d]',
        r'"balance"\s*:\s*[\d]',
        r'"private"\s*:\s*true',
    ]

    # 响应中提取 ID 的模式
    ID_EXTRACTION_PATTERNS = [
        (r'"id"\s*:\s*(\d+)', "numeric", "id"),
        (r'"user_id"\s*:\s*(\d+)', "numeric", "user_id"),
        (r'"userId"\s*:\s*"?(\d+)"?', "numeric", "userId"),
        (r'"order_id"\s*:\s*"?(\d+)"?', "numeric", "order_id"),
        (r'"account_id"\s*:\s*"?(\d+)"?', "numeric", "account_id"),
        (r'"org_id"\s*:\s*"?(\d+)"?', "numeric", "org_id"),
        (r'"team_id"\s*:\s*"?(\d+)"?', "numeric", "team_id"),
        (r'"project_id"\s*:\s*"?(\d+)"?', "numeric", "project_id"),
        (r'"file_id"\s*:\s*"?(\d+)"?', "numeric", "file_id"),
        (r'"invoice_id"\s*:\s*"?(\d+)"?', "numeric", "invoice_id"),
        (r'"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"',
         "uuid", "uuid"),
    ]

    def __init__(self, http_engine, config: dict = None):
        self.http = http_engine
        self.config = config or {}

        # 账号 A (被测账号 — 我们观察它的资源)
        self.account_a = self.config.get("account_a", {})
        self.cookies_a = self.account_a.get("cookies", {})
        self.headers_a = self.account_a.get("headers", {})

        # 账号 B (攻击者账号 — 用它的凭证去越权)
        self.account_b = self.config.get("account_b", {})
        self.cookies_b = self.account_b.get("cookies", {})
        self.headers_b = self.account_b.get("headers", {})

        # 可选: lead_collector 集成
        self.lead_collector = self.config.get("lead_collector", None)

        self.results: list[DualAccountResult] = []
        self.extracted_ids: list[IDPattern] = []


    async def test_endpoints(self, urls: list[str]) -> list[DualAccountResult]:
        """
        对一组URL进行双账号差异测试。
        
        测试流程:
        1. 用账号A访问 → 获取正常响应 + 提取ID
        2. 用账号B访问同一URL → 对比响应
        3. 无认证访问 → 判断是否公开数据
        4. 综合判定
        """
        results = []

        for url in urls:
            result = await self._test_single_url(url, "GET")
            if result:
                results.append(result)

                # 如果 GET 有问题，也测试写操作方法
                if result.verdict in ("idor_confirmed", "needs_review"):
                    for method in ("PUT", "PATCH", "DELETE"):
                        write_result = await self._test_single_url(url, method)
                        if write_result and write_result.verdict != "access_denied":
                            write_result.severity = "critical"
                            write_result.evidence += f" (写操作 {method} 也可访问!)"
                            results.append(write_result)

        self.results.extend(results)
        return results

    async def discover_and_test(self, base_url: str, account_a_urls: list[str] = None):
        """
        高级模式：
        1. 先用账号A浏览应用，从响应中自动提取业务对象ID
        2. 构造所有可能的越权URL
        3. 用账号B逐一测试
        """
        # Step 1: 用账号A访问，收集响应中的ID
        discovery_urls = account_a_urls or [base_url]
        for url in discovery_urls[:30]:
            resp = await self.http.request(
                "GET", url,
                headers=self.headers_a,
                cookies=self.cookies_a,
            )
            if resp.status_code == 200 and resp.body:
                self._extract_ids_from_response(resp.body, url)

        # Step 2: 基于发现的ID，构造测试URL
        test_urls = self._build_test_urls_from_ids(base_url)

        # Step 3: 双账号测试
        return await self.test_endpoints(test_urls)

    async def _test_single_url(self, url: str, method: str = "GET") -> Optional[DualAccountResult]:
        """测试单个URL的双账号差异"""
        result = DualAccountResult(url=url, method=method)

        # 1. 账号A 访问（正常用户）
        resp_a = await self.http.request(
            method, url,
            headers=self.headers_a,
            cookies=self.cookies_a,
        )
        result.account_a_status = resp_a.status_code
        result.account_a_body_hash = self._hash_body(resp_a.body)
        result.account_a_body_length = len(resp_a.body) if resp_a.body else 0

        # 如果账号A自己都访问不了，跳过
        if resp_a.status_code in (401, 403, 404):
            return None

        # 2. 账号B 访问（攻击者）
        resp_b = await self.http.request(
            method, url,
            headers=self.headers_b,
            cookies=self.cookies_b,
        )
        result.account_b_status = resp_b.status_code
        result.account_b_body_hash = self._hash_body(resp_b.body)
        result.account_b_body_length = len(resp_b.body) if resp_b.body else 0

        # 3. 无认证访问
        resp_none = await self.http.request(method, url)
        result.no_auth_status = resp_none.status_code
        result.no_auth_body_hash = self._hash_body(resp_none.body)

        # 4. 检测敏感数据
        if resp_b.status_code == 200 and resp_b.body:
            private_fields = self._detect_private_data(resp_b.body)
            result.contains_private_data = bool(private_fields)
            result.private_fields_found = private_fields

        # 5. 综合判定
        self._make_verdict(result)

        # 6. 如果有 lead_collector，保存线索
        if self.lead_collector and result.verdict in ("idor_confirmed", "needs_review"):
            self.lead_collector.add_lead(
                category="BIZ_OBJECT",
                url=url,
                method=method,
                summary=f"双账号差异[{result.verdict}]: {result.evidence[:60]}",
                detail=result.evidence,
                severity_hint=result.severity,
                confidence=result.confidence,
                source="dual_account_tester",
                requires_dual_account=True,
            )

        return result


    def _make_verdict(self, result: DualAccountResult):
        """综合判定IDOR/越权"""
        a_status = result.account_a_status
        b_status = result.account_b_status
        none_status = result.no_auth_status

        # Case 1: B被拒绝 → 有权限控制，不是IDOR
        if b_status in (401, 403):
            result.verdict = "access_denied"
            result.severity = "info"
            result.confidence = 0.9
            result.evidence = f"账号B收到{b_status}，接口有权限控制"
            return

        # Case 2: 无认证也能访问 + 响应相同 → 公开数据
        if (none_status == 200
            and result.no_auth_body_hash == result.account_a_body_hash):
            result.verdict = "public_data"
            result.severity = "info"
            result.confidence = 0.9
            result.evidence = "匿名访问响应与认证访问相同，是公开数据"
            return

        # Case 3: B能访问 + 响应与A不同 + 包含敏感数据 → 确认IDOR
        if (b_status == 200
            and result.account_b_body_hash != result.account_a_body_hash
            and result.contains_private_data):
            result.verdict = "idor_confirmed"
            result.severity = "high"
            result.confidence = 0.9
            result.evidence = (
                f"账号B可访问账号A的资源，响应体不同且包含敏感字段: "
                f"{', '.join(result.private_fields_found[:5])}"
            )
            return

        # Case 4: B能访问 + 响应与A相同 + 包含敏感数据
        if (b_status == 200
            and result.account_b_body_hash == result.account_a_body_hash
            and result.contains_private_data):
            # 响应相同可能是：
            # - 确实是同一条数据（两个人都能访问自己的）→ 还需确认URL中有用户标识
            # - 或者是越权（B拿到了A的数据）
            result.verdict = "needs_review"
            result.severity = "medium"
            result.confidence = 0.6
            result.evidence = (
                "两账号响应相同且含敏感字段，需确认是否为同一资源的越权访问 "
                f"(敏感字段: {', '.join(result.private_fields_found[:3])})"
            )
            return

        # Case 5: B能访问 + 响应与A不同 + 无敏感数据
        if (b_status == 200
            and result.account_b_body_hash != result.account_a_body_hash):
            length_diff = abs(result.account_a_body_length - result.account_b_body_length)
            if length_diff > 100:
                result.verdict = "needs_review"
                result.severity = "medium"
                result.confidence = 0.5
                result.evidence = (
                    f"两账号响应体不同(长度差{length_diff})，"
                    f"但未检测到明确敏感字段，需人工确认"
                )
            else:
                result.verdict = "needs_review"
                result.severity = "low"
                result.confidence = 0.3
                result.evidence = "响应略有不同，可能是动态内容(时间戳等)"
            return

        # Case 6: 其他情况
        result.verdict = "needs_review"
        result.severity = "low"
        result.confidence = 0.2
        result.evidence = f"A={a_status} B={b_status} NoAuth={none_status}，需人工分析"


    def _extract_ids_from_response(self, body: str, source_url: str):
        """从响应体中提取所有 ID 模式"""
        for pattern, pattern_type, field_name in self.ID_EXTRACTION_PATTERNS:
            matches = re.findall(pattern, body, re.I)
            for match in matches[:5]:  # 每种模式最多取5个
                # 避免重复
                if any(
                    p.field_name == field_name and p.sample_value == match
                    for p in self.extracted_ids
                ):
                    continue
                self.extracted_ids.append(IDPattern(
                    field_name=field_name,
                    sample_value=match,
                    pattern_type=pattern_type,
                    found_in_url=source_url,
                ))

    def _build_test_urls_from_ids(self, base_url: str) -> list[str]:
        """基于提取的ID构造测试URL"""
        test_urls = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 常见的资源 API 路径模板
        api_templates = [
            "/api/user/{id}",
            "/api/users/{id}",
            "/api/users/{id}/profile",
            "/api/account/{id}",
            "/api/order/{id}",
            "/api/orders/{id}",
            "/api/invoice/{id}",
            "/api/file/{id}",
            "/api/files/{id}/download",
            "/api/message/{id}",
            "/api/project/{id}",
            "/api/team/{id}",
            "/api/org/{id}",
            "/api/v1/user/{id}",
            "/api/v1/users/{id}",
            "/api/v2/user/{id}",
        ]

        for id_info in self.extracted_ids:
            if id_info.pattern_type == "numeric":
                for template in api_templates:
                    url = base + template.replace("{id}", id_info.sample_value)
                    if url not in test_urls:
                        test_urls.append(url)

            # 也基于发现 URL 的路径模式构造
            source_parsed = urlparse(id_info.found_in_url)
            source_path = source_parsed.path
            # 尝试在路径中替换其他数字为目标ID
            parts = source_path.split("/")
            for i, part in enumerate(parts):
                if re.match(r"^\d+$", part):
                    new_parts = list(parts)
                    new_parts[i] = id_info.sample_value
                    new_url = base + "/".join(new_parts)
                    if new_url not in test_urls:
                        test_urls.append(new_url)

        return test_urls[:50]  # 限制数量

    def _detect_private_data(self, body: str) -> list[str]:
        """检测响应中的敏感数据字段"""
        found = []
        for pattern in self.PRIVATE_FIELD_PATTERNS:
            if re.search(pattern, body, re.I):
                # 提取字段名
                field_match = re.search(r'"(\w+)"\s*:', pattern)
                if field_match:
                    found.append(field_match.group(1))
                else:
                    found.append(pattern[:30])
        return found

    def _hash_body(self, body: str) -> str:
        """计算响应体hash（去除动态字段后）"""
        if not body:
            return ""
        # 移除常见的动态字段（时间戳、csrf token等）
        cleaned = re.sub(r'"(timestamp|created_at|updated_at|csrf|nonce|request_id)"\s*:\s*"[^"]*"', '', body)
        cleaned = re.sub(r'"(timestamp|created_at|updated_at)"\s*:\s*\d+', '', cleaned)
        return hashlib.sha256(cleaned.encode("utf-8", "ignore")).hexdigest()[:16]

    def get_confirmed_findings(self) -> list[DualAccountResult]:
        """获取确认的IDOR发现"""
        return [r for r in self.results if r.verdict == "idor_confirmed"]

    def get_review_needed(self) -> list[DualAccountResult]:
        """获取需要人工确认的发现"""
        return [r for r in self.results if r.verdict == "needs_review"]

    def get_summary(self) -> dict:
        """获取测试摘要"""
        return {
            "total_tested": len(self.results),
            "confirmed_idor": len(self.get_confirmed_findings()),
            "needs_review": len(self.get_review_needed()),
            "access_denied": len([r for r in self.results if r.verdict == "access_denied"]),
            "public_data": len([r for r in self.results if r.verdict == "public_data"]),
            "extracted_ids": len(self.extracted_ids),
        }
