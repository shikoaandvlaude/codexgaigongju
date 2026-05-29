#!/usr/bin/env python3
"""
Active Fuzzer — 基于响应差异的主动参数 Fuzz 模块
不再依赖历史URL和被动收集，而是主动探测注入点

核心方法论：
1. 对每个参数发送 baseline 请求
2. 逐个替换为各类 payload
3. 对比响应差异（长度/状态码/时间/反射）
4. 差异超过阈值 → 标记为潜在注入点
5. 用确认性 payload 二次验证

这是手工挖洞的核心技术的自动化版本。
"""

import asyncio
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Optional
from dataclasses import dataclass, field

from http_engine import HttpEngine, HttpResponse, DiffResult
from payload_generator import PayloadGenerator


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class FuzzFinding:
    """Fuzz 发现"""
    url: str = ""
    param: str = ""
    vuln_type: str = ""  # sqli/xss/ssti/ssrf/lfi/redirect
    severity: str = "medium"
    confidence: float = 0.0  # 0-1
    payload: str = ""
    evidence: str = ""
    anomaly_score: int = 0
    reflection_context: str = ""
    # 二次确认状态
    confirmed: bool = False
    confirm_evidence: str = ""


@dataclass
class FuzzTarget:
    """Fuzz 目标"""
    url: str = ""
    method: str = "GET"
    params: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    body_template: dict = field(default_factory=dict)
    # 元数据
    tech_stack: str = ""  # 探测到的技术栈
    has_waf: bool = False


# ═══════════════════════════════════════════════════════════════
# Active Fuzzer
# ═══════════════════════════════════════════════════════════════

class ActiveFuzzer:
    """
    基于响应差异的主动 Fuzz 引擎
    
    用法:
        fuzzer = ActiveFuzzer(http_engine, config)
        findings = await fuzzer.fuzz_url("https://target.com/api/search?q=test&page=1")
        findings = await fuzzer.fuzz_endpoint(target)
    """

    def __init__(self, http_engine: HttpEngine, config: dict = None):
        self.http = http_engine
        self.config = config or {}
        self.payload_gen = PayloadGenerator(config)
        self.findings: list[FuzzFinding] = []
        
        # 配置
        self.anomaly_threshold = self.config.get("anomaly_threshold", 30)
        self.confirm_threshold = self.config.get("confirm_threshold", 60)
        self.max_params_per_url = self.config.get("max_params_per_url", 10)
        self.skip_static = self.config.get("skip_static", True)
        self.auto_confirm = self.config.get("auto_confirm", True)

    # ─── 主入口：Fuzz 一个 URL ──────────────────────────────────

    async def fuzz_url(
        self,
        url: str,
        method: str = "GET",
        extra_headers: dict = None,
        cookies: dict = None,
        body_params: dict = None,
    ) -> list[FuzzFinding]:
        """
        对一个 URL 的所有参数进行 fuzz
        
        1. 解析 URL 中的参数
        2. 对每个参数逐一测试多种漏洞类型
        3. 返回所有异常发现
        """
        findings = []

        # 跳过静态资源
        if self.skip_static and self._is_static(url):
            return findings

        # 解析参数
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # GET 参数 fuzz
        param_count = 0
        for param_name in query_params:
            if param_count >= self.max_params_per_url:
                break
            param_findings = await self._fuzz_single_param(
                url, param_name, "GET", extra_headers, cookies
            )
            findings.extend(param_findings)
            param_count += 1

        # POST body 参数 fuzz
        if body_params and method.upper() in ("POST", "PUT", "PATCH"):
            for param_name in body_params:
                if param_count >= self.max_params_per_url:
                    break
                param_findings = await self._fuzz_single_param(
                    url, param_name, method, extra_headers, cookies,
                    body_template=body_params
                )
                findings.extend(param_findings)
                param_count += 1

        # 二次确认
        if self.auto_confirm:
            findings = await self._confirm_findings(findings, extra_headers, cookies)

        self.findings.extend(findings)
        return findings

    # ─── Fuzz 单个参数 ─────────────────────────────────────────

    async def _fuzz_single_param(
        self,
        url: str,
        param: str,
        method: str,
        headers: dict = None,
        cookies: dict = None,
        body_template: dict = None,
    ) -> list[FuzzFinding]:
        """对单个参数进行多类型 fuzz"""
        findings = []

        # 获取轻量级检测 payload
        detection_payloads = self.payload_gen.get_detection_payloads()

        for vuln_type, payloads in detection_payloads.items():
            # 用响应差异检测
            diff_results = await self.http.diff_responses(
                url=url,
                param=param,
                payloads=payloads,
                method=method,
                extra_headers=headers,
                cookies=cookies,
                body_template=body_template,
            )

            # 分析差异结果
            for diff in diff_results:
                if diff.anomaly_score >= self.anomaly_threshold:
                    finding = FuzzFinding(
                        url=url,
                        param=param,
                        vuln_type=vuln_type,
                        payload=diff.payload,
                        anomaly_score=diff.anomaly_score,
                        reflection_context=diff.reflection_context,
                        evidence=self._build_evidence(diff),
                        confidence=diff.anomaly_score / 100.0,
                        severity=self._assess_severity(vuln_type, diff),
                    )
                    findings.append(finding)

        return findings

    # ─── 二次确认 ──────────────────────────────────────────────

    async def _confirm_findings(
        self,
        findings: list[FuzzFinding],
        headers: dict = None,
        cookies: dict = None,
    ) -> list[FuzzFinding]:
        """对初始发现进行二次确认"""
        confirmed = []

        for finding in findings:
            if finding.anomaly_score < self.anomaly_threshold:
                continue

            # 获取确认性 payload
            confirm_payloads = self.payload_gen.get_confirm_payloads(
                finding.vuln_type,
                {
                    "reflection_context": finding.reflection_context,
                    "payload": finding.payload,
                }
            )

            if not confirm_payloads:
                confirmed.append(finding)
                continue

            # 根据漏洞类型执行不同的确认逻辑
            if finding.vuln_type == "sqli":
                is_confirmed = await self._confirm_sqli(
                    finding, confirm_payloads, headers, cookies
                )
            elif finding.vuln_type == "xss":
                is_confirmed = await self._confirm_xss(
                    finding, confirm_payloads, headers, cookies
                )
            elif finding.vuln_type == "ssti":
                is_confirmed = await self._confirm_ssti(
                    finding, confirm_payloads, headers, cookies
                )
            else:
                is_confirmed = finding.anomaly_score >= self.confirm_threshold

            if is_confirmed:
                finding.confirmed = True
                finding.confidence = min(1.0, finding.confidence + 0.3)
                confirmed.append(finding)
            elif finding.anomaly_score >= self.confirm_threshold:
                # 高异常分但未能确认，仍保留但标记
                finding.confirm_evidence = "未能通过二次确认，但异常分较高"
                confirmed.append(finding)

        return confirmed

    async def _confirm_sqli(
        self,
        finding: FuzzFinding,
        payloads: list[str],
        headers: dict,
        cookies: dict,
    ) -> bool:
        """
        SQLi 确认：布尔差异法
        发送 TRUE 和 FALSE 条件，如果响应不同 → 确认注入
        """
        true_payloads = [p for p in payloads if "1=1" in p or "'a'='a'" in p]
        false_payloads = [p for p in payloads if "1=2" in p or "'a'='b'" in p]

        if not true_payloads or not false_payloads:
            return False

        # 发送 TRUE 条件
        diff_true = await self.http.diff_responses(
            url=finding.url,
            param=finding.param,
            payloads=true_payloads[:2],
            extra_headers=headers,
            cookies=cookies,
        )

        # 发送 FALSE 条件
        diff_false = await self.http.diff_responses(
            url=finding.url,
            param=finding.param,
            payloads=false_payloads[:2],
            extra_headers=headers,
            cookies=cookies,
        )

        if not diff_true or not diff_false:
            return False

        # 核心判断：TRUE 和 FALSE 的响应应该不同
        # 且 TRUE 应该和 baseline 相似
        true_resp = diff_true[0].response
        false_resp = diff_false[0].response

        if true_resp and false_resp:
            # 状态码不同
            if true_resp.status_code != false_resp.status_code:
                finding.confirm_evidence = (
                    f"布尔盲注确认: TRUE({true_payloads[0]})→{true_resp.status_code}, "
                    f"FALSE({false_payloads[0]})→{false_resp.status_code}"
                )
                return True

            # 响应长度显著不同
            len_diff = abs(true_resp.content_length - false_resp.content_length)
            if len_diff > 20:
                finding.confirm_evidence = (
                    f"布尔盲注确认: TRUE 响应长度={true_resp.content_length}, "
                    f"FALSE 响应长度={false_resp.content_length} (差异={len_diff})"
                )
                return True

        return False

    async def _confirm_xss(
        self,
        finding: FuzzFinding,
        payloads: list[str],
        headers: dict,
        cookies: dict,
    ) -> bool:
        """
        XSS 确认：检查 payload 在响应中是否未经编码地反射
        """
        for payload in payloads[:3]:
            diff_results = await self.http.diff_responses(
                url=finding.url,
                param=finding.param,
                payloads=[payload],
                extra_headers=headers,
                cookies=cookies,
            )

            if diff_results:
                diff = diff_results[0]
                if diff.reflected and diff.response:
                    # 检查是否在危险上下文中反射
                    body = diff.response.body
                    if payload in body:
                        # 检查是否被 HTML 编码
                        encoded_payload = (payload
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\"", "&quot;"))
                        
                        if encoded_payload not in body:
                            # 未被编码！确认 XSS
                            finding.confirm_evidence = (
                                f"XSS确认: payload '{payload[:50]}' 未经编码反射, "
                                f"上下文: {diff.reflection_context}"
                            )
                            return True

        return False

    async def _confirm_ssti(
        self,
        finding: FuzzFinding,
        payloads: list[str],
        headers: dict,
        cookies: dict,
    ) -> bool:
        """
        SSTI 确认：检查数学运算是否被执行
        {{7*7}} 如果响应中出现 49 → 确认 SSTI
        """
        math_tests = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("{{7*'7'}}", "7777777"),  # Jinja2 特征
            ("<%= 7*7 %>", "49"),
        ]

        for payload, expected in math_tests:
            diff_results = await self.http.diff_responses(
                url=finding.url,
                param=finding.param,
                payloads=[payload],
                extra_headers=headers,
                cookies=cookies,
            )

            if diff_results and diff_results[0].response:
                body = diff_results[0].response.body
                if expected in body and payload not in body:
                    # 运算结果出现，但原始 payload 不在（说明被执行了）
                    finding.confirm_evidence = (
                        f"SSTI确认: payload '{payload}' 执行后响应包含 '{expected}'"
                    )
                    return True

        return False

    # ─── 高级 Fuzz 模式 ────────────────────────────────────────

    async def fuzz_hidden_params(
        self,
        url: str,
        wordlist: list[str] = None,
        method: str = "GET",
        headers: dict = None,
        cookies: dict = None,
    ) -> list[str]:
        """
        隐藏参数发现 — 通过响应差异检测未文档化的参数
        
        原理：
        1. 获取 baseline（无额外参数）
        2. 逐个添加候选参数名
        3. 如果响应发生变化 → 发现隐藏参数
        """
        if wordlist is None:
            wordlist = self._default_param_wordlist()

        discovered = []
        
        # baseline
        baseline = await self.http.request(method, url, headers=headers, cookies=cookies)
        if baseline.error:
            return discovered

        # 批量测试
        for param_name in wordlist:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param_name] = ["test"]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            resp = await self.http.request(method, test_url, headers=headers, cookies=cookies)
            
            if resp.error:
                continue

            # 对比差异
            length_diff = abs(resp.content_length - baseline.content_length)
            status_diff = resp.status_code != baseline.status_code

            if status_diff or length_diff > 50:
                discovered.append(param_name)

        return discovered

    async def fuzz_endpoints(
        self,
        base_url: str,
        wordlist: list[str] = None,
        headers: dict = None,
        cookies: dict = None,
    ) -> list[dict]:
        """
        端点发现 — 暴力探测隐藏 API 路径
        
        返回: [{"path": "/api/admin", "status": 200, "length": 1234}, ...]
        """
        if wordlist is None:
            wordlist = self._default_endpoint_wordlist()

        discovered = []
        
        for path in wordlist:
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            resp = await self.http.request("GET", url, headers=headers, cookies=cookies)
            
            if resp.error:
                continue

            # 有意义的响应（非404/通用错误页）
            if resp.status_code in (200, 201, 301, 302, 403, 405):
                discovered.append({
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "length": resp.content_length,
                    "content_type": resp.content_type,
                })

        return discovered

    async def fuzz_auth_bypass(
        self,
        url: str,
        cookies: dict = None,
    ) -> list[dict]:
        """
        认证绕过测试 — 用各种 header 尝试绕过 403
        """
        bypasses = []
        bypass_headers_list = self.payload_gen.get_auth_bypass_headers()

        # 先确认原始请求是 403
        original = await self.http.request("GET", url, cookies=cookies)
        if original.status_code not in (401, 403):
            return bypasses  # 不是受限页面，不需要绕过

        for bypass_headers in bypass_headers_list:
            resp = await self.http.request("GET", url, headers=bypass_headers, cookies=cookies)
            
            if resp.status_code == 200:
                bypasses.append({
                    "url": url,
                    "headers": bypass_headers,
                    "status": resp.status_code,
                    "evidence": f"原始403, 加 {list(bypass_headers.keys())[0]} 后变200",
                })

        # 路径绕过
        path_bypasses = [
            url + "/",
            url + "/.",
            url + "//",
            url + "/./",
            url + "%2f",
            url.replace("/admin", "/ADMIN"),
            url.replace("/admin", "/Admin"),
            url + "?anything",
            url + "#",
            url + "%20",
            url + "..;/",
        ]

        for bypass_url in path_bypasses:
            resp = await self.http.request("GET", bypass_url, cookies=cookies)
            if resp.status_code == 200:
                bypasses.append({
                    "url": bypass_url,
                    "headers": {},
                    "status": resp.status_code,
                    "evidence": f"路径绕过: {bypass_url}",
                })

        return bypasses

    # ─── 辅助方法 ─────────────────────────────────────────────

    def _build_evidence(self, diff: DiffResult) -> str:
        """构建证据描述"""
        parts = []
        if diff.status_diff:
            parts.append(f"状态码变化→{diff.response.status_code if diff.response else '?'}")
        if diff.length_diff > 0:
            parts.append(f"长度差异={diff.length_diff}({diff.length_diff_percent:.1f}%)")
        if diff.time_diff > 1:
            parts.append(f"时间延迟={diff.time_diff:.2f}s")
        if diff.reflected:
            parts.append(f"反射点={diff.reflection_context}")
        if diff.header_diff:
            parts.append(f"Header差异={len(diff.header_diff)}个")
        return "; ".join(parts) if parts else "异常分超阈值"

    def _assess_severity(self, vuln_type: str, diff: DiffResult) -> str:
        """评估严重程度"""
        if vuln_type in ("sqli", "ssti", "ssrf") and diff.anomaly_score >= 60:
            return "high"
        elif vuln_type == "xss" and diff.reflected:
            if diff.reflection_context in ("js_block", "event_handler"):
                return "high"
            return "medium"
        elif diff.anomaly_score >= 80:
            return "high"
        elif diff.anomaly_score >= 50:
            return "medium"
        return "low"

    def _is_static(self, url: str) -> bool:
        """判断是否是静态资源"""
        static_exts = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
            ".mp3", ".mp4", ".avi", ".pdf", ".zip",
        )
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in static_exts)

    def _default_param_wordlist(self) -> list[str]:
        """常见隐藏参数名"""
        return [
            "id", "user_id", "uid", "admin", "debug", "test",
            "token", "api_key", "secret", "password", "passwd",
            "role", "is_admin", "privilege", "access_level",
            "redirect", "url", "next", "return", "callback",
            "file", "path", "filename", "template", "page",
            "sort", "order", "limit", "offset", "format",
            "action", "cmd", "command", "exec", "query",
            "search", "filter", "type", "category", "status",
            "email", "phone", "name", "username", "account",
            "invoice_id", "order_id", "payment_id", "session_id",
            "org_id", "team_id", "project_id", "workspace_id",
            "_method", "__proto__", "constructor",
            "v", "version", "api_version",
            "include", "fields", "expand", "embed",
            "lang", "locale", "currency",
        ]

    def _default_endpoint_wordlist(self) -> list[str]:
        """常见隐藏端点"""
        return [
            # Admin/Debug
            "admin", "administrator", "manage", "dashboard",
            "debug", "trace", "metrics", "health", "status",
            "info", "env", "config", "settings",
            # API
            "api", "api/v1", "api/v2", "api/internal",
            "graphql", "graphiql", "playground",
            # Files
            ".env", ".git/config", ".git/HEAD",
            "robots.txt", "sitemap.xml", ".well-known/security.txt",
            "swagger.json", "openapi.json", "api-docs",
            # Framework specific
            "actuator", "actuator/env", "actuator/heapdump",
            "telescope", "horizon", "_debugbar",
            "elmah.axd", "trace.axd",
            "server-status", "server-info",
            # Backup
            "backup", "db", "database", "dump",
            "export", "download",
            # Auth
            "login", "register", "signup", "oauth", "sso",
            "forgot-password", "reset-password",
            "token", "auth", "session",
        ]

    def get_findings_summary(self) -> dict:
        """获取发现汇总"""
        return {
            "total": len(self.findings),
            "confirmed": len([f for f in self.findings if f.confirmed]),
            "by_type": self._count_by_type(),
            "by_severity": self._count_by_severity(),
        }

    def _count_by_type(self) -> dict:
        counts = {}
        for f in self.findings:
            counts[f.vuln_type] = counts.get(f.vuln_type, 0) + 1
        return counts

    def _count_by_severity(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
