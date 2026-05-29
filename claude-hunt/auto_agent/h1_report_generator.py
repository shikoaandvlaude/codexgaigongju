#!/usr/bin/env python3
"""
H1 Report Generator — HackerOne / SRC 赏金报告模板生成器

生成符合 HackerOne 标准的 Markdown 报告，包含：
1. 标准化标题格式
2. CVSS 3.1 评分
3. 复现步骤（curl 命令级别）
4. 影响声明
5. 修复建议
6. 双环境验证（UAT → Production）

输出格式支持：
- markdown (默认) — 直接粘贴到 H1
- hackerone — H1 表单字段分离
- butian — 补天格式
- json — 机器可读

用法:
    from h1_report_generator import H1ReportGenerator
    gen = H1ReportGenerator()
    report = gen.generate(finding)
    print(report.markdown)
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# CVSS 3.1 计算
# ═══════════════════════════════════════════════════════════════

CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": False, "C": True},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def calculate_cvss(vector: dict) -> tuple[float, str]:
    """
    Calculate CVSS 3.1 Base Score from vector dict.
    vector: {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
    Returns: (score, severity_label)
    """
    try:
        av = CVSS_WEIGHTS["AV"][vector.get("AV", "N")]
        ac = CVSS_WEIGHTS["AC"][vector.get("AC", "L")]
        pr = CVSS_WEIGHTS["PR"][vector.get("PR", "N")]
        ui = CVSS_WEIGHTS["UI"][vector.get("UI", "N")]
        scope_changed = CVSS_WEIGHTS["S"][vector.get("S", "U")]
        c = CVSS_WEIGHTS["C"][vector.get("C", "N")]
        i = CVSS_WEIGHTS["I"][vector.get("I", "N")]
        a = CVSS_WEIGHTS["A"][vector.get("A", "N")]

        # ISS (Impact Sub-Score)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Impact
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif not scope_changed:
            base_score = min(impact + exploitability, 10.0)
            # Round up to nearest 0.1
            base_score = _roundup(base_score)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
            base_score = _roundup(base_score)

        # Severity label
        if base_score >= 9.0:
            label = "Critical"
        elif base_score >= 7.0:
            label = "High"
        elif base_score >= 4.0:
            label = "Medium"
        elif base_score > 0.0:
            label = "Low"
        else:
            label = "None"

        return base_score, label

    except (KeyError, TypeError):
        return 0.0, "Unknown"


def _roundup(value: float) -> float:
    """CVSS round-up to 1 decimal"""
    import math
    return math.ceil(value * 10) / 10


def vector_string(vector: dict) -> str:
    """Generate CVSS vector string"""
    return "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in vector.items())


# ═══════════════════════════════════════════════════════════════
# 漏洞类型 → CVSS 默认向量映射
# ═══════════════════════════════════════════════════════════════

DEFAULT_CVSS_VECTORS = {
    "idor": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
    "horizontal_idor": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "sqli": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "xss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "stored_xss": {"AV": "N", "AC": "L", "PR": "L", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "ssrf": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "N", "A": "N"},
    "rce": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "auth_bypass": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "race_condition": {"AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U", "C": "N", "I": "H", "A": "N"},
    "open_redirect": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "cors": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "H", "I": "N", "A": "N"},
}


# ═══════════════════════════════════════════════════════════════
# 报告数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class H1Report:
    """生成的报告"""
    title: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    markdown: str = ""
    # H1 表单字段（分离的）
    summary: str = ""
    steps_to_reproduce: str = ""
    impact_statement: str = ""
    supporting_material: str = ""
    # 元数据
    vuln_type: str = ""
    target: str = ""
    url: str = ""
    generated_at: str = ""


# ═══════════════════════════════════════════════════════════════
# Report Generator
# ═══════════════════════════════════════════════════════════════

class H1ReportGenerator:
    """
    HackerOne 赏金报告生成器

    用法:
        gen = H1ReportGenerator(target="target.com")
        report = gen.generate(finding_dict)
        print(report.markdown)  # 完整 Markdown
        print(report.steps_to_reproduce)  # 只要复现步骤
    """

    def __init__(self, target: str = "", author: str = ""):
        self.target = target
        self.author = author or "Bai Auto-Hunt Agent"

    def generate(self, finding: dict) -> H1Report:
        """从 finding dict 生成完整报告"""
        report = H1Report()
        report.generated_at = datetime.now().isoformat()
        report.target = self.target

        # 基本信息
        vuln_type = finding.get("type", "Unknown")
        report.vuln_type = vuln_type
        report.url = finding.get("url", "")

        # CVSS
        cvss_vector = self._get_cvss_vector(vuln_type, finding)
        score, severity = calculate_cvss(cvss_vector)
        report.cvss_score = score
        report.cvss_vector = vector_string(cvss_vector)
        report.severity = severity

        # 标题
        report.title = self._generate_title(vuln_type, finding, severity)

        # 各部分内容
        report.summary = self._generate_summary(vuln_type, finding, severity)
        report.steps_to_reproduce = self._generate_steps(finding)
        report.impact_statement = self._generate_impact(vuln_type, finding, severity, score)
        report.supporting_material = self._generate_evidence(finding)

        # 组装完整 Markdown
        report.markdown = self._assemble_markdown(report)

        return report

    def _get_cvss_vector(self, vuln_type: str, finding: dict) -> dict:
        """获取 CVSS 向量（优先用 finding 中的，否则用默认值）"""
        if finding.get("cvss_vector"):
            # 解析已有向量
            try:
                parts = finding["cvss_vector"].replace("CVSS:3.1/", "").split("/")
                return {p.split(":")[0]: p.split(":")[1] for p in parts}
            except (IndexError, ValueError):
                pass

        # 按类型匹配默认向量
        type_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")
        for key, vector in DEFAULT_CVSS_VECTORS.items():
            if key in type_lower:
                return dict(vector)

        # 兜底
        return {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}

    def _generate_title(self, vuln_type: str, finding: dict, severity: str) -> str:
        """生成标准化标题"""
        url = finding.get("url", "")
        # 提取路径部分
        from urllib.parse import urlparse
        parsed = urlparse(url)
        endpoint = parsed.path or url

        # 格式: [类型] 具体描述 at 端点
        type_clean = vuln_type.replace("_", " ").title()
        detail = finding.get("detail", "")

        if "idor" in vuln_type.lower():
            return f"IDOR — Unauthorized access to user data via {endpoint}"
        elif "sqli" in vuln_type.lower():
            return f"SQL Injection in {endpoint}"
        elif "xss" in vuln_type.lower():
            return f"{'Stored' if 'stored' in vuln_type.lower() else 'Reflected'} XSS in {endpoint}"
        elif "ssrf" in vuln_type.lower():
            return f"SSRF — Server-side request to internal services via {endpoint}"
        elif "rce" in vuln_type.lower():
            return f"Remote Code Execution via {endpoint}"
        elif "race" in vuln_type.lower():
            return f"Race Condition — Duplicate resource creation via {endpoint}"
        elif "auth" in vuln_type.lower():
            return f"Authentication Bypass at {endpoint}"
        else:
            return f"{type_clean} at {endpoint}"

    def _generate_summary(self, vuln_type: str, finding: dict, severity: str) -> str:
        """生成摘要"""
        url = finding.get("url", "N/A")
        detail = finding.get("detail", "")
        confidence = finding.get("confidence", finding.get("validation_confidence", ""))

        lines = [
            f"**Severity:** {severity}",
            f"**Endpoint:** `{url}`",
            f"**Type:** {vuln_type}",
            "",
        ]

        if detail:
            lines.append(detail[:300])

        return "\n".join(lines)

    def _generate_steps(self, finding: dict) -> str:
        """生成复现步骤"""
        url = finding.get("url", "https://TARGET/endpoint")
        method = finding.get("method", "GET")
        evidence = finding.get("evidence", finding.get("validation_evidence", ""))
        detail = finding.get("detail", "")

        steps = []

        # Step 1: 基本信息
        steps.append("1. Create two test accounts (Account A and Account B) on the target application.")
        steps.append("")

        # Step 2: curl 命令
        steps.append("2. Send the following request as Account B to access Account A's resource:")
        steps.append("")
        steps.append("```")

        if method.upper() == "GET":
            steps.append(f"curl -v '{url}' \\")
            steps.append(f"  -H 'Cookie: SESSION_COOKIE_OF_ACCOUNT_B'")
        else:
            steps.append(f"curl -v -X {method.upper()} '{url}' \\")
            steps.append(f"  -H 'Cookie: SESSION_COOKIE_OF_ACCOUNT_B' \\")
            steps.append(f"  -H 'Content-Type: application/json'")

        steps.append("```")
        steps.append("")

        # Step 3: 预期 vs 实际
        steps.append("3. Observe that the response contains Account A's private data:")
        steps.append("")
        if evidence:
            steps.append("```")
            steps.append(evidence[:500])
            steps.append("```")
        else:
            steps.append("*(See supporting material below)*")

        steps.append("")
        steps.append("4. Compare with the expected behavior: Account B should receive 403 Forbidden.")

        return "\n".join(steps)

    def _generate_impact(self, vuln_type: str, finding: dict, severity: str, score: float) -> str:
        """生成影响声明"""
        type_lower = vuln_type.lower()
        lines = []

        if "idor" in type_lower:
            lines.extend([
                "An attacker with a valid low-privileged account can access, modify, or delete ",
                "other users' private data by manipulating object identifiers in the API request. ",
                "This directly violates the authorization model and exposes sensitive user information ",
                "including PII, financial data, or account settings.",
            ])
        elif "sqli" in type_lower:
            lines.extend([
                "An attacker can extract the entire database contents including user credentials, ",
                "PII, and sensitive business data. Depending on database permissions, this may also ",
                "allow writing arbitrary data or executing system commands on the database server.",
            ])
        elif "xss" in type_lower:
            lines.extend([
                "An attacker can execute arbitrary JavaScript in the context of a victim's browser session. ",
                "This enables session hijacking, credential theft, or performing actions on behalf of the victim.",
            ])
        elif "ssrf" in type_lower:
            lines.extend([
                "An attacker can make the server issue requests to internal services, potentially accessing ",
                "cloud metadata endpoints (169.254.169.254), internal APIs, or other services not exposed ",
                "to the internet.",
            ])
        elif "rce" in type_lower:
            lines.extend([
                "An attacker can execute arbitrary commands on the server, leading to full system compromise, ",
                "data exfiltration, lateral movement, and potential access to other internal systems.",
            ])
        elif "race" in type_lower:
            lines.extend([
                "An attacker can exploit the race condition to perform duplicate operations (e.g., double ",
                "spending, multiple reward claims, duplicate transactions) resulting in direct financial loss.",
            ])
        else:
            lines.extend([
                f"This {vuln_type} vulnerability allows an attacker to compromise the security of the application. ",
                f"Based on the CVSS score of {score}, the impact is rated as {severity}.",
            ])

        return "".join(lines)

    def _generate_evidence(self, finding: dict) -> str:
        """生成证据/附件部分"""
        parts = []

        # 请求/响应证据
        evidence = finding.get("evidence", finding.get("validation_evidence", ""))
        if evidence:
            parts.append("### Request/Response Evidence")
            parts.append("")
            parts.append("```")
            parts.append(evidence[:2000])
            parts.append("```")
            parts.append("")

        # 验证信息
        if finding.get("reproduction_count"):
            parts.append(f"- **Reproduction count:** {finding['reproduction_count']} successful reproductions")
        if finding.get("dual_account_tested"):
            parts.append("- **Dual account tested:** Yes (two independently owned accounts)")
        if finding.get("private_data_observed"):
            parts.append("- **Private data confirmed:** Response contains non-public user data")

        return "\n".join(parts)

    def _assemble_markdown(self, report: H1Report) -> str:
        """组装完整 Markdown 报告"""
        lines = [
            f"# {report.title}",
            "",
            f"**CVSS 3.1:** {report.cvss_score} ({report.severity}) — `{report.cvss_vector}`",
            f"**Target:** {report.target}",
            f"**Generated:** {report.generated_at}",
            "",
            "---",
            "",
            "## Summary",
            "",
            report.summary,
            "",
            "---",
            "",
            "## Steps to Reproduce",
            "",
            report.steps_to_reproduce,
            "",
            "---",
            "",
            "## Impact",
            "",
            report.impact_statement,
            "",
            "---",
            "",
            "## Supporting Material / References",
            "",
            report.supporting_material,
            "",
            "---",
            "",
            "## Recommendations",
            "",
            self._generate_fix_recommendation(report.vuln_type),
            "",
        ]

        return "\n".join(lines)

    def _generate_fix_recommendation(self, vuln_type: str) -> str:
        """生成修复建议"""
        type_lower = vuln_type.lower()

        if "idor" in type_lower:
            return (
                "- Implement server-side authorization checks that verify the requesting user "
                "owns or has permission to access the requested resource.\n"
                "- Do not rely on client-side ID obfuscation — use session-bound ownership verification.\n"
                "- Add integration tests that verify cross-account access is denied."
            )
        elif "sqli" in type_lower:
            return (
                "- Use parameterized queries (prepared statements) for all database operations.\n"
                "- Implement input validation and sanitization.\n"
                "- Apply least-privilege database permissions."
            )
        elif "xss" in type_lower:
            return (
                "- Encode all user-supplied output using context-appropriate encoding.\n"
                "- Implement Content-Security-Policy headers.\n"
                "- Use frameworks' built-in XSS protection (React JSX, Vue templates)."
            )
        elif "ssrf" in type_lower:
            return (
                "- Validate and allowlist target URLs/IPs on the server side.\n"
                "- Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x).\n"
                "- Use a dedicated egress proxy for server-initiated requests."
            )
        elif "race" in type_lower:
            return (
                "- Implement database-level locking (SELECT FOR UPDATE) for financial operations.\n"
                "- Use idempotency keys to prevent duplicate processing.\n"
                "- Add rate limiting on sensitive endpoints."
            )
        else:
            return (
                "- Review and fix the vulnerable endpoint.\n"
                "- Add automated security tests to prevent regression.\n"
                "- Consider a security review of related endpoints."
            )
