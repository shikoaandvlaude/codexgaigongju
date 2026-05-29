#!/usr/bin/env python3
"""
Report Generator — 专业渗透测试报告生成器

功能：
1. 多格式输出（Markdown/HTML/JSON/PDF-ready）
2. 自动严重性评估（CVSS 评分参考）
3. 复现步骤自动生成
4. PoC 代码嵌入
5. 修复建议生成
6. 执行摘要（管理层可读）
7. 漏洞统计图表数据
8. SRC 平台提交格式适配（HackerOne/Bugcrowd/补天/漏洞盒子）

用法：
    from report_generator import ReportGenerator
    
    gen = ReportGenerator(config)
    report = gen.generate(findings, target="example.com", format="markdown")
"""

import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path



# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """标准化漏洞发现"""
    id: str = ""
    title: str = ""
    severity: str = "medium"  # critical/high/medium/low/info
    cvss_score: float = 0.0
    # 分类
    vuln_type: str = ""  # sqli/xss/rce/idor/ssrf/auth_bypass...
    cwe_id: str = ""
    # 详情
    description: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    # 证据
    evidence: str = ""
    request: str = ""
    response: str = ""
    screenshot: str = ""  # 截图路径
    # 影响
    impact: str = ""
    # 复现
    steps_to_reproduce: List[str] = field(default_factory=list)
    # 修复
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    # 元数据
    found_by: str = "Bai Auto-Hunt Agent"
    timestamp: str = ""
    status: str = "new"  # new/confirmed/fixed/wontfix


# CVSS 参考评分
SEVERITY_CVSS = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "info": (0.0, 0.0),
}

# CWE 映射
VULN_CWE_MAP = {
    "sqli": ("CWE-89", "SQL Injection"),
    "xss": ("CWE-79", "Cross-Site Scripting"),
    "rce": ("CWE-78", "OS Command Injection"),
    "idor": ("CWE-639", "Insecure Direct Object Reference"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "auth_bypass": ("CWE-287", "Improper Authentication"),
    "path_traversal": ("CWE-22", "Path Traversal"),
    "file_upload": ("CWE-434", "Unrestricted File Upload"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "open_redirect": ("CWE-601", "Open Redirect"),
    "xxe": ("CWE-611", "XML External Entity"),
    "ssti": ("CWE-1336", "Server-Side Template Injection"),
    "cors": ("CWE-942", "Overly Permissive CORS Policy"),
    "jwt": ("CWE-347", "Improper Verification of Cryptographic Signature"),
    "subdomain_takeover": ("CWE-295", "Subdomain Takeover"),
    "credential_exposure": ("CWE-798", "Hard-coded Credentials"),
    "graphql_introspection": ("CWE-200", "Information Exposure"),
    "rate_limit_bypass": ("CWE-307", "Improper Restriction of Excessive Authentication Attempts"),
    "mass_assignment": ("CWE-915", "Mass Assignment"),
}

# 修复建议模板
REMEDIATION_TEMPLATES = {
    "sqli": "使用参数化查询/预编译语句。对所有用户输入进行验证和转义。使用 ORM 框架。",
    "xss": "对输出进行 HTML 实体编码。实施 CSP (Content-Security-Policy)。使用安全的模板引擎自动转义。",
    "rce": "避免将用户输入传递给系统命令。使用白名单验证。如必须执行命令，使用安全的 API 替代 shell 调用。",
    "idor": "实施严格的对象级授权检查。使用不可预测的标识符（UUID）。在每次访问时验证用户权限。",
    "ssrf": "实施 URL 白名单。禁止访问内网 IP 地址段。使用专用的 HTTP 客户端库并禁用重定向。",
    "auth_bypass": "修复认证逻辑。确保所有敏感端点都有统一的认证中间件。禁止通过 HTTP 头绕过。",
    "subdomain_takeover": "删除不再使用的 DNS CNAME 记录。定期审计 DNS 配置。",
    "credential_exposure": "从代码中移除硬编码凭证。使用环境变量或密钥管理服务。轮换已泄露的密钥。",
    "cors": "限制 Access-Control-Allow-Origin 为可信域名。不使用通配符 *。验证 Origin 头。",
}



class ReportGenerator:
    """专业渗透测试报告生成器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.output_dir = Path(self.config.get("output_dir", "./reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.author = self.config.get("author", "Bai Auto-Hunt Agent")

    def generate(self, findings: List[Finding], target: str,
                 format: str = "markdown", scan_duration: float = 0) -> str:
        """
        生成报告
        
        Args:
            findings: 漏洞发现列表
            target: 目标
            format: 输出格式 (markdown/html/json/hackerone/bugcrowd/butian)
        """
        # 标准化 findings
        findings = self._normalize_findings(findings)

        if format == "markdown":
            report = self._generate_markdown(findings, target, scan_duration)
        elif format == "html":
            report = self._generate_html(findings, target, scan_duration)
        elif format == "json":
            report = self._generate_json(findings, target, scan_duration)
        elif format == "hackerone":
            report = self._generate_hackerone(findings, target)
        elif format == "bugcrowd":
            report = self._generate_bugcrowd(findings, target)
        elif format == "butian":
            report = self._generate_butian(findings, target)
        else:
            report = self._generate_markdown(findings, target, scan_duration)

        # 保存报告
        ext = {"markdown": "md", "html": "html", "json": "json"}.get(format, "md")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_{timestamp}.{ext}"
        filepath = self.output_dir / filename
        filepath.write_text(report, encoding="utf-8")
        print(f"[+] Report saved: {filepath}")

        return report

    def _normalize_findings(self, findings: List[Finding]) -> List[Finding]:
        """标准化和增强 findings"""
        for f in findings:
            # 生成 ID
            if not f.id:
                f.id = hashlib.md5(f"{f.endpoint}{f.vuln_type}{f.payload}".encode()).hexdigest()[:8]

            # 添加 CWE
            if not f.cwe_id and f.vuln_type in VULN_CWE_MAP:
                f.cwe_id = VULN_CWE_MAP[f.vuln_type][0]

            # 添加 CVSS
            if f.cvss_score == 0 and f.severity in SEVERITY_CVSS:
                low, high = SEVERITY_CVSS[f.severity]
                f.cvss_score = round((low + high) / 2, 1)

            # 添加修复建议
            if not f.remediation and f.vuln_type in REMEDIATION_TEMPLATES:
                f.remediation = REMEDIATION_TEMPLATES[f.vuln_type]

            # 时间戳
            if not f.timestamp:
                f.timestamp = datetime.now().isoformat()

        # 按严重性排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: severity_order.get(x.severity, 5))
        return findings


    # ═══════════════════════════════════════════════════════════════
    # Markdown 报告
    # ═══════════════════════════════════════════════════════════════

    def _generate_markdown(self, findings: List[Finding], target: str, duration: float) -> str:
        """生成 Markdown 格式报告"""
        lines = []

        # 标题
        lines.append(f"# Penetration Test Report: {target}")
        lines.append(f"\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"**Tester:** {self.author}")
        lines.append(f"**Duration:** {duration:.0f}s" if duration else "")
        lines.append("")

        # 执行摘要
        lines.append("## Executive Summary\n")
        stats = self._get_stats(findings)
        lines.append(f"A security assessment was conducted on **{target}**. ")
        lines.append(f"The assessment identified **{stats['total']}** vulnerabilities:\n")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = stats.get(sev, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
                lines.append(f"| {emoji} {sev.upper()} | {count} |")
        lines.append("")

        # 风险评级
        if stats.get("critical", 0) > 0:
            lines.append("> **Overall Risk: CRITICAL** — Immediate action required.\n")
        elif stats.get("high", 0) > 0:
            lines.append("> **Overall Risk: HIGH** — Urgent remediation needed.\n")
        elif stats.get("medium", 0) > 0:
            lines.append("> **Overall Risk: MEDIUM** — Remediation should be planned.\n")
        else:
            lines.append("> **Overall Risk: LOW** — Minor issues identified.\n")

        # 详细发现
        lines.append("## Detailed Findings\n")
        for i, finding in enumerate(findings, 1):
            lines.append(f"### {i}. [{finding.severity.upper()}] {finding.title}\n")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {finding.severity.upper()} (CVSS: {finding.cvss_score}) |")
            lines.append(f"| **Type** | {finding.vuln_type} |")
            if finding.cwe_id:
                lines.append(f"| **CWE** | {finding.cwe_id} |")
            lines.append(f"| **Endpoint** | `{finding.endpoint}` |")
            if finding.parameter:
                lines.append(f"| **Parameter** | `{finding.parameter}` |")
            lines.append("")

            # 描述
            if finding.description:
                lines.append(f"**Description:**\n{finding.description}\n")

            # 影响
            if finding.impact:
                lines.append(f"**Impact:**\n{finding.impact}\n")

            # 复现步骤
            if finding.steps_to_reproduce:
                lines.append("**Steps to Reproduce:**\n")
                for step_num, step in enumerate(finding.steps_to_reproduce, 1):
                    lines.append(f"{step_num}. {step}")
                lines.append("")

            # Payload
            if finding.payload:
                lines.append(f"**Payload:**\n```\n{finding.payload}\n```\n")

            # 证据
            if finding.evidence:
                lines.append(f"**Evidence:**\n```\n{finding.evidence[:500]}\n```\n")

            # 修复建议
            if finding.remediation:
                lines.append(f"**Remediation:**\n{finding.remediation}\n")

            # 参考
            if finding.references:
                lines.append("**References:**")
                for ref in finding.references:
                    lines.append(f"- {ref}")
                lines.append("")

            lines.append("---\n")

        return "\n".join(lines)


    # ═══════════════════════════════════════════════════════════════
    # HTML 报告
    # ═══════════════════════════════════════════════════════════════

    def _generate_html(self, findings: List[Finding], target: str, duration: float) -> str:
        """生成 HTML 格式报告"""
        stats = self._get_stats(findings)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Pentest Report - {target}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
.header {{ background: #1a1a2e; color: white; padding: 30px; border-radius: 8px; }}
.stats {{ display: flex; gap: 15px; margin: 20px 0; }}
.stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; flex: 1; }}
.critical {{ border-left: 4px solid #dc3545; }}
.high {{ border-left: 4px solid #fd7e14; }}
.medium {{ border-left: 4px solid #ffc107; }}
.low {{ border-left: 4px solid #0dcaf0; }}
.finding {{ border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 15px 0; }}
.finding h3 {{ margin-top: 0; }}
.badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }}
.badge-critical {{ background: #dc3545; }}
.badge-high {{ background: #fd7e14; }}
.badge-medium {{ background: #ffc107; color: #333; }}
.badge-low {{ background: #0dcaf0; color: #333; }}
code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 6px; overflow-x: auto; }}
</style>
</head>
<body>
<div class="header">
<h1>Security Assessment Report</h1>
<p>Target: <strong>{target}</strong></p>
<p>Date: {datetime.now().strftime('%Y-%m-%d')} | Author: {self.author}</p>
</div>

<div class="stats">
<div class="stat-card"><h3>{stats['total']}</h3><p>Total Findings</p></div>
<div class="stat-card" style="border-left:4px solid #dc3545"><h3>{stats.get('critical',0)}</h3><p>Critical</p></div>
<div class="stat-card" style="border-left:4px solid #fd7e14"><h3>{stats.get('high',0)}</h3><p>High</p></div>
<div class="stat-card" style="border-left:4px solid #ffc107"><h3>{stats.get('medium',0)}</h3><p>Medium</p></div>
<div class="stat-card" style="border-left:4px solid #0dcaf0"><h3>{stats.get('low',0)}</h3><p>Low</p></div>
</div>

<h2>Findings</h2>
"""
        for i, f in enumerate(findings, 1):
            html += f"""
<div class="finding {f.severity}">
<h3><span class="badge badge-{f.severity}">{f.severity.upper()}</span> {i}. {f.title}</h3>
<p><strong>Type:</strong> {f.vuln_type} | <strong>CVSS:</strong> {f.cvss_score} | <strong>CWE:</strong> {f.cwe_id}</p>
<p><strong>Endpoint:</strong> <code>{f.endpoint}</code></p>
{"<p><strong>Description:</strong> " + f.description + "</p>" if f.description else ""}
{"<p><strong>Impact:</strong> " + f.impact + "</p>" if f.impact else ""}
{"<pre>" + f.payload[:300] + "</pre>" if f.payload else ""}
{"<p><strong>Remediation:</strong> " + f.remediation + "</p>" if f.remediation else ""}
</div>
"""
        html += "</body></html>"
        return html


    # ═══════════════════════════════════════════════════════════════
    # JSON 报告
    # ═══════════════════════════════════════════════════════════════

    def _generate_json(self, findings: List[Finding], target: str, duration: float) -> str:
        """生成 JSON 格式报告"""
        data = {
            "report": {
                "target": target,
                "date": datetime.now().isoformat(),
                "author": self.author,
                "duration_seconds": duration,
            },
            "summary": self._get_stats(findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "vuln_type": f.vuln_type,
                    "cwe_id": f.cwe_id,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "parameter": f.parameter,
                    "description": f.description,
                    "impact": f.impact,
                    "payload": f.payload,
                    "evidence": f.evidence[:500],
                    "steps_to_reproduce": f.steps_to_reproduce,
                    "remediation": f.remediation,
                    "references": f.references,
                    "timestamp": f.timestamp,
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    # ═══════════════════════════════════════════════════════════════
    # SRC 平台格式
    # ═══════════════════════════════════════════════════════════════

    def _generate_hackerone(self, findings: List[Finding], target: str) -> str:
        """HackerOne 提交格式"""
        reports = []
        for f in findings:
            report = f"""## Summary
{f.description or f.title}

## Steps To Reproduce
{chr(10).join(f"{i+1}. {s}" for i, s in enumerate(f.steps_to_reproduce)) if f.steps_to_reproduce else "1. Navigate to " + f.endpoint}

## Impact
{f.impact or "An attacker could exploit this vulnerability to compromise user data."}

## Supporting Material/References
- Endpoint: `{f.endpoint}`
- Parameter: `{f.parameter}`
- Payload: `{f.payload}`

{chr(10).join("- " + r for r in f.references) if f.references else ""}
"""
            reports.append(f"# [{f.severity.upper()}] {f.title}\n\n{report}\n{'='*60}\n")
        return "\n".join(reports)

    def _generate_bugcrowd(self, findings: List[Finding], target: str) -> str:
        """Bugcrowd 提交格式"""
        reports = []
        for f in findings:
            report = f"""**Title:** {f.title}
**Severity:** {f.severity.upper()}
**URL:** {f.endpoint}
**Vulnerability Type:** {f.vuln_type}

**Description:**
{f.description or f.title}

**Proof of Concept:**
{f.payload or "See steps below"}

**Steps to Reproduce:**
{chr(10).join(f"{i+1}. {s}" for i, s in enumerate(f.steps_to_reproduce)) if f.steps_to_reproduce else "1. Visit " + f.endpoint}

**Impact:**
{f.impact}

**Suggested Fix:**
{f.remediation}
"""
            reports.append(report + "\n" + "=" * 60 + "\n")
        return "\n".join(reports)

    def _generate_butian(self, findings: List[Finding], target: str) -> str:
        """补天/漏洞盒子 中文提交格式"""
        reports = []
        severity_cn = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
        for f in findings:
            report = f"""【漏洞标题】{f.title}
【危害等级】{severity_cn.get(f.severity, "中危")}
【漏洞类型】{f.vuln_type}
【漏洞地址】{f.endpoint}

【漏洞描述】
{f.description or f.title}

【复现步骤】
{chr(10).join(f"{i+1}. {s}" for i, s in enumerate(f.steps_to_reproduce)) if f.steps_to_reproduce else "1. 访问 " + f.endpoint}

【漏洞证明】
Payload: {f.payload}
{f.evidence[:300] if f.evidence else ""}

【影响范围】
{f.impact}

【修复建议】
{f.remediation}
"""
            reports.append(report + "\n" + "=" * 60 + "\n")
        return "\n".join(reports)


    # ═══════════════════════════════════════════════════════════════
    # 工具函数
    # ═══════════════════════════════════════════════════════════════

    def _get_stats(self, findings: List[Finding]) -> Dict:
        """统计摘要"""
        stats = {"total": len(findings)}
        for f in findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1
        return stats

    def from_raw_findings(self, raw_findings: List[Dict]) -> List[Finding]:
        """从原始字典转换为标准 Finding 对象"""
        findings = []
        for raw in raw_findings:
            f = Finding(
                title=raw.get("title", raw.get("vulnerability", raw.get("name", "Unknown"))),
                severity=raw.get("severity", "medium"),
                vuln_type=raw.get("vuln_type", raw.get("type", "")),
                description=raw.get("description", ""),
                endpoint=raw.get("endpoint", raw.get("url", raw.get("target", ""))),
                method=raw.get("method", "GET"),
                parameter=raw.get("parameter", raw.get("param", "")),
                payload=raw.get("payload", ""),
                evidence=raw.get("evidence", raw.get("response_excerpt", "")),
                impact=raw.get("impact", ""),
                remediation=raw.get("remediation", ""),
                timestamp=raw.get("timestamp", datetime.now().isoformat()),
            )
            # 步骤
            steps = raw.get("steps_to_reproduce", raw.get("steps", []))
            if isinstance(steps, str):
                f.steps_to_reproduce = [steps]
            else:
                f.steps_to_reproduce = steps

            findings.append(f)
        return findings

    def generate_executive_summary(self, findings: List[Finding], target: str) -> str:
        """生成管理层摘要"""
        stats = self._get_stats(findings)
        critical_findings = [f for f in findings if f.severity == "critical"][:3]

        summary = f"""## Executive Summary

A security assessment of **{target}** was conducted on {datetime.now().strftime('%B %d, %Y')}.

### Key Findings
- **{stats['total']}** security vulnerabilities were identified
- **{stats.get('critical', 0)}** critical and **{stats.get('high', 0)}** high severity issues require immediate attention
- Overall security posture: {'**CRITICAL RISK**' if stats.get('critical', 0) > 0 else '**HIGH RISK**' if stats.get('high', 0) > 0 else '**MODERATE RISK**'}

### Immediate Actions Required
"""
        if critical_findings:
            for i, f in enumerate(critical_findings, 1):
                summary += f"{i}. **{f.title}** — {f.impact or f.description[:100]}\n"
        else:
            summary += "No critical findings require immediate action.\n"

        summary += f"""
### Risk Distribution
| Severity | Count | Percentage |
|----------|-------|-----------|
"""
        for sev in ["critical", "high", "medium", "low"]:
            count = stats.get(sev, 0)
            pct = (count / max(stats['total'], 1)) * 100
            summary += f"| {sev.upper()} | {count} | {pct:.0f}% |\n"

        return summary
