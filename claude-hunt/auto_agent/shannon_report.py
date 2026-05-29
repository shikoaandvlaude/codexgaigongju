#!/usr/bin/env python3
"""
Shannon Report Generator - 结构化中文安全评估报告
移植自 Shannon 框架的报告生成能力

特性：
1. 三分类漏洞整理：已验证可利用 / 环境阻断暂未打通 / 误报
2. 中文技术报告格式
3. 修复优先级排序
4. 可复现的利用步骤记录
5. 攻击面覆盖度统计
"""

import json
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class VulnFinding:
    """单个漏洞发现"""
    id: str = ""
    vuln_type: str = ""  # injection/xss/auth/authz/ssrf/idor/race/bizlogic
    title: str = ""
    severity: str = "medium"  # critical/high/medium/low/info
    confidence: str = "medium"  # high/medium/low
    # 分类
    status: str = "exploited"  # exploited/blocked/false_positive
    # 位置
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    # 证据
    description: str = ""
    impact: str = ""
    evidence: str = ""
    payload: str = ""
    response_excerpt: str = ""
    # 利用步骤
    exploitation_steps: List[str] = field(default_factory=list)
    # 代码定位（白盒时用）
    source_file: str = ""
    source_line: int = 0
    sink_file: str = ""
    sink_line: int = 0
    data_flow: str = ""
    # 修复建议
    remediation: str = ""
    # 阻断原因（status=blocked时）
    blocker: str = ""
    bypass_attempted: List[str] = field(default_factory=list)



@dataclass
class ReconSummary:
    """侦察阶段汇总"""
    target: str = ""
    subdomains_found: int = 0
    alive_hosts: int = 0
    endpoints_found: int = 0
    params_found: int = 0
    tech_stack: List[str] = field(default_factory=list)
    waf_detected: str = ""
    open_ports: List[str] = field(default_factory=list)


@dataclass
class SecurityAssessment:
    """完整安全评估"""
    target: str = ""
    assessment_date: str = ""
    mode: str = "blackbox"  # blackbox/greybox/whitebox
    tester: str = "Bai Auto-Hunt Agent"
    # 范围
    scope: List[str] = field(default_factory=list)
    vuln_classes_tested: List[str] = field(default_factory=list)
    # 侦察汇总
    recon: Optional[ReconSummary] = None
    # 发现
    findings: List[VulnFinding] = field(default_factory=list)
    # 统计
    total_requests: int = 0
    duration_seconds: int = 0


# ═══════════════════════════════════════════════════════════════
# 报告生成器
# ═══════════════════════════════════════════════════════════════

class ShannonReportGenerator:
    """
    结构化中文安全评估报告生成器
    
    移植自 Shannon 框架，适配 Bai-codeagent 的黑盒/灰盒场景
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    SEVERITY_LABELS = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    }
    VULN_TYPE_LABELS = {
        "injection": "注入漏洞 (SQLi/命令注入/SSTI)",
        "xss": "跨站脚本 (XSS)",
        "auth": "认证缺陷",
        "authz": "授权缺陷 (越权/IDOR)",
        "ssrf": "服务端请求伪造 (SSRF)",
        "idor": "越权访问 (IDOR)",
        "race": "竞态条件",
        "bizlogic": "业务逻辑漏洞",
        "cors": "CORS 错配",
        "info_leak": "信息泄露",
        "upload": "文件上传漏洞",
        "other": "其他",
    }


    def __init__(self, assessment: SecurityAssessment):
        self.assessment = assessment

    def generate_markdown(self) -> str:
        """生成完整 Markdown 报告"""
        sections = [
            self._header(),
            self._executive_summary(),
            self._vuln_type_summary(),
            self._priority_fix_list(),
            self._exploited_section(),
            self._blocked_section(),
            self._false_positive_section(),
            self._recon_summary(),
            self._coverage_stats(),
            self._footer(),
        ]
        return "\n\n".join(s for s in sections if s)

    def generate_html(self) -> str:
        """生成 HTML 报告（嵌入样式）"""
        md_content = self.generate_markdown()
        return self._wrap_html(md_content)

    # ─── 各报告段落 ──────────────────────────────────────────

    def _header(self) -> str:
        a = self.assessment
        return f"""# 安全评估报告

| 项目 | 信息 |
|------|------|
| **目标** | {a.target} |
| **评估日期** | {a.assessment_date or datetime.now().strftime('%Y-%m-%d')} |
| **测试模式** | {a.mode} |
| **测试工具** | {a.tester} |
| **测试范围** | {', '.join(a.vuln_classes_tested) if a.vuln_classes_tested else '全覆盖'} |
| **总请求数** | {a.total_requests} |
| **耗时** | {a.duration_seconds}s |"""

    def _executive_summary(self) -> str:
        exploited = [f for f in self.assessment.findings if f.status == "exploited"]
        blocked = [f for f in self.assessment.findings if f.status == "blocked"]
        fp = [f for f in self.assessment.findings if f.status == "false_positive"]

        critical_count = len([f for f in exploited if f.severity == "critical"])
        high_count = len([f for f in exploited if f.severity == "high"])

        risk_level = "严重" if critical_count > 0 else "高" if high_count > 0 else "中" if exploited else "低"

        return f"""## 执行摘要

**整体风险等级：{risk_level}**

| 分类 | 数量 | 说明 |
|------|------|------|
| **已验证可利用** | {len(exploited)} | 已成功利用并获取证据 |
| **环境阻断暂未打通** | {len(blocked)} | 代码存在风险但当前环境阻断利用 |
| **误报/不可利用** | {len(fp)} | 经测试确认当前部署不可利用 |

### 关键发现

{self._key_findings_text(exploited)}"""


    def _key_findings_text(self, exploited: List[VulnFinding]) -> str:
        if not exploited:
            return "未发现可验证的漏洞。"
        lines = []
        sorted_findings = sorted(exploited, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 9))
        for f in sorted_findings[:5]:
            sev = self.SEVERITY_LABELS.get(f.severity, f.severity)
            lines.append(f"- **[{sev}]** {f.title} (`{f.url}`)")
        if len(exploited) > 5:
            lines.append(f"- ... 及其他 {len(exploited) - 5} 个已验证漏洞")
        return "\n".join(lines)

    def _vuln_type_summary(self) -> str:
        exploited = [f for f in self.assessment.findings if f.status == "exploited"]
        if not exploited:
            return ""

        type_groups: Dict[str, List[VulnFinding]] = {}
        for f in exploited:
            vtype = f.vuln_type or "other"
            type_groups.setdefault(vtype, []).append(f)

        lines = ["## 按漏洞类型汇总", ""]
        for vtype, findings in sorted(type_groups.items()):
            label = self.VULN_TYPE_LABELS.get(vtype, vtype)
            sevs = [self.SEVERITY_LABELS.get(f.severity, "?") for f in findings]
            sev_str = ", ".join(sevs)
            lines.append(f"**{label}** ({len(findings)} 个): {sev_str}")
            for f in findings[:3]:
                lines.append(f"  - {f.title}")
            if len(findings) > 3:
                lines.append(f"  - ... 等 {len(findings)} 个")
            lines.append("")

        return "\n".join(lines)

    def _priority_fix_list(self) -> str:
        exploited = [f for f in self.assessment.findings if f.status == "exploited"]
        if not exploited:
            return ""

        sorted_findings = sorted(exploited, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 9))
        lines = ["## 优先修复顺序", ""]
        for i, f in enumerate(sorted_findings[:10], 1):
            sev = self.SEVERITY_LABELS.get(f.severity, f.severity)
            lines.append(f"{i}. **[{sev}]** {f.id}: {f.title}")
            if f.remediation:
                lines.append(f"   - 修复建议: {f.remediation}")
        return "\n".join(lines)


    def _exploited_section(self) -> str:
        exploited = [f for f in self.assessment.findings if f.status == "exploited"]
        if not exploited:
            return ""

        lines = ["## 已验证可利用的漏洞", ""]
        sorted_findings = sorted(exploited, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 9))

        for f in sorted_findings:
            sev = self.SEVERITY_LABELS.get(f.severity, f.severity)
            lines.append(f"### {f.id}: {f.title}")
            lines.append("")
            lines.append(f"| 项目 | 详情 |")
            lines.append(f"|------|------|")
            lines.append(f"| **严重程度** | {sev} |")
            lines.append(f"| **漏洞类型** | {self.VULN_TYPE_LABELS.get(f.vuln_type, f.vuln_type)} |")
            lines.append(f"| **位置** | `{f.method} {f.url}` |")
            if f.parameter:
                lines.append(f"| **参数** | `{f.parameter}` |")
            lines.append(f"| **可信度** | {f.confidence} |")
            lines.append("")

            if f.description:
                lines.append(f"**描述:** {f.description}")
                lines.append("")

            if f.impact:
                lines.append(f"**影响:** {f.impact}")
                lines.append("")

            # 代码定位（白盒/灰盒时）
            if f.source_file:
                lines.append("**数据流追踪:**")
                lines.append(f"- Source: `{f.source_file}:{f.source_line}`")
                if f.sink_file:
                    lines.append(f"- Sink: `{f.sink_file}:{f.sink_line}`")
                if f.data_flow:
                    lines.append(f"- 路径: {f.data_flow}")
                lines.append("")

            # 利用步骤
            if f.exploitation_steps:
                lines.append("**利用步骤:**")
                for i, step in enumerate(f.exploitation_steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

            # Payload
            if f.payload:
                lines.append("**Payload:**")
                lines.append(f"```")
                lines.append(f"{f.payload}")
                lines.append(f"```")
                lines.append("")

            # 证据
            if f.evidence:
                lines.append("**证据:**")
                lines.append(f"```")
                lines.append(f"{f.evidence}")
                lines.append(f"```")
                lines.append("")

            if f.remediation:
                lines.append(f"**修复建议:** {f.remediation}")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)


    def _blocked_section(self) -> str:
        blocked = [f for f in self.assessment.findings if f.status == "blocked"]
        if not blocked:
            return ""

        lines = ["## 环境阻断暂未打通（代码存在风险）", ""]
        for f in blocked:
            sev = self.SEVERITY_LABELS.get(f.severity, f.severity)
            lines.append(f"### {f.id}: {f.title}")
            lines.append("")
            lines.append(f"- **严重程度:** {sev}")
            lines.append(f"- **位置:** `{f.method} {f.url}`")
            if f.parameter:
                lines.append(f"- **参数:** `{f.parameter}`")
            lines.append(f"- **阻断原因:** {f.blocker}")
            lines.append("")

            if f.description:
                lines.append(f"**风险描述:** {f.description}")
                lines.append("")

            if f.data_flow:
                lines.append(f"**数据流:** {f.data_flow}")
                lines.append("")

            if f.bypass_attempted:
                lines.append("**已尝试的绕过:**")
                for attempt in f.bypass_attempted:
                    lines.append(f"- {attempt}")
                lines.append("")

            if f.remediation:
                lines.append(f"**建议:** {f.remediation}")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _false_positive_section(self) -> str:
        fps = [f for f in self.assessment.findings if f.status == "false_positive"]
        if not fps:
            return ""

        lines = ["## 误报/当前不可利用", ""]
        lines.append("以下为经测试确认当前部署不可利用的项目：")
        lines.append("")
        lines.append("| ID | 类型 | 位置 | 原因 |")
        lines.append("|-----|------|------|------|")
        for f in fps:
            vtype = self.VULN_TYPE_LABELS.get(f.vuln_type, f.vuln_type)
            reason = f.blocker or f.description or "防御措施有效"
            lines.append(f"| {f.id} | {vtype} | `{f.url}` | {reason} |")

        return "\n".join(lines)


    def _recon_summary(self) -> str:
        r = self.assessment.recon
        if not r:
            return ""

        lines = ["## 侦察汇总", ""]
        lines.append(f"| 项目 | 数量/详情 |")
        lines.append(f"|------|---------|")
        lines.append(f"| 子域名 | {r.subdomains_found} |")
        lines.append(f"| 存活主机 | {r.alive_hosts} |")
        lines.append(f"| 端点/URL | {r.endpoints_found} |")
        lines.append(f"| 参数 | {r.params_found} |")
        if r.tech_stack:
            lines.append(f"| 技术栈 | {', '.join(r.tech_stack)} |")
        if r.waf_detected:
            lines.append(f"| WAF | {r.waf_detected} |")
        if r.open_ports:
            lines.append(f"| 开放端口 | {', '.join(r.open_ports[:10])} |")

        return "\n".join(lines)

    def _coverage_stats(self) -> str:
        a = self.assessment
        total = len(a.findings)
        if total == 0:
            return ""

        exploited = len([f for f in a.findings if f.status == "exploited"])
        blocked = len([f for f in a.findings if f.status == "blocked"])
        fp = len([f for f in a.findings if f.status == "false_positive"])

        # 按类型统计覆盖
        tested_types = set(f.vuln_type for f in a.findings)

        lines = ["## 测试覆盖度", ""]
        lines.append(f"- 总发现数: {total}")
        lines.append(f"- 已验证: {exploited} ({exploited*100//max(total,1)}%)")
        lines.append(f"- 环境阻断: {blocked} ({blocked*100//max(total,1)}%)")
        lines.append(f"- 误报: {fp} ({fp*100//max(total,1)}%)")
        lines.append(f"- 覆盖漏洞类型: {', '.join(sorted(tested_types))}")
        lines.append(f"- 总请求数: {a.total_requests}")
        lines.append(f"- 测试耗时: {a.duration_seconds}s")

        return "\n".join(lines)

    def _footer(self) -> str:
        return f"""---

*报告由 Bai Auto-Hunt Agent 自动生成 (Shannon 报告引擎)*  
*生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"""

    def _wrap_html(self, md_content: str) -> str:
        """将 Markdown 包装为简单 HTML"""
        # 基础转换（无需外部依赖）
        import re
        html = md_content
        # 表格和代码块保留原样
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
        html = re.sub(r'`(.+?)`', r'<code>\1</code>', html)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>安全评估报告 - {self.assessment.target}</title>
<style>
body {{ font-family: -apple-system, "Microsoft YaHei", sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; line-height: 1.6; }}
h1 {{ color: #c0392b; border-bottom: 2px solid #c0392b; }}
h2 {{ color: #2c3e50; margin-top: 2em; }}
h3 {{ color: #34495e; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
pre {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
hr {{ border: none; border-top: 1px solid #eee; margin: 2em 0; }}
</style>
</head>
<body>
<pre>{html}</pre>
</body>
</html>"""



# ═══════════════════════════════════════════════════════════════
# 适配器：将 auto_hunt findings 转换为 Shannon 报告格式
# ═══════════════════════════════════════════════════════════════

def convert_findings_to_assessment(
    target: str,
    findings: dict,
    mode: str = "blackbox",
    duration: int = 0,
    total_requests: int = 0,
) -> SecurityAssessment:
    """
    将 auto_hunt.py 的 findings dict 转换为 SecurityAssessment
    
    兼容现有的 findings 格式：
    {
        "subdomains": [...],
        "alive_hosts": [...],
        "urls": [...],
        "params": [...],
        "vulnerabilities": [...],
        "secrets": [...],
    }
    """
    assessment = SecurityAssessment(
        target=target,
        assessment_date=datetime.now().strftime('%Y-%m-%d'),
        mode=mode,
        total_requests=total_requests,
        duration_seconds=duration,
    )

    # 侦察汇总
    assessment.recon = ReconSummary(
        target=target,
        subdomains_found=len(findings.get("subdomains", [])),
        alive_hosts=len(findings.get("alive_hosts", [])),
        endpoints_found=len(findings.get("urls", [])),
        params_found=len(findings.get("params", [])),
    )

    # 转换漏洞发现
    vulns = findings.get("vulnerabilities", [])
    for i, v in enumerate(vulns):
        if isinstance(v, dict):
            finding = VulnFinding(
                id=v.get("id", f"VULN-{i+1:03d}"),
                vuln_type=_map_vuln_type(v.get("type", v.get("vuln_type", "other"))),
                title=v.get("title", v.get("description", "Unknown")),
                severity=v.get("severity", "medium"),
                confidence=v.get("confidence", "medium"),
                status=_map_status(v),
                url=v.get("url", ""),
                parameter=v.get("parameter", v.get("param", "")),
                method=v.get("method", "GET"),
                description=v.get("description", ""),
                impact=v.get("impact", ""),
                evidence=v.get("evidence", ""),
                payload=v.get("payload", ""),
                exploitation_steps=v.get("steps", []),
                source_file=v.get("source_file", ""),
                source_line=v.get("source_line", 0),
                sink_file=v.get("sink_file", ""),
                data_flow=v.get("data_flow", ""),
                remediation=v.get("remediation", v.get("fix", "")),
                blocker=v.get("blocker", ""),
            )
            assessment.findings.append(finding)
        elif isinstance(v, str):
            # 简单字符串格式的漏洞
            assessment.findings.append(VulnFinding(
                id=f"VULN-{i+1:03d}",
                title=v,
                status="exploited",
            ))

    # 密钥泄露作为信息泄露类
    secrets = findings.get("secrets", [])
    for i, s in enumerate(secrets):
        secret_str = s if isinstance(s, str) else str(s)
        assessment.findings.append(VulnFinding(
            id=f"LEAK-{i+1:03d}",
            vuln_type="info_leak",
            title=f"密钥/凭据泄露: {secret_str[:50]}",
            severity="high",
            status="exploited",
            evidence=secret_str,
        ))

    # 设置测试类型
    tested_types = list(set(f.vuln_type for f in assessment.findings))
    assessment.vuln_classes_tested = tested_types

    return assessment


def _map_vuln_type(raw_type: str) -> str:
    """将各种漏洞类型名称映射为标准化类型"""
    mapping = {
        "sqli": "injection", "sql_injection": "injection",
        "cmdi": "injection", "command_injection": "injection",
        "ssti": "injection", "lfi": "injection", "rfi": "injection",
        "xss": "xss", "reflected_xss": "xss", "stored_xss": "xss",
        "auth": "auth", "authentication": "auth", "auth_bypass": "auth",
        "authz": "authz", "authorization": "authz",
        "idor": "idor", "horizontal_idor": "idor", "vertical_idor": "idor",
        "ssrf": "ssrf",
        "race": "race", "race_condition": "race",
        "bizlogic": "bizlogic", "business_logic": "bizlogic",
        "cors": "cors",
        "info_leak": "info_leak", "information_disclosure": "info_leak",
        "upload": "upload", "file_upload": "upload",
    }
    return mapping.get(raw_type.lower(), raw_type.lower())


def _map_status(v: dict) -> str:
    """根据漏洞数据判断状态"""
    if v.get("false_positive") or v.get("is_fp"):
        return "false_positive"
    if v.get("blocked") or v.get("blocker"):
        return "blocked"
    if v.get("verified") or v.get("confirmed") or v.get("verified_4proof"):
        return "exploited"
    # 有 evidence 的默认为已验证
    if v.get("evidence") or v.get("payload"):
        return "exploited"
    return "exploited"


def generate_shannon_report(
    target: str,
    findings: dict,
    output_dir: str = "",
    mode: str = "blackbox",
    duration: int = 0,
) -> Dict[str, str]:
    """
    一键生成 Shannon 风格报告
    
    Args:
        target: 目标域名
        findings: auto_hunt 的 findings dict
        output_dir: 报告输出目录
        mode: 测试模式
        duration: 耗时(秒)
    
    Returns:
        {"md": md路径, "html": html路径, "content": md内容}
    """
    assessment = convert_findings_to_assessment(target, findings, mode, duration)
    generator = ShannonReportGenerator(assessment)

    md_content = generator.generate_markdown()
    html_content = generator.generate_html()

    result = {"content": md_content}

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace(".", "_").replace("/", "_")

        md_path = os.path.join(output_dir, f"report_{safe_target}_{date_str}.md")
        html_path = os.path.join(output_dir, f"report_{safe_target}_{date_str}.html")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        result["md"] = md_path
        result["html"] = html_path

    return result
