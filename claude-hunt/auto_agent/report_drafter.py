#!/usr/bin/env python3
"""
Report Drafter — 漏洞报告草稿自动生成

解决问题：
- 好报告需要：请求、响应、影响、复现步骤、项目规则对应
- 手动整理证据链费时费力
- 不同平台格式不同（HackerOne/Bugcrowd/补天/EDUSRC）

功能：
1. 自动收集测试过程中的请求/响应证据
2. 生成结构化 Markdown 报告草稿
3. 支持多平台格式（HackerOne/Bugcrowd/补天/EDUSRC/CNVD）
4. CVSS 3.1 评分辅助
5. 证据链时间线生成
6. 中英文双语输出

用法：
    from report_drafter import ReportDrafter

    rd = ReportDrafter(program="syfe", platform="hackerone")

    # 记录证据
    rd.add_evidence(method="GET", url="...", status=200, response="...", note="未授权访问")

    # 生成报告
    report = rd.generate(
        title="IDOR on /api/invoices/{id}",
        vuln_type="idor",
        severity="high",
    )

CLI:
    python report_drafter.py --generate findings.json --platform hackerone
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class Evidence:
    """单条证据"""
    step: int = 0
    timestamp: str = ""
    method: str = ""
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    status_code: int = 0
    response_excerpt: str = ""
    note: str = ""                # 这一步说明了什么
    screenshot: str = ""          # 截图路径（可选）


@dataclass
class ReportDraft:
    """报告草稿"""
    title: str = ""
    program: str = ""
    platform: str = ""
    vuln_type: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    # 内容
    summary: str = ""
    impact: str = ""
    steps: List[Evidence] = field(default_factory=list)
    remediation: str = ""
    # 元数据
    target_url: str = ""
    created_at: str = ""
    researcher: str = ""


# ═══════════════════════════════════════════════════════════════
# CVSS 辅助
# ═══════════════════════════════════════════════════════════════

CVSS_PRESETS = {
    "idor_read": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "idor_write": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "sqli": {"score": 8.6, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"},
    "rce": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "ssrf_internal": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "ssrf_cloud": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"},
    "xss_stored": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "xss_reflected": {"score": 5.4, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "auth_bypass": {"score": 8.2, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"},
    "file_upload_rce": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "info_leak": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "unauth_access": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
}

# 影响描述模板
IMPACT_TEMPLATES = {
    "idor": "攻击者可以通过篡改对象ID，未授权访问/修改其他用户的{resource}数据，导致隐私泄露或数据篡改。",
    "sqli": "攻击者可以通过SQL注入获取数据库中的敏感信息，包括用户凭据、个人数据等，严重时可实现远程代码执行。",
    "rce": "攻击者可以在服务器上执行任意命令，完全控制目标系统，窃取数据、植入后门或横向渗透内网。",
    "ssrf": "攻击者可以利用服务端请求伪造访问内网服务，读取云元数据（如AWS凭证），进而扩大攻击面。",
    "xss": "攻击者可以在受害者浏览器中执行恶意JavaScript，窃取会话Cookie、执行敏感操作或钓鱼。",
    "auth_bypass": "攻击者可以绕过认证机制，未授权访问受保护的功能或数据。",
    "file_upload": "攻击者可以上传恶意文件（如WebShell），在服务器上实现远程代码执行。",
    "info_leak": "敏感信息泄露可能被攻击者利用进行进一步攻击，如凭据泄露可导致账户接管。",
    "unauth": "未授权访问暴露了敏感数据或管理功能，任何人无需认证即可获取。",
}

# 修复建议模板
REMEDIATION_TEMPLATES = {
    "idor": "1. 在服务端验证当前用户是否有权访问请求的资源\n2. 使用不可预测的对象ID（如UUID）\n3. 实施基于角色的访问控制(RBAC)",
    "sqli": "1. 使用参数化查询/预编译语句\n2. 实施输入验证和过滤\n3. 最小化数据库用户权限\n4. 部署WAF规则",
    "rce": "1. 避免拼接用户输入到系统命令中\n2. 使用安全的API替代系统调用\n3. 实施严格的输入白名单验证\n4. 使用沙箱隔离",
    "ssrf": "1. 实施URL白名单验证\n2. 禁止请求内网IP段(10.x/172.16-31.x/192.168.x/169.254.x)\n3. 禁用不必要的URL协议\n4. 使用DNS解析后的IP做二次验证",
    "xss": "1. 对所有输出进行上下文相关的编码\n2. 使用Content-Security-Policy(CSP)头\n3. 设置HttpOnly和Secure Cookie标志\n4. 实施输入验证",
    "auth_bypass": "1. 在服务端对所有受保护端点实施认证检查\n2. 使用统一的认证中间件\n3. 定期审计认证逻辑\n4. 实施多因素认证",
    "file_upload": "1. 验证文件类型（魔术字节+扩展名+MIME类型）\n2. 重命名上传文件\n3. 存储在非Web可访问目录\n4. 限制文件大小\n5. 使用CDN/对象存储",
    "info_leak": "1. 移除或限制信息暴露的接口\n2. 实施访问控制\n3. 在生产环境关闭调试信息\n4. 审计API响应中的敏感字段",
    "unauth": "1. 对所有敏感接口实施认证要求\n2. 关闭匿名/游客访问\n3. 在反向代理层添加认证\n4. 审计所有公开端点",
}


# ═══════════════════════════════════════════════════════════════
# Report Drafter
# ═══════════════════════════════════════════════════════════════

class ReportDrafter:
    """报告草稿生成器"""

    def __init__(self, program: str = "", platform: str = "hackerone",
                 researcher: str = "", config: dict = None):
        self.program = program
        self.platform = platform
        self.researcher = researcher
        self.config = config or {}
        self.evidences: List[Evidence] = []
        self.reports_dir = os.path.expanduser("~/.bai-agent/reports")
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

    def add_evidence(self, method: str = "", url: str = "", status: int = 0,
                     response: str = "", headers: dict = None, body: str = "",
                     note: str = "", screenshot: str = "") -> Evidence:
        """添加一条证据"""
        ev = Evidence(
            step=len(self.evidences) + 1,
            timestamp=datetime.now().isoformat(),
            method=method,
            url=url,
            headers=headers or {},
            body=body,
            status_code=status,
            response_excerpt=response[:1000] if response else "",
            note=note,
            screenshot=screenshot,
        )
        self.evidences.append(ev)
        print(f"  [+] 证据 #{ev.step}: {method} {url[:60]} → {status} | {note}")
        return ev

    def generate(self, title: str, vuln_type: str = "", severity: str = "medium",
                 impact: str = "", target_url: str = "",
                 custom_steps: str = "") -> str:
        """生成报告草稿"""
        # 自动补全信息
        vuln_key = vuln_type.lower().replace(" ", "_").replace("-", "_")
        cvss_info = CVSS_PRESETS.get(vuln_key, {})
        impact_text = impact or IMPACT_TEMPLATES.get(vuln_key, "")
        remediation = REMEDIATION_TEMPLATES.get(vuln_key, "")

        if self.platform == "hackerone":
            report = self._gen_hackerone(title, vuln_type, severity, cvss_info,
                                         impact_text, remediation, target_url)
        elif self.platform == "bugcrowd":
            report = self._gen_bugcrowd(title, vuln_type, severity, cvss_info,
                                         impact_text, remediation, target_url)
        elif self.platform in ("butian", "补天"):
            report = self._gen_butian(title, vuln_type, severity, impact_text,
                                      remediation, target_url)
        elif self.platform == "edusrc":
            report = self._gen_edusrc(title, vuln_type, severity, impact_text,
                                      remediation, target_url)
        else:
            report = self._gen_generic(title, vuln_type, severity, cvss_info,
                                        impact_text, remediation, target_url)

        # 保存
        safe_title = re.sub(r'[^\w\-]', '_', title)[:50]
        filename = f"{self.program}_{safe_title}_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
        path = os.path.join(self.reports_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"\n[+] 报告草稿已生成: {path}")
        return report

    # ═══════════════════════════════════════════════════════════
    # 平台格式生成器
    # ═══════════════════════════════════════════════════════════

    def _gen_hackerone(self, title, vuln_type, severity, cvss, impact, remediation, target_url):
        """HackerOne 格式"""
        lines = [
            f"## Summary",
            f"",
            f"[简要描述漏洞，一两句话]",
            f"",
            f"## Vulnerability Type",
            f"",
            f"{vuln_type}",
            f"",
            f"## Steps To Reproduce",
            f"",
        ]

        if self.evidences:
            for ev in self.evidences:
                lines.append(f"### Step {ev.step}: {ev.note}")
                lines.append(f"")
                lines.append(f"```http")
                lines.append(f"{ev.method} {ev.url}")
                for k, v in ev.headers.items():
                    if k.lower() not in ("cookie", "authorization"):
                        lines.append(f"{k}: {v}")
                    else:
                        lines.append(f"{k}: [REDACTED]")
                if ev.body:
                    lines.append(f"")
                    lines.append(f"{ev.body[:500]}")
                lines.append(f"```")
                lines.append(f"")
                if ev.status_code:
                    lines.append(f"**Response:** HTTP {ev.status_code}")
                if ev.response_excerpt:
                    lines.append(f"```json")
                    lines.append(f"{ev.response_excerpt[:500]}")
                    lines.append(f"```")
                lines.append(f"")
        else:
            lines.extend([
                "1. Navigate to `[URL]`",
                "2. [Describe action]",
                "3. Observe that [vulnerability behavior]",
                "",
            ])

        lines.extend([
            f"## Impact",
            f"",
            f"{impact}",
            f"",
            f"## Severity",
            f"",
            f"**{severity.capitalize()}**",
        ])

        if cvss:
            lines.extend([
                f"",
                f"CVSS: {cvss.get('score', '')} ({cvss.get('vector', '')})",
            ])

        lines.extend([
            f"",
            f"## Remediation",
            f"",
            f"{remediation}",
            f"",
            f"---",
            f"*Generated by Bai Auto-Hunt Agent | {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
        ])

        return "\n".join(lines)

    def _gen_edusrc(self, title, vuln_type, severity, impact, remediation, target_url):
        """EDUSRC 格式"""
        lines = [
            f"【标题】",
            f"{title}",
            f"",
            f"【分类】",
            f"{vuln_type}",
            f"",
            f"【等级】",
            f"{severity}",
            f"",
            f"【漏洞单位】",
            f"[填写单位名称]",
            f"",
            f"【资产所在网段】",
            f"互联网",
            f"",
            f"【是否需要账号认证】",
            f"否",
            f"",
            f"【漏洞URL】",
            f"{target_url or (self.evidences[0].url if self.evidences else '[填写]')}",
            f"",
            f"【漏洞详情】",
            f"",
            f"测试环境：Chrome 无痕模式，未登录任何账号。",
            f"",
        ]

        if self.evidences:
            for ev in self.evidences:
                lines.append(f"步骤 {ev.step}：{ev.note}")
                lines.append(f"")
                lines.append(f"{ev.method} {ev.url}")
                lines.append(f"")
                if ev.response_excerpt:
                    lines.append(f"返回：")
                    lines.append(f"{ev.response_excerpt[:300]}")
                    lines.append(f"")

        lines.extend([
            f"漏洞危害：",
            f"",
            f"{impact}",
            f"",
            f"修复建议：",
            f"",
            f"{remediation}",
        ])

        return "\n".join(lines)

    def _gen_butian(self, title, vuln_type, severity, impact, remediation, target_url):
        """补天格式"""
        lines = [
            f"# {title}",
            f"",
            f"## 漏洞信息",
            f"",
            f"- 漏洞类型: {vuln_type}",
            f"- 危害等级: {severity}",
            f"- 漏洞地址: {target_url}",
            f"",
            f"## 漏洞描述",
            f"",
            f"[填写漏洞描述]",
            f"",
            f"## 复现步骤",
            f"",
        ]

        if self.evidences:
            for ev in self.evidences:
                lines.append(f"### {ev.step}. {ev.note}")
                lines.append(f"")
                lines.append(f"```")
                lines.append(f"{ev.method} {ev.url}")
                lines.append(f"```")
                if ev.response_excerpt:
                    lines.append(f"")
                    lines.append(f"响应 (HTTP {ev.status_code}):")
                    lines.append(f"```")
                    lines.append(f"{ev.response_excerpt[:300]}")
                    lines.append(f"```")
                lines.append(f"")

        lines.extend([
            f"## 危害分析",
            f"",
            f"{impact}",
            f"",
            f"## 修复建议",
            f"",
            f"{remediation}",
        ])

        return "\n".join(lines)

    def _gen_bugcrowd(self, title, vuln_type, severity, cvss, impact, remediation, target_url):
        """Bugcrowd 格式（类似 HackerOne）"""
        return self._gen_hackerone(title, vuln_type, severity, cvss, impact, remediation, target_url)

    def _gen_generic(self, title, vuln_type, severity, cvss, impact, remediation, target_url):
        """通用 Markdown 格式"""
        lines = [
            f"# 漏洞报告: {title}",
            f"",
            f"| 项目 | 内容 |",
            f"|------|------|",
            f"| 漏洞类型 | {vuln_type} |",
            f"| 严重程度 | {severity} |",
            f"| 目标 | {target_url} |",
            f"| 发现时间 | {datetime.now().strftime('%Y-%m-%d')} |",
        ]

        if cvss:
            lines.append(f"| CVSS | {cvss.get('score', '')} |")

        lines.extend([
            f"",
            f"## 漏洞描述",
            f"",
            f"[填写]",
            f"",
            f"## 复现步骤",
            f"",
        ])

        if self.evidences:
            for ev in self.evidences:
                lines.append(f"### 步骤 {ev.step}: {ev.note}")
                lines.append(f"")
                lines.append(f"```")
                lines.append(f"{ev.method} {ev.url}")
                lines.append(f"```")
                if ev.status_code:
                    lines.append(f"HTTP {ev.status_code}")
                if ev.response_excerpt:
                    lines.append(f"```")
                    lines.append(f"{ev.response_excerpt[:300]}")
                    lines.append(f"```")
                lines.append(f"")

        lines.extend([
            f"## 影响",
            f"",
            f"{impact}",
            f"",
            f"## 修复建议",
            f"",
            f"{remediation}",
        ])

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="漏洞报告草稿生成器")
    parser.add_argument("--platform", "-p", default="hackerone",
                        choices=["hackerone", "bugcrowd", "butian", "edusrc", "generic"])
    parser.add_argument("--program", default="")
    parser.add_argument("--title", "-t", help="报告标题")
    parser.add_argument("--type", dest="vuln_type", help="漏洞类型")
    parser.add_argument("--severity", "-s", default="medium")
    parser.add_argument("--demo", action="store_true", help="生成示例报告")
    args = parser.parse_args()

    rd = ReportDrafter(program=args.program, platform=args.platform)

    if args.demo:
        rd.add_evidence("GET", "https://api.example.com/api/users/123", 200,
                        '{"id":123,"email":"victim@example.com","ssn":"xxx"}',
                        note="用攻击者Token访问受害者ID")
        rd.add_evidence("GET", "https://api.example.com/api/users/456", 200,
                        '{"id":456,"email":"other@example.com"}',
                        note="确认可枚举任意用户")
        report = rd.generate("IDOR - 未授权读取任意用户信息", "idor_read", "high")
        print("\n" + report)
    elif args.title:
        report = rd.generate(args.title, args.vuln_type or "", args.severity)
        print("\n" + report)
    else:
        parser.print_help()
