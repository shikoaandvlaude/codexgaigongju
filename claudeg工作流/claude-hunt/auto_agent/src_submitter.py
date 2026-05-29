#!/usr/bin/env python3
"""
SRC Submitter — 中国 SRC 平台报告格式化 + 辅助提交
专为补天/漏洞盒子/企业SRC设计的报告生成器

功能：
1. 标准化报告格式（补天/漏洞盒子/HackerOne 三种模板）
2. 自动填充漏洞分类、严重等级、影响范围
3. 复现步骤格式化（带数据包/截图占位）
4. 修复建议自动生成
5. 提交前查重（检查是否已有同类报告）
6. 批量报告生成（一次挖掘多个洞）

用法：
    from src_submitter import SRCSubmitter

    submitter = SRCSubmitter(platform="butian")
    report = submitter.generate_report(finding)
    print(report)  # 直接复制粘贴到 SRC 平台
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime



# ═══════════════════════════════════════════════════════════════
# SRC 平台配置
# ═══════════════════════════════════════════════════════════════

SRC_PLATFORMS = {
    "butian": {
        "name": "补天",
        "url": "https://www.butian.net",
        "severity_levels": ["严重", "高危", "中危", "低危"],
        "vuln_categories": [
            "SQL注入", "XSS跨站", "命令执行", "文件上传", "文件包含",
            "越权访问", "信息泄露", "逻辑漏洞", "SSRF", "CSRF",
            "弱口令", "未授权访问", "任意文件读取", "代码执行",
            "反序列化", "XXE", "目录遍历", "配置错误", "其他",
        ],
    },
    "vulbox": {
        "name": "漏洞盒子",
        "url": "https://www.vulbox.com",
        "severity_levels": ["严重", "高危", "中危", "低危", "信息"],
        "vuln_categories": [
            "远程代码执行", "SQL注入", "越权", "SSRF", "XSS",
            "任意文件操作", "逻辑漏洞", "信息泄露", "弱口令",
            "未授权访问", "CSRF", "命令注入", "其他",
        ],
    },
    "hackerone": {
        "name": "HackerOne",
        "url": "https://hackerone.com",
        "severity_levels": ["Critical", "High", "Medium", "Low", "None"],
        "vuln_categories": [
            "SQL Injection", "XSS", "SSRF", "IDOR", "RCE",
            "Authentication Bypass", "Business Logic",
            "Information Disclosure", "CSRF", "Open Redirect",
        ],
    },
    "enterprise": {
        "name": "企业SRC通用",
        "url": "",
        "severity_levels": ["严重", "高危", "中危", "低危"],
        "vuln_categories": [
            "远程代码执行", "SQL注入", "越权访问", "敏感信息泄露",
            "业务逻辑", "支付漏洞", "验证码绕过", "未授权访问",
        ],
    },
}

# 漏洞类型 → SRC 分类映射
VULN_TYPE_TO_SRC_CATEGORY = {
    "injection": "SQL注入",
    "sqli": "SQL注入",
    "xss": "XSS跨站",
    "ssrf": "SSRF",
    "idor": "越权访问",
    "authz": "越权访问",
    "auth": "逻辑漏洞",
    "rce": "命令执行",
    "cmdi": "命令执行",
    "ssti": "代码执行",
    "upload": "文件上传",
    "lfi": "任意文件读取",
    "info_leak": "信息泄露",
    "race": "逻辑漏洞",
    "bizlogic": "逻辑漏洞",
    "cors": "配置错误",
    "csrf": "CSRF",
    "xxe": "XXE",
    "deserialization": "反序列化",
    "weak_password": "弱口令",
    "unauth": "未授权访问",
}

# 严重程度映射
SEVERITY_MAP = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}



# ═══════════════════════════════════════════════════════════════
# 修复建议知识库
# ═══════════════════════════════════════════════════════════════

FIX_SUGGESTIONS = {
    "injection": "1. 使用参数化查询/预编译语句\n2. 对用户输入进行严格类型校验\n3. 最小权限原则配置数据库账户\n4. 部署WAF进行SQL注入检测",
    "xss": "1. 对所有用户输入进行HTML实体编码输出\n2. 设置Content-Security-Policy响应头\n3. Cookie设置HttpOnly和Secure标记\n4. 使用成熟的模板引擎自动转义",
    "ssrf": "1. 对URL参数进行白名单校验（协议+主机）\n2. 禁止请求内网IP段（10.x/172.16-31.x/192.168.x）\n3. 禁止重定向跟随或限制重定向次数\n4. 使用独立网络区域的代理服务器发起外部请求",
    "idor": "1. 后端对每个资源访问进行所有权验证\n2. 使用不可预测的资源标识符（UUID）\n3. 实现基于角色的访问控制(RBAC)\n4. 记录越权访问日志并告警",
    "rce": "1. 避免直接调用系统命令，使用安全的API替代\n2. 如必须调用，使用白名单限制可执行命令\n3. 使用安全的命令参数传递方式（数组而非字符串拼接）\n4. 运行环境做沙箱隔离",
    "upload": "1. 服务端校验文件类型（Magic Number，非仅扩展名）\n2. 限制上传文件大小\n3. 存储目录禁止执行权限\n4. 文件重命名为随机名称",
    "info_leak": "1. 关闭调试模式和详细错误信息\n2. 删除或限制访问管理接口/监控端点\n3. 敏感配置文件加入.gitignore\n4. API响应中移除不必要的内部字段",
    "race": "1. 使用数据库事务+行锁保证原子性\n2. 使用分布式锁(Redis/ZooKeeper)\n3. 幂等性设计（同一请求多次执行效果相同）\n4. 关键操作增加唯一性约束",
    "bizlogic": "1. 服务端重新计算金额/数量，不信任前端参数\n2. 关键操作增加二次验证\n3. 优惠券/积分使用增加唯一性校验\n4. 流程步骤做服务端状态机校验",
    "auth": "1. 密码使用bcrypt/argon2哈希存储\n2. 实现账户锁定和登录频率限制\n3. Session/Token设置合理过期时间\n4. 实现MFA多因素认证",
    "unauth": "1. 所有管理接口添加认证中间件\n2. 默认关闭不必要的服务端口和页面\n3. 修改所有默认口令\n4. 定期扫描未授权暴露的接口",
}


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class SRCReport:
    """生成的 SRC 报告"""
    platform: str = ""
    title: str = ""
    content: str = ""
    # 元数据
    severity: str = ""
    category: str = ""
    target: str = ""
    # 文件
    markdown_path: str = ""
    # 提交状态
    submitted: bool = False
    duplicate: bool = False


# ═══════════════════════════════════════════════════════════════
# 报告模板
# ═══════════════════════════════════════════════════════════════

BUTIAN_TEMPLATE = """# {title}

## 漏洞信息

| 项目 | 内容 |
|------|------|
| **漏洞类型** | {category} |
| **严重程度** | {severity} |
| **目标地址** | {target_url} |
| **影响范围** | {scope} |

## 漏洞概述

{description}

## 复现步骤

{reproduction_steps}

## 数据包/请求

```http
{http_request}
```

## 响应/证据

```
{evidence}
```

## 影响说明

{impact}

## 修复建议

{fix_suggestion}
"""

VULBOX_TEMPLATE = """## 漏洞标题
{title}

## 漏洞类型
{category}

## 漏洞等级
{severity}

## 漏洞URL
{target_url}

## 漏洞描述
{description}

## 复现过程

{reproduction_steps}

### 请求包
```
{http_request}
```

### 返回结果
```
{evidence}
```

## 漏洞危害
{impact}

## 修复方案
{fix_suggestion}
"""

HACKERONE_TEMPLATE = """## Summary
{description}

## Severity
{severity}

## Steps To Reproduce

{reproduction_steps_en}

## Supporting Material/References

### Request
```http
{http_request}
```

### Response
```
{evidence}
```

## Impact
{impact_en}

## Remediation
{fix_suggestion_en}
"""



# ═══════════════════════════════════════════════════════════════
# SRC Submitter 主类
# ═══════════════════════════════════════════════════════════════

class SRCSubmitter:
    """
    SRC 报告生成器

    将 auto_hunt 的 findings 转换为可直接提交的 SRC 报告格式。

    用法：
        submitter = SRCSubmitter(platform="butian")

        # 单个漏洞
        report = submitter.generate_report(finding)
        print(report.content)  # 复制粘贴到 SRC

        # 批量生成
        reports = submitter.batch_generate(findings)
        submitter.save_reports(reports, output_dir="./reports")
    """

    def __init__(self, platform: str = "butian", company: str = "", output_dir: str = ""):
        self.platform = platform
        self.company = company
        self.output_dir = output_dir or os.path.expanduser("~/.bai-agent/src_reports")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_report(self, finding: Dict) -> SRCReport:
        """
        从单个 finding 生成 SRC 报告

        Args:
            finding: auto_hunt 格式的漏洞字典
        """
        report = SRCReport(platform=self.platform)

        # 基本信息
        vuln_type = finding.get("type", finding.get("vuln_type", "other"))
        severity = finding.get("severity", "medium")
        url = finding.get("url", "")
        title = finding.get("title", "")
        description = finding.get("description", "")
        evidence = finding.get("evidence", "")
        payload = finding.get("payload", "")
        parameter = finding.get("parameter", finding.get("param", ""))

        # 映射分类
        report.category = VULN_TYPE_TO_SRC_CATEGORY.get(vuln_type, "其他")
        report.severity = SEVERITY_MAP.get(severity, severity)
        report.target = url

        # 生成标题
        if not title:
            title = f"{report.category} — {self._extract_domain(url)}"
        report.title = title

        # 构建各字段
        fields = {
            "title": report.title,
            "category": report.category,
            "severity": report.severity,
            "target_url": url,
            "scope": self._guess_scope(url),
            "description": description or self._auto_description(vuln_type, url, parameter),
            "reproduction_steps": self._format_steps(finding),
            "reproduction_steps_en": self._format_steps_en(finding),
            "http_request": self._format_request(finding),
            "evidence": evidence[:2000] if evidence else "[请粘贴响应截图或文本]",
            "impact": self._impact_text(vuln_type, report.severity),
            "impact_en": self._impact_text_en(vuln_type, severity),
            "fix_suggestion": FIX_SUGGESTIONS.get(vuln_type, FIX_SUGGESTIONS.get("bizlogic", "请参考OWASP安全指南进行修复。")),
            "fix_suggestion_en": self._fix_en(vuln_type),
        }

        # 选择模板
        if self.platform == "vulbox":
            report.content = VULBOX_TEMPLATE.format(**fields)
        elif self.platform == "hackerone":
            report.content = HACKERONE_TEMPLATE.format(**fields)
        else:
            report.content = BUTIAN_TEMPLATE.format(**fields)

        return report

    def batch_generate(self, findings: List[Dict]) -> List[SRCReport]:
        """批量生成报告"""
        reports = []
        for finding in findings:
            if not self._is_submission_ready(finding):
                continue
            report = self.generate_report(finding)
            reports.append(report)
        return reports

    def _is_submission_ready(self, finding: Dict) -> bool:
        """只让真正可交付的发现进入提交草稿。"""
        if finding.get("duplicate"):
            return False

        verified = (
            finding.get("verified")
            or finding.get("verified_4proof")
            or finding.get("status") == "exploited"
        )
        if not verified:
            return False

        confidence = finding.get("confidence")
        if confidence is not None:
            try:
                if float(confidence) < 80:
                    return False
            except (TypeError, ValueError):
                return False

        vuln_type = str(finding.get("type", finding.get("vuln_type", ""))).lower()
        if vuln_type in {"info", "informational", "generic"}:
            return False

        evidence = str(finding.get("evidence", "")).strip()
        if not evidence:
            return False

        return True
    def save_reports(self, reports: List[SRCReport], output_dir: str = "") -> List[str]:
        """保存报告到文件"""
        out_dir = output_dir or self.output_dir
        os.makedirs(out_dir, exist_ok=True)
        paths = []

        for i, report in enumerate(reports, 1):
            safe_title = re.sub(r'[^\w\-]', '_', report.title)[:50]
            filename = f"{i:02d}_{safe_title}_{self.platform}.md"
            filepath = os.path.join(out_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report.content)

            report.markdown_path = filepath
            paths.append(filepath)

        return paths

    def check_duplicate(self, finding: Dict, history: List[Dict] = None) -> bool:
        """
        检查是否可能重复（同 URL + 同类型 = 可能重复）
        """
        if not history:
            return False
        url = finding.get("url", "")
        vuln_type = finding.get("type", "")
        for h in history:
            if h.get("url") == url and h.get("type") == vuln_type:
                return True
        return False

    # ─── 辅助方法 ──────────────────────────────────────────

    def _extract_domain(self, url: str) -> str:
        from urllib.parse import urlparse
        try:
            return urlparse(url).hostname or url
        except Exception:
            return url

    def _guess_scope(self, url: str) -> str:
        domain = self._extract_domain(url)
        if self.company:
            return f"{self.company} — {domain}"
        return domain

    def _auto_description(self, vuln_type: str, url: str, param: str) -> str:
        """自动生成漏洞描述"""
        desc_map = {
            "injection": f"在 {url} 的 {param or '某参数'} 处发现SQL注入漏洞，攻击者可通过构造恶意SQL语句获取数据库敏感信息。",
            "xss": f"在 {url} 的 {param or '某参数'} 处发现跨站脚本漏洞，用户输入未经过滤直接输出到页面中，攻击者可窃取用户Cookie或执行恶意操作。",
            "ssrf": f"在 {url} 的 {param or 'URL参数'} 处发现服务端请求伪造漏洞，攻击者可利用服务器访问内网资源或云元数据。",
            "idor": f"在 {url} 处发现越权访问漏洞，通过修改资源ID可访问其他用户的数据。",
            "rce": f"在 {url} 处发现远程代码执行漏洞，攻击者可在服务器上执行任意系统命令。",
            "race": f"在 {url} 处发现竞态条件漏洞，通过并发请求可实现重复领取/提现等操作。",
            "bizlogic": f"在 {url} 处发现业务逻辑漏洞，可通过篡改请求参数绕过业务校验。",
            "info_leak": f"在 {url} 处发现敏感信息泄露，包含内部配置/凭据/用户数据等。",
            "unauth": f"在 {url} 处发现未授权访问，无需认证即可访问管理功能或敏感数据。",
        }
        return desc_map.get(vuln_type, f"在 {url} 处发现安全漏洞。")

    def _format_steps(self, finding: Dict) -> str:
        """格式化复现步骤（中文）"""
        steps = finding.get("exploitation_steps", finding.get("steps", []))
        url = finding.get("url", "")
        payload = finding.get("payload", "")
        param = finding.get("parameter", finding.get("param", ""))

        if steps:
            return "\n".join([f"{i}. {s}" for i, s in enumerate(steps, 1)])

        # 自动生成步骤
        auto_steps = [f"1. 访问目标页面: {url}"]
        if param:
            auto_steps.append(f"2. 定位参数: `{param}`")
        if payload:
            auto_steps.append(f"3. 将参数值修改为: `{payload}`")
            auto_steps.append("4. 发送请求，观察响应中的异常")
        else:
            auto_steps.append("2. 使用 Burp/Fiddler 抓取请求包")
            auto_steps.append("3. 修改关键参数后重放")
            auto_steps.append("4. 观察响应变化确认漏洞")
        auto_steps.append("5. 截图保存证据")
        return "\n".join(auto_steps)

    def _format_steps_en(self, finding: Dict) -> str:
        """格式化复现步骤（英文，HackerOne用）"""
        url = finding.get("url", "")
        payload = finding.get("payload", "")
        param = finding.get("parameter", "")
        steps = [
            f"1. Navigate to: {url}",
            f"2. Intercept the request using Burp Suite",
        ]
        if param and payload:
            steps.append(f"3. Modify parameter `{param}` to: `{payload}`")
            steps.append("4. Forward the request and observe the response")
        else:
            steps.append("3. Modify the vulnerable parameter as shown below")
            steps.append("4. Observe the server response confirming the vulnerability")
        return "\n".join(steps)

    def _format_request(self, finding: Dict) -> str:
        """格式化 HTTP 请求"""
        method = finding.get("method", "GET")
        url = finding.get("url", "")
        payload = finding.get("payload", "")
        param = finding.get("parameter", "")

        if method.upper() == "GET":
            req = f"GET {url}{'?' + param + '=' + payload if param and payload else ''} HTTP/1.1\n"
            req += f"Host: {self._extract_domain(url)}\n"
            req += "Cookie: [你的Session Cookie]\n"
            req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        else:
            req = f"POST {url} HTTP/1.1\n"
            req += f"Host: {self._extract_domain(url)}\n"
            req += "Content-Type: application/json\n"
            req += "Cookie: [你的Session Cookie]\n\n"
            if param and payload:
                req += json.dumps({param: payload}, ensure_ascii=False)
            else:
                req += "[请粘贴实际请求体]"
        return req

    def _impact_text(self, vuln_type: str, severity: str) -> str:
        """影响说明（中文）"""
        impacts = {
            "injection": "攻击者可通过该漏洞获取数据库中的敏感信息（用户账号密码、手机号、身份证号等），甚至可能获取服务器权限。",
            "xss": "攻击者可利用该漏洞窃取用户登录凭据（Cookie/Token），进行钓鱼攻击，或在用户浏览器中执行恶意操作。",
            "ssrf": "攻击者可利用该漏洞访问企业内网服务、获取云服务器元数据（AccessKey等），进一步渗透内网。",
            "idor": "攻击者可通过遍历ID访问任意用户的隐私数据（订单信息、个人资料、聊天记录等），影响全部用户。",
            "rce": "攻击者可在服务器上执行任意命令，完全控制服务器，窃取全部数据，甚至以此为跳板攻击内网其他系统。",
            "race": "攻击者可通过并发请求实现重复领取优惠券/积分/提现等操作，直接造成平台经济损失。",
            "bizlogic": "攻击者可利用业务逻辑缺陷进行薅羊毛、0元购、金额篡改等操作，造成平台直接经济损失。",
            "info_leak": "敏感信息泄露可能包含数据库凭据、API密钥、内部IP等，攻击者可利用这些信息进一步渗透。",
        }
        return impacts.get(vuln_type, "该漏洞可能导致数据泄露或业务安全风险。")

    def _impact_text_en(self, vuln_type: str, severity: str) -> str:
        """影响说明（英文）"""
        impacts = {
            "injection": "An attacker can extract sensitive data from the database including user credentials and PII.",
            "xss": "An attacker can steal user session tokens and perform actions on behalf of victims.",
            "ssrf": "An attacker can access internal services and cloud metadata, potentially leading to full infrastructure compromise.",
            "idor": "An attacker can access any user's private data by manipulating resource identifiers.",
            "rce": "An attacker can execute arbitrary commands on the server, leading to full system compromise.",
        }
        return impacts.get(vuln_type, "This vulnerability may lead to data exposure or service disruption.")

    def _fix_en(self, vuln_type: str) -> str:
        """修复建议（英文）"""
        fixes = {
            "injection": "Use parameterized queries/prepared statements. Implement input validation and least-privilege database accounts.",
            "xss": "Implement context-aware output encoding. Set Content-Security-Policy headers. Use HttpOnly cookie flag.",
            "ssrf": "Implement URL allowlisting. Block requests to private IP ranges. Disable redirect following.",
            "idor": "Implement server-side ownership validation for every resource access. Use unpredictable identifiers.",
            "rce": "Avoid direct command execution. Use safe APIs. Implement input sanitization and sandboxing.",
        }
        return fixes.get(vuln_type, "Please refer to OWASP guidelines for remediation.")


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

def generate_src_report(
    finding: Dict,
    platform: str = "butian",
    company: str = "",
) -> str:
    """一键生成 SRC 报告（返回 Markdown 文本）"""
    submitter = SRCSubmitter(platform=platform, company=company)
    report = submitter.generate_report(finding)
    return report.content


def batch_src_reports(
    findings: List[Dict],
    platform: str = "butian",
    output_dir: str = "",
    company: str = "",
) -> List[str]:
    """批量生成并保存 SRC 报告"""
    submitter = SRCSubmitter(platform=platform, company=company, output_dir=output_dir)
    reports = submitter.batch_generate(findings)
    return submitter.save_reports(reports)

