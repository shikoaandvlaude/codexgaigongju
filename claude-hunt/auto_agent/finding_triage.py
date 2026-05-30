#!/usr/bin/env python3
"""
Finding Triage — 发现结果自动标签/分类

解决问题：
- 工具发现很多线索，但需要人工判断"能不能报"
- 在一堆 401/403/公开 key 里迷路
- 需要快速过滤出值得深入的发现

标签体系：
- 🟢 SUBMITTABLE    可提交（确认漏洞+有影响+在scope内）
- 🟡 NEEDS_PROD     需要生产环境复现
- 🟠 UAT_ONLY       仅UAT/低影响（部分项目不收）
- 🔴 EXCLUDED       已排除（误报/不收/out-of-scope）
- 🔵 NEEDS_AUTH     需要登录账号才能深入
- ⚪ INVESTIGATING  调查中（线索有潜力）

用法：
    from finding_triage import FindingTriage

    ft = FindingTriage(compliance=compliance_mode)
    label = ft.triage(finding)
    report = ft.get_submittable()
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

# 标签定义
LABELS = {
    "submittable": {"emoji": "🟢", "name": "可提交", "priority": 1},
    "needs_prod": {"emoji": "🟡", "name": "需生产复现", "priority": 2},
    "investigating": {"emoji": "⚪", "name": "调查中", "priority": 3},
    "needs_auth": {"emoji": "🔵", "name": "需要登录", "priority": 4},
    "uat_only": {"emoji": "🟠", "name": "仅UAT", "priority": 5},
    "excluded": {"emoji": "🔴", "name": "已排除", "priority": 6},
}


@dataclass
class TriagedFinding:
    """分类后的发现"""
    # 基本信息
    id: str = ""
    title: str = ""
    vuln_type: str = ""
    url: str = ""
    method: str = ""
    severity: str = ""
    # 标签
    label: str = "investigating"
    label_reason: str = ""
    # 证据
    evidence: str = ""
    response_code: int = 0
    response_excerpt: str = ""
    # 上下文
    environment: str = ""          # production/uat/staging
    requires_auth: bool = False
    confirmed: bool = False
    # 元数据
    discovered_at: str = ""
    triaged_at: str = ""
    notes: str = ""


# 自动排除规则
AUTO_EXCLUDE_PATTERNS = [
    # 公开的无害信息
    {"pattern": r"google.analytics|gtag|ga\.js", "reason": "公开的 Analytics ID"},
    {"pattern": r"api-?key.*AIza", "reason": "Google Maps API Key（通常公开）"},
    {"pattern": r"recaptcha.*sitekey", "reason": "reCAPTCHA 公开 site key"},
    {"pattern": r"stripe.*pk_(test|live)_", "reason": "Stripe 公开 publishable key"},
    {"pattern": r"facebook.*app.?id", "reason": "Facebook App ID（通常公开）"},
    # 非漏洞
    {"pattern": r"X-Frame-Options.*missing", "reason": "缺少安全头（大多数项目不收）"},
    {"pattern": r"CSP.*missing", "reason": "缺少 CSP（大多数项目不收）"},
    {"pattern": r"HSTS.*missing", "reason": "缺少 HSTS（低危/不收）"},
    {"pattern": r"clickjacking", "reason": "Clickjacking（大多数项目不收）"},
    {"pattern": r"self[_-]?xss", "reason": "Self-XSS（不收）"},
    {"pattern": r"logout.*csrf", "reason": "Logout CSRF（不收）"},
    {"pattern": r"email.*spoof", "reason": "Email Spoofing（大多数不收）"},
]

# 需要登录才能深入的信号
AUTH_REQUIRED_SIGNALS = [
    r"401\s*unauthorized",
    r"login.required",
    r"authentication.required",
    r"must.be.logged.in",
    r"session.expired",
    r"token.invalid",
    r"bearer.*required",
]

# UAT/非生产信号
UAT_SIGNALS = [
    r"uat\.", r"staging\.", r"test\.", r"dev\.",
    r"sandbox\.", r"preprod\.", r"qa\.",
]


class FindingTriage:
    """发现结果分类器"""

    def __init__(self, compliance=None, config: dict = None):
        self.compliance = compliance  # ComplianceMode 实例
        self.config = config or {}
        self.findings: List[TriagedFinding] = []
        self.triage_dir = os.path.expanduser("~/.bai-agent/triage")
        Path(self.triage_dir).mkdir(parents=True, exist_ok=True)

    def triage(self, finding: dict) -> TriagedFinding:
        """
        对单个发现进行分类
        输入: {"url": "...", "vuln_type": "...", "evidence": "...", "status_code": 200, ...}
        """
        tf = TriagedFinding(
            id=f"F{len(self.findings)+1:04d}",
            title=finding.get("title", finding.get("vuln_type", "Unknown")),
            vuln_type=finding.get("vuln_type", ""),
            url=finding.get("url", ""),
            method=finding.get("method", "GET"),
            severity=finding.get("severity", "medium"),
            evidence=finding.get("evidence", ""),
            response_code=finding.get("status_code", 0),
            response_excerpt=finding.get("response", "")[:500],
            discovered_at=finding.get("timestamp", datetime.now().isoformat()),
            triaged_at=datetime.now().isoformat(),
        )

        # 自动标签流程
        label, reason = self._auto_label(tf)
        tf.label = label
        tf.label_reason = reason

        self.findings.append(tf)
        label_info = LABELS.get(label, {})
        print(f"  {label_info.get('emoji', '?')} [{label_info.get('name', label)}] "
              f"{tf.title[:40]} — {reason}")

        return tf

    def triage_batch(self, findings: List[dict]) -> List[TriagedFinding]:
        """批量分类"""
        print(f"\n[*] 批量分类 {len(findings)} 个发现...\n")
        results = [self.triage(f) for f in findings]

        # 打印汇总
        self._print_summary()
        return results

    def get_submittable(self) -> List[TriagedFinding]:
        """获取可提交的发现"""
        return [f for f in self.findings if f.label == "submittable"]

    def get_by_label(self, label: str) -> List[TriagedFinding]:
        """按标签获取"""
        return [f for f in self.findings if f.label == label]

    def override_label(self, finding_id: str, new_label: str, reason: str = ""):
        """手动覆盖标签"""
        for f in self.findings:
            if f.id == finding_id:
                old = f.label
                f.label = new_label
                f.label_reason = reason or f"手动从 {old} 改为 {new_label}"
                f.notes += f"\n[{datetime.now().strftime('%H:%M')}] 标签变更: {old} → {new_label}"
                print(f"  [+] {finding_id} 标签已更新: {old} → {new_label}")
                return
        print(f"  [!] 未找到: {finding_id}")

    def get_dashboard(self) -> str:
        """获取分类仪表盘"""
        lines = [f"\n{'='*60}", f"发现分类仪表盘", f"{'='*60}\n"]

        counts = {}
        for f in self.findings:
            counts[f.label] = counts.get(f.label, 0) + 1

        for label_key, label_info in LABELS.items():
            count = counts.get(label_key, 0)
            bar = "█" * count + "░" * (20 - min(count, 20))
            lines.append(f"  {label_info['emoji']} {label_info['name']:10s} {bar} {count}")

        lines.append(f"\n  总计: {len(self.findings)} 个发现")
        submittable = counts.get("submittable", 0)
        if submittable:
            lines.append(f"  🎯 可提交: {submittable} 个")

        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════
    # 自动标签逻辑
    # ═══════════════════════════════════════════════════════════

    def _auto_label(self, tf: TriagedFinding) -> Tuple[str, str]:
        """自动判断标签"""
        url = tf.url.lower()
        evidence = (tf.evidence + tf.response_excerpt).lower()
        full_text = f"{url} {evidence} {tf.vuln_type}".lower()

        # 1. 检查自动排除
        for rule in AUTO_EXCLUDE_PATTERNS:
            if re.search(rule["pattern"], full_text, re.IGNORECASE):
                return "excluded", rule["reason"]

        # 2. 检查合规模式（Non-Qualifying）
        if self.compliance:
            accepted, msg = self.compliance.check_finding_type(tf.vuln_type)
            if not accepted:
                return "excluded", msg

        # 3. 检查是否需要认证
        for pattern in AUTH_REQUIRED_SIGNALS:
            if re.search(pattern, full_text, re.IGNORECASE):
                tf.requires_auth = True
                return "needs_auth", "响应显示需要认证"

        # 4. 检查是否 UAT/非生产
        for pattern in UAT_SIGNALS:
            if re.search(pattern, url):
                tf.environment = "uat"
                # 如果合规模式要求只收生产
                if self.compliance and self.compliance.rule.production_only:
                    return "uat_only", "仅UAT环境（项目只收生产）"
                return "needs_prod", "发现在UAT环境，需生产复现"

        # 5. 检查 scope
        if self.compliance:
            in_scope, reason = self.compliance.check_target(tf.url)
            if not in_scope:
                return "excluded", reason

        # 6. 确认的漏洞 → 可提交
        if tf.confirmed or tf.response_code == 200:
            # 高危/关键漏洞
            if tf.severity in ("critical", "high"):
                return "submittable", f"确认的{tf.severity}级漏洞"
            # 中危需要更多证据
            elif tf.severity == "medium":
                if tf.evidence and len(tf.evidence) > 50:
                    return "submittable", "中危漏洞，有充分证据"
                return "investigating", "中危漏洞，需补充证据"

        # 7. 403/401 但有绕过潜力
        if tf.response_code in (403, 401):
            return "needs_auth", f"HTTP {tf.response_code}，需认证或绕过"

        # 默认
        return "investigating", "需要进一步调查"

    def _print_summary(self):
        """打印分类汇总"""
        print(self.get_dashboard())

    def save(self, name: str = ""):
        """保存分类结果"""
        name = name or datetime.now().strftime("%Y%m%d_%H%M")
        path = os.path.join(self.triage_dir, f"triage_{name}.json")
        from dataclasses import asdict
        data = [asdict(f) for f in self.findings]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] 分类结果已保存: {path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="发现结果分类器")
    parser.add_argument("--demo", action="store_true", help="演示分类")
    parser.add_argument("--dashboard", action="store_true", help="显示仪表盘")
    args = parser.parse_args()

    ft = FindingTriage()

    if args.demo:
        demo_findings = [
            {"url": "https://api.example.com/users/123", "vuln_type": "idor", "severity": "high",
             "status_code": 200, "evidence": "返回了其他用户的PII数据", "response": '{"email":"victim@x.com"}'},
            {"url": "https://uat.example.com/admin", "vuln_type": "unauth", "severity": "high",
             "status_code": 200, "evidence": "管理后台无需认证"},
            {"url": "https://app.example.com/login", "vuln_type": "self_xss", "severity": "low",
             "status_code": 200, "evidence": "需要受害者自行输入payload"},
            {"url": "https://api.example.com/secret", "vuln_type": "info_leak", "severity": "medium",
             "status_code": 401, "evidence": "Unauthorized"},
            {"url": "https://app.example.com/js/app.js", "vuln_type": "info_leak", "severity": "info",
             "evidence": "Google Analytics ID: UA-123456"},
        ]
        ft.triage_batch(demo_findings)
    elif args.dashboard:
        print("无数据。先运行 --demo 查看示例。")
    else:
        parser.print_help()
