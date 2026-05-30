#!/usr/bin/env python3
"""
Compliance Mode — HackerOne/Bugcrowd 合规测试模式

解决问题：
- 不同 Bug Bounty 项目规则不同，容易误操作
- 需要记录允许测哪些资产、禁止什么动作、必带什么 header
- 防止 brute force / DoS / 写数据等违规操作

功能：
1. 加载项目规则文件（JSON/YAML）
2. 自动拦截违规请求（brute force、写操作等）
3. 自动注入必需 header（如 X-Bug-Bounty: researcher-name）
4. Scope 白名单/黑名单实时检查
5. 操作日志（证明合规）

用法：
    from compliance_mode import ComplianceMode

    # 加载项目规则
    cm = ComplianceMode("programs/syfe.yaml")

    # 检查目标是否在 scope 内
    cm.check_target("api.syfe.com")  # True
    cm.check_target("admin.syfe.com")  # False + 警告

    # 检查操作是否合规
    cm.check_action("GET", "/api/users/me")  # OK
    cm.check_action("DELETE", "/api/users/123")  # BLOCKED

    # 获取必需 headers
    headers = cm.get_required_headers()

    # 记录操作日志
    cm.log_action("GET", "/api/users/me", 200)

CLI:
    python compliance_mode.py --init syfe       # 交互式创建项目规则
    python compliance_mode.py --show syfe       # 显示当前规则
    python compliance_mode.py --check syfe api.syfe.com  # 检查目标
"""

import json
import os
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class ProgramRule:
    """Bug Bounty 项目规则"""
    # 基本信息
    program_name: str = ""
    platform: str = "hackerone"       # hackerone/bugcrowd/intigriti/custom
    program_url: str = ""
    researcher_name: str = ""

    # Scope 规则
    in_scope: List[Dict] = field(default_factory=list)      # [{"asset": "*.syfe.com", "type": "web"}]
    out_of_scope: List[Dict] = field(default_factory=list)  # [{"asset": "admin.syfe.com", "reason": "no test"}]

    # 禁止的动作
    forbidden_actions: List[str] = field(default_factory=list)
    # 默认: ["brute_force", "dos", "ddos", "social_engineering", "physical",
    #         "automated_mass_scan", "data_destruction", "spam"]

    # 禁止的 HTTP 方法（针对特定路径）
    forbidden_methods: Dict[str, List[str]] = field(default_factory=dict)
    # 例: {"/api/users": ["DELETE", "PUT"], "*": ["DELETE"]}

    # 必需的 Headers
    required_headers: Dict[str, str] = field(default_factory=dict)
    # 例: {"X-Bug-Bounty": "researcher-name", "User-Agent": "BugBounty-Research"}

    # 速率限制
    max_requests_per_minute: int = 30
    max_requests_per_second: int = 2

    # 特殊规则
    no_auto_scan: bool = False          # 禁止自动化扫描
    read_only: bool = False             # 只读模式（禁止所有写操作）
    require_auth: bool = False          # 所有请求必须带认证
    uat_findings_accepted: bool = True  # UAT 环境发现是否接受
    production_only: bool = False       # 只接受生产环境发现

    # 不收的漏洞类型（Non-Qualifying Bugs）
    non_qualifying: List[str] = field(default_factory=list)
    # 例: ["self_xss", "logout_csrf", "missing_headers", "rate_limiting",
    #       "uat_info_leak", "email_spoofing", "clickjacking"]

    # 备注
    notes: List[str] = field(default_factory=list)


@dataclass
class ComplianceLog:
    """合规操作日志"""
    timestamp: str = ""
    action: str = ""          # GET/POST/PUT/DELETE/SCAN
    target: str = ""
    status: str = ""          # allowed/blocked/warning
    reason: str = ""
    response_code: int = 0


# ═══════════════════════════════════════════════════════════════
# 合规模式引擎
# ═══════════════════════════════════════════════════════════════

class ComplianceMode:
    """合规测试模式"""

    def __init__(self, rule_path: str = None, config: dict = None):
        self.config = config or {}
        self.rule: ProgramRule = ProgramRule()
        self.logs: List[ComplianceLog] = []
        self.request_timestamps: List[float] = []
        self.programs_dir = os.path.expanduser("~/.bai-agent/programs")
        Path(self.programs_dir).mkdir(parents=True, exist_ok=True)

        if rule_path:
            self.load_rule(rule_path)

    # ═══════════════════════════════════════════════════════════
    # 规则加载/保存
    # ═══════════════════════════════════════════════════════════

    def load_rule(self, path: str) -> bool:
        """加载项目规则"""
        # 支持简称加载
        if not os.path.exists(path):
            full_path = os.path.join(self.programs_dir, f"{path}.json")
            if os.path.exists(full_path):
                path = full_path
            else:
                print(f"[!] 规则文件未找到: {path}")
                return False

        try:
            with open(path, "r", encoding="utf-8") as f:
                if path.endswith(".yaml") or path.endswith(".yml"):
                    import yaml
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            self.rule = ProgramRule(**{k: v for k, v in data.items()
                                      if k in ProgramRule.__dataclass_fields__})
            print(f"[+] 已加载项目规则: {self.rule.program_name} ({self.rule.platform})")
            self._print_summary()
            return True

        except Exception as e:
            print(f"[!] 加载规则失败: {e}")
            return False

    def save_rule(self, name: str = None) -> str:
        """保存项目规则"""
        name = name or self.rule.program_name.lower().replace(" ", "_")
        path = os.path.join(self.programs_dir, f"{name}.json")

        from dataclasses import asdict
        data = asdict(self.rule)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[+] 规则已保存: {path}")
        return path

    def init_interactive(self) -> ProgramRule:
        """交互式创建项目规则"""
        print("\n╔══════════════════════════════════════╗")
        print("║   创建 Bug Bounty 项目合规规则       ║")
        print("╚══════════════════════════════════════╝\n")

        self.rule.program_name = input("项目名称 (如 Syfe): ").strip()
        self.rule.platform = input("平台 [hackerone/bugcrowd/intigriti]: ").strip() or "hackerone"
        self.rule.program_url = input("项目链接: ").strip()
        self.rule.researcher_name = input("你的研究员用户名: ").strip()

        # Scope
        print("\n── In-Scope 资产 (每行一个，空行结束) ──")
        while True:
            asset = input("  资产 (如 *.syfe.com): ").strip()
            if not asset:
                break
            asset_type = input(f"  类型 [web/api/mobile/other]: ").strip() or "web"
            self.rule.in_scope.append({"asset": asset, "type": asset_type})

        print("\n── Out-of-Scope 资产 (每行一个，空行结束) ──")
        while True:
            asset = input("  资产: ").strip()
            if not asset:
                break
            reason = input(f"  排除原因: ").strip()
            self.rule.out_of_scope.append({"asset": asset, "reason": reason})

        # 禁止动作
        print("\n── 禁止的操作 ──")
        default_forbidden = ["brute_force", "dos", "social_engineering", "data_destruction"]
        use_default = input(f"  使用默认禁止列表 {default_forbidden}? [Y/n]: ").strip().lower()
        if use_default != "n":
            self.rule.forbidden_actions = default_forbidden

        # 必需 Headers
        print("\n── 必需的请求 Header ──")
        add_header = input("  是否需要添加特定 Header (如 X-Bug-Bounty)? [y/N]: ").strip().lower()
        if add_header == "y":
            while True:
                key = input("  Header 名: ").strip()
                if not key:
                    break
                val = input(f"  Header 值: ").strip()
                self.rule.required_headers[key] = val

        # 速率限制
        rps = input("\n每秒最大请求数 [2]: ").strip()
        self.rule.max_requests_per_second = int(rps) if rps else 2

        # 特殊规则
        self.rule.read_only = input("只读模式（禁止所有写操作）? [y/N]: ").strip().lower() == "y"
        self.rule.no_auto_scan = input("禁止自动化扫描? [y/N]: ").strip().lower() == "y"
        self.rule.production_only = input("只接受生产环境发现? [y/N]: ").strip().lower() == "y"

        # 不收的漏洞
        print("\n── 不收的漏洞类型 (Non-Qualifying) ──")
        print("  常见: self_xss, logout_csrf, missing_headers, rate_limiting, uat_info_leak")
        nq = input("  输入不收的类型（逗号分隔）: ").strip()
        if nq:
            self.rule.non_qualifying = [x.strip() for x in nq.split(",")]

        # 保存
        self.save_rule()
        self._print_summary()
        return self.rule

    # ═══════════════════════════════════════════════════════════
    # 合规检查
    # ═══════════════════════════════════════════════════════════

    def check_target(self, target: str) -> Tuple[bool, str]:
        """
        检查目标是否在 scope 内
        返回: (是否允许, 原因)
        """
        target_lower = target.lower().strip()

        # 检查 out-of-scope
        for oos in self.rule.out_of_scope:
            pattern = oos.get("asset", "").lower()
            if self._match_asset(target_lower, pattern):
                reason = f"OUT-OF-SCOPE: {target} (原因: {oos.get('reason', '未知')})"
                self._log("CHECK_TARGET", target, "blocked", reason)
                return False, reason

        # 检查 in-scope
        if self.rule.in_scope:
            for ins in self.rule.in_scope:
                pattern = ins.get("asset", "").lower()
                if self._match_asset(target_lower, pattern):
                    self._log("CHECK_TARGET", target, "allowed", "在 scope 内")
                    return True, "在 scope 内"
            # 不在任何 in-scope 中
            reason = f"NOT-IN-SCOPE: {target} 不在已定义的 scope 中"
            self._log("CHECK_TARGET", target, "warning", reason)
            return False, reason

        # 没有定义 scope，默认允许
        return True, "未定义 scope 规则"

    def check_action(self, method: str, path: str, target: str = "") -> Tuple[bool, str]:
        """
        检查操作是否合规
        返回: (是否允许, 原因)
        """
        method = method.upper()

        # 只读模式检查
        if self.rule.read_only and method in ("POST", "PUT", "DELETE", "PATCH"):
            reason = f"BLOCKED: 只读模式禁止 {method} 请求"
            self._log(method, f"{target}{path}", "blocked", reason)
            return False, reason

        # 检查特定路径的禁止方法
        for pattern, forbidden_methods in self.rule.forbidden_methods.items():
            if pattern == "*" or pattern in path:
                if method in [m.upper() for m in forbidden_methods]:
                    reason = f"BLOCKED: {method} {path} 被项目规则禁止"
                    self._log(method, f"{target}{path}", "blocked", reason)
                    return False, reason

        # 检查禁止动作（需要上层调用者标记动作类型）
        # 这里只做基本检查

        # 速率限制
        if not self._check_rate_limit():
            reason = f"RATE_LIMITED: 超过 {self.rule.max_requests_per_second} req/s"
            self._log(method, f"{target}{path}", "blocked", reason)
            return False, reason

        self._log(method, f"{target}{path}", "allowed", "合规")
        return True, "合规"

    def check_finding_type(self, vuln_type: str) -> Tuple[bool, str]:
        """
        检查漏洞类型是否在项目收录范围内
        返回: (是否值得报告, 提示)
        """
        vuln_type_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")

        for nq in self.rule.non_qualifying:
            if nq.lower() in vuln_type_lower or vuln_type_lower in nq.lower():
                return False, f"⚠️ 该项目不收此类漏洞: {vuln_type} (Non-Qualifying)"

        return True, "该漏洞类型在收录范围内"

    def get_required_headers(self) -> Dict[str, str]:
        """获取必需的请求 headers"""
        headers = dict(self.rule.required_headers)
        # 自动添加研究员标识
        if self.rule.researcher_name and "X-Bug-Bounty" not in headers:
            headers["X-Bug-Bounty"] = self.rule.researcher_name
        return headers

    def is_auto_scan_allowed(self) -> bool:
        """是否允许自动化扫描"""
        return not self.rule.no_auto_scan

    def get_rate_limit(self) -> int:
        """获取速率限制"""
        return self.rule.max_requests_per_second

    # ═══════════════════════════════════════════════════════════
    # 内部方法
    # ═══════════════════════════════════════════════════════════

    def _match_asset(self, target: str, pattern: str) -> bool:
        """通配符匹配资产"""
        if not pattern:
            return False
        # 转换通配符为正则
        regex = pattern.replace(".", r"\.").replace("*", ".*")
        return bool(re.match(f"^{regex}$", target))

    def _check_rate_limit(self) -> bool:
        """速率限制检查"""
        now = time.time()
        # 清理过期记录
        self.request_timestamps = [t for t in self.request_timestamps if now - t < 1.0]
        if len(self.request_timestamps) >= self.rule.max_requests_per_second:
            return False
        self.request_timestamps.append(now)
        return True

    def _log(self, action: str, target: str, status: str, reason: str):
        """记录合规日志"""
        log = ComplianceLog(
            timestamp=datetime.now().isoformat(),
            action=action,
            target=target,
            status=status,
            reason=reason,
        )
        self.logs.append(log)

        # 实时输出警告
        if status == "blocked":
            print(f"  🚫 [合规拦截] {reason}")
        elif status == "warning":
            print(f"  ⚠️  [合规警告] {reason}")

    def _print_summary(self):
        """打印规则摘要"""
        r = self.rule
        print(f"\n  ┌─ 项目: {r.program_name} ({r.platform})")
        print(f"  │  In-Scope: {len(r.in_scope)} 个资产")
        print(f"  │  Out-of-Scope: {len(r.out_of_scope)} 个资产")
        print(f"  │  速率限制: {r.max_requests_per_second} req/s")
        if r.read_only:
            print(f"  │  ⚠️  只读模式（禁止写操作）")
        if r.no_auto_scan:
            print(f"  │  ⚠️  禁止自动化扫描")
        if r.non_qualifying:
            print(f"  │  不收: {', '.join(r.non_qualifying[:5])}")
        if r.required_headers:
            print(f"  │  必需Header: {list(r.required_headers.keys())}")
        print(f"  └─────────────────────────────")

    # ═══════════════════════════════════════════════════════════
    # 导出合规日志
    # ═══════════════════════════════════════════════════════════

    def export_logs(self, path: str = None) -> str:
        """导出合规操作日志（证明合规测试）"""
        path = path or os.path.join(
            self.programs_dir,
            f"{self.rule.program_name}_compliance_log_{datetime.now().strftime('%Y%m%d')}.md"
        )

        lines = [
            f"# 合规测试日志 — {self.rule.program_name}",
            f"",
            f"- 平台: {self.rule.platform}",
            f"- 研究员: {self.rule.researcher_name}",
            f"- 导出时间: {datetime.now().isoformat()}",
            f"- 总操作数: {len(self.logs)}",
            f"",
            f"## 操作记录",
            f"",
            f"| 时间 | 动作 | 目标 | 状态 | 原因 |",
            f"|------|------|------|------|------|",
        ]

        for log in self.logs[-200:]:  # 最近 200 条
            lines.append(
                f"| {log.timestamp[11:19]} | {log.action} | {log.target[:40]} | {log.status} | {log.reason[:30]} |"
            )

        blocked_count = sum(1 for l in self.logs if l.status == "blocked")
        lines.extend([
            f"",
            f"## 统计",
            f"- 总请求: {len(self.logs)}",
            f"- 拦截: {blocked_count}",
            f"- 通过: {len(self.logs) - blocked_count}",
        ])

        content = "\n".join(lines)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"[+] 合规日志已导出: {path}")
        return path


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty 合规测试模式")
    parser.add_argument("--init", help="交互式创建项目规则")
    parser.add_argument("--show", help="显示项目规则")
    parser.add_argument("--check", nargs=2, help="检查目标是否在 scope 内: --check 项目名 目标")
    parser.add_argument("--list", action="store_true", help="列出已保存的项目规则")
    args = parser.parse_args()

    cm = ComplianceMode()

    if args.init:
        cm.rule.program_name = args.init
        cm.init_interactive()
    elif args.show:
        cm.load_rule(args.show)
    elif args.check:
        cm.load_rule(args.check[0])
        allowed, reason = cm.check_target(args.check[1])
        print(f"\n{'✅ 允许' if allowed else '❌ 禁止'}: {reason}")
    elif args.list:
        programs_dir = os.path.expanduser("~/.bai-agent/programs")
        if os.path.exists(programs_dir):
            files = [f for f in os.listdir(programs_dir) if f.endswith(".json")]
            print(f"\n已保存的项目规则 ({len(files)}):\n")
            for f in files:
                print(f"  • {f.replace('.json', '')}")
        else:
            print("暂无保存的项目规则")
    else:
        parser.print_help()
