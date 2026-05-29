#!/usr/bin/env python3
"""
Phase-Aware Tool Manager — 按攻击阶段限制工具调用
移植自 RedAmon 框架的 Phase-Aware Tool Execution

核心理念：不同攻击阶段只允许使用对应的工具，防止在侦察阶段
就调用 exploit 工具，或在 post-exploit 阶段还在跑 nmap。

攻击阶段（Kill Chain）：
1. RECON — 信息收集（被动 + 主动）
2. WEAPONIZE — 攻击面分析 + 工具准备
3. EXPLOIT — 漏洞利用
4. POST_EXPLOIT — 后渗透（提权/横移/持久化）
5. REPORT — 报告生成

用法：
    from phase_tool_manager import PhaseToolManager, AttackPhase
    
    manager = PhaseToolManager()
    manager.set_phase(AttackPhase.RECON)
    
    # 检查工具是否允许
    if manager.is_allowed("nmap"):
        run_nmap(...)
    
    # 自动阶段升级
    manager.auto_advance(findings)
"""

import time
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Callable
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 攻击阶段定义
# ═══════════════════════════════════════════════════════════════

class AttackPhase(str, Enum):
    """Kill Chain 攻击阶段"""
    RECON = "recon"
    WEAPONIZE = "weaponize"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"

    @property
    def order(self) -> int:
        return list(AttackPhase).index(self)

    @property
    def label_cn(self) -> str:
        labels = {
            "recon": "侦察",
            "weaponize": "武器化",
            "exploit": "利用",
            "post_exploit": "后渗透",
            "report": "报告",
        }
        return labels.get(self.value, self.value)


# ═══════════════════════════════════════════════════════════════
# 工具分类注册表
# ═══════════════════════════════════════════════════════════════

# 每个阶段允许使用的工具
PHASE_TOOL_REGISTRY: Dict[AttackPhase, Set[str]] = {
    AttackPhase.RECON: {
        # 被动侦察
        "whois", "dig", "nslookup", "host", "theHarvester",
        "subfinder", "amass", "assetfinder", "crt.sh",
        "waybackurls", "gau", "hakrawler",
        # 主动侦察
        "nmap", "masscan", "httpx", "dnsx", "katana",
        "whatweb", "wappalyzer", "nuclei-info",
        # 网络探测
        "ping", "traceroute", "curl", "wget",
        # OSINT
        "shodan", "censys", "fofa", "zoomeye",
        "google-dork", "github-search",
    },
    AttackPhase.WEAPONIZE: {
        # 攻击面分析
        "nuclei", "nikto", "wpscan", "joomscan",
        # 参数发现
        "arjun", "paramspider", "ffuf",
        # 目录爆破
        "dirsearch", "gobuster", "feroxbuster",
        # 漏洞扫描
        "sqlmap-test", "dalfox", "ssrfmap",
        "xsstrike", "commix-test",
        # 密码分析
        "hash-identifier", "john-list",
        # 继承侦察阶段的工具
        *PHASE_TOOL_REGISTRY.get(AttackPhase.RECON, set()) if False else set(),
    },
    AttackPhase.EXPLOIT: {
        # SQL 注入
        "sqlmap", "nosqlmap",
        # XSS
        "dalfox", "xsstrike",
        # 命令注入
        "commix",
        # 文件上传
        "upload-bypass",
        # SSRF
        "ssrfmap",
        # 认证
        "hydra", "medusa", "patator",
        # 框架利用
        "nuclei-exploit",
        # 自定义 exploit
        "python", "curl", "wget",
        # 浏览器
        "playwright", "selenium",
    },
    AttackPhase.POST_EXPLOIT: {
        # 提权
        "linpeas", "winpeas", "linux-exploit-suggester",
        # 横移
        "crackmapexec", "impacket",
        # 持久化
        "crontab", "systemctl",
        # 数据收集
        "find", "grep", "cat", "ls",
        # 隧道
        "chisel", "ligolo", "socat",
        # Metasploit
        "msfconsole", "meterpreter",
    },
    AttackPhase.REPORT: {
        # 报告工具
        "python", "markdown", "pandoc",
        # 截图
        "gowitness", "eyewitness",
        # 文件操作
        "cat", "cp", "mv", "tar",
    },
}

# 补充：每个阶段继承前置阶段的安全工具
PHASE_TOOL_REGISTRY[AttackPhase.WEAPONIZE] |= PHASE_TOOL_REGISTRY[AttackPhase.RECON]
PHASE_TOOL_REGISTRY[AttackPhase.EXPLOIT] |= {"curl", "wget", "python", "httpx"}
PHASE_TOOL_REGISTRY[AttackPhase.REPORT] |= {"curl", "python"}

# 全阶段通用工具（任何阶段都允许）
UNIVERSAL_TOOLS: Set[str] = {
    "echo", "cat", "ls", "pwd", "date", "whoami",
    "python3", "python", "node", "bash", "sh",
    "head", "tail", "wc", "sort", "uniq", "grep",
    "jq", "sed", "awk", "tee", "mkdir", "touch",
}

# 绝对禁止的工具（任何阶段都不允许）
BANNED_TOOLS: Set[str] = {
    "rm -rf /", "mkfs", "dd of=/dev",
    ":(){ :|:& };:", "fork-bomb",
}


# ═══════════════════════════════════════════════════════════════
# 阶段升级条件
# ═══════════════════════════════════════════════════════════════

@dataclass
class PhaseAdvanceCondition:
    """阶段升级条件"""
    from_phase: AttackPhase
    to_phase: AttackPhase
    condition_description: str = ""
    # 触发条件函数
    check_fn: Optional[Callable] = None
    # 基于 findings 的简单条件
    min_subdomains: int = 0
    min_alive_hosts: int = 0
    min_urls: int = 0
    min_params: int = 0
    min_vulnerabilities: int = 0
    # 时间限制
    max_phase_duration: int = 600  # 秒


DEFAULT_ADVANCE_CONDITIONS = [
    PhaseAdvanceCondition(
        from_phase=AttackPhase.RECON,
        to_phase=AttackPhase.WEAPONIZE,
        condition_description="发现至少 1 个存活主机或 5 个子域名",
        min_alive_hosts=1,
        min_subdomains=5,
        max_phase_duration=300,
    ),
    PhaseAdvanceCondition(
        from_phase=AttackPhase.WEAPONIZE,
        to_phase=AttackPhase.EXPLOIT,
        condition_description="发现至少 1 个可能的漏洞或 10 个参数",
        min_vulnerabilities=1,
        min_params=10,
        max_phase_duration=600,
    ),
    PhaseAdvanceCondition(
        from_phase=AttackPhase.EXPLOIT,
        to_phase=AttackPhase.POST_EXPLOIT,
        condition_description="成功利用至少 1 个漏洞（获得 shell/数据）",
        min_vulnerabilities=1,  # 已验证的
        max_phase_duration=900,
    ),
    PhaseAdvanceCondition(
        from_phase=AttackPhase.POST_EXPLOIT,
        to_phase=AttackPhase.REPORT,
        condition_description="后渗透任务完成或超时",
        max_phase_duration=600,
    ),
]


# ═══════════════════════════════════════════════════════════════
# Phase Tool Manager 主类
# ═══════════════════════════════════════════════════════════════

@dataclass
class ToolExecutionRecord:
    """工具执行记录"""
    tool: str = ""
    phase: str = ""
    allowed: bool = True
    timestamp: float = 0
    reason: str = ""


class PhaseToolManager:
    """
    Phase-Aware 工具管理器
    
    核心功能：
    1. 根据当前攻击阶段限制可用工具
    2. 自动检测阶段升级条件
    3. 记录工具使用审计日志
    4. 支持手动/自动阶段切换
    
    用法：
        manager = PhaseToolManager()
        manager.set_phase(AttackPhase.RECON)
        
        # 执行前检查
        if manager.is_allowed("sqlmap"):
            # 在 RECON 阶段会返回 False
            pass
        
        # 自动升级检查
        manager.auto_advance(findings={
            "subdomains": [...],
            "alive_hosts": [...],
        })
    """

    def __init__(
        self,
        initial_phase: AttackPhase = AttackPhase.RECON,
        conditions: List[PhaseAdvanceCondition] = None,
        strict: bool = True,
        on_phase_change: Optional[Callable] = None,
    ):
        self.current_phase = initial_phase
        self.strict = strict  # True=严格拦截, False=警告但允许
        self.conditions = conditions or DEFAULT_ADVANCE_CONDITIONS
        self.on_phase_change = on_phase_change

        # 状态
        self._phase_start_time = time.time()
        self._phase_history: List[Dict] = []
        self._execution_log: List[ToolExecutionRecord] = []
        self._blocked_count = 0
        self._total_checks = 0

        # 记录初始阶段
        self._phase_history.append({
            "phase": initial_phase.value,
            "started_at": datetime.now().isoformat(),
            "reason": "initial",
        })

    # ─── 核心接口 ──────────────────────────────────────────

    def set_phase(self, phase: AttackPhase, reason: str = "manual"):
        """手动设置当前阶段"""
        old_phase = self.current_phase
        self.current_phase = phase
        self._phase_start_time = time.time()
        self._phase_history.append({
            "phase": phase.value,
            "started_at": datetime.now().isoformat(),
            "reason": reason,
            "from": old_phase.value,
        })
        if self.on_phase_change:
            self.on_phase_change(old_phase, phase, reason)

    def is_allowed(self, tool_name: str) -> bool:
        """
        检查工具在当前阶段是否允许使用
        
        Returns:
            True=允许, False=拒绝
        """
        self._total_checks += 1
        result = self._check_tool(tool_name)

        self._execution_log.append(ToolExecutionRecord(
            tool=tool_name,
            phase=self.current_phase.value,
            allowed=result.allowed,
            timestamp=time.time(),
            reason=result.reason,
        ))

        if not result.allowed:
            self._blocked_count += 1

        return result.allowed

    def check_tool(self, tool_name: str) -> ToolExecutionRecord:
        """检查工具并返回详细结果（不记录日志）"""
        return self._check_tool(tool_name)

    def get_allowed_tools(self) -> Set[str]:
        """获取当前阶段所有允许的工具"""
        phase_tools = PHASE_TOOL_REGISTRY.get(self.current_phase, set())
        return phase_tools | UNIVERSAL_TOOLS

    def get_phase_info(self) -> Dict:
        """获取当前阶段信息"""
        elapsed = time.time() - self._phase_start_time
        phase_tools = PHASE_TOOL_REGISTRY.get(self.current_phase, set())
        return {
            "current_phase": self.current_phase.value,
            "phase_label": self.current_phase.label_cn,
            "elapsed_seconds": int(elapsed),
            "tools_available": len(phase_tools | UNIVERSAL_TOOLS),
            "total_checks": self._total_checks,
            "blocked_count": self._blocked_count,
        }

    # ─── 自动阶段升级 ──────────────────────────────────────

    def auto_advance(self, findings: Dict) -> Optional[AttackPhase]:
        """
        根据 findings 自动判断是否应该升级阶段
        
        Args:
            findings: auto_hunt 的 findings dict
            
        Returns:
            新阶段（如果升级了），否则 None
        """
        elapsed = time.time() - self._phase_start_time

        for condition in self.conditions:
            if condition.from_phase != self.current_phase:
                continue

            should_advance = False

            # 时间超限
            if elapsed > condition.max_phase_duration:
                should_advance = True
                reason = f"阶段超时 ({int(elapsed)}s > {condition.max_phase_duration}s)"

            # 基于 findings 的条件
            elif self._check_findings_condition(findings, condition):
                should_advance = True
                reason = condition.condition_description

            # 自定义检查函数
            elif condition.check_fn and condition.check_fn(findings):
                should_advance = True
                reason = condition.condition_description

            if should_advance:
                self.set_phase(condition.to_phase, reason=reason)
                return condition.to_phase

        return None

    def force_advance(self) -> AttackPhase:
        """强制升级到下一阶段"""
        phases = list(AttackPhase)
        current_idx = phases.index(self.current_phase)
        if current_idx < len(phases) - 1:
            next_phase = phases[current_idx + 1]
            self.set_phase(next_phase, reason="force_advance")
            return next_phase
        return self.current_phase

    # ─── 内部方法 ──────────────────────────────────────────

    def _check_tool(self, tool_name: str) -> ToolExecutionRecord:
        """内部工具检查"""
        # 提取命令基础名（去掉参数）
        base_tool = tool_name.strip().split()[0].split("/")[-1].lower()

        # 通用工具直接放行
        if base_tool in UNIVERSAL_TOOLS:
            return ToolExecutionRecord(tool=tool_name, allowed=True, reason="universal")

        # 禁止列表
        for banned in BANNED_TOOLS:
            if banned in tool_name.lower():
                return ToolExecutionRecord(
                    tool=tool_name, allowed=False,
                    reason=f"BANNED: {banned}",
                    phase=self.current_phase.value,
                )

        # 阶段工具检查
        phase_tools = PHASE_TOOL_REGISTRY.get(self.current_phase, set())
        if base_tool in phase_tools:
            return ToolExecutionRecord(tool=tool_name, allowed=True, reason="phase_allowed")

        # 不在当前阶段允许列表
        # 查找属于哪个阶段
        belongs_to = []
        for phase, tools in PHASE_TOOL_REGISTRY.items():
            if base_tool in tools:
                belongs_to.append(phase.value)

        if belongs_to:
            reason = f"工具 '{base_tool}' 属于阶段 [{', '.join(belongs_to)}]，当前在 [{self.current_phase.value}]"
        else:
            reason = f"工具 '{base_tool}' 未注册在任何阶段"

        # 非严格模式下允许但发出警告
        allowed = not self.strict
        return ToolExecutionRecord(
            tool=tool_name, allowed=allowed,
            reason=reason,
            phase=self.current_phase.value,
        )

    def _check_findings_condition(self, findings: Dict, condition: PhaseAdvanceCondition) -> bool:
        """检查 findings 是否满足升级条件"""
        if condition.min_subdomains > 0:
            if len(findings.get("subdomains", [])) >= condition.min_subdomains:
                return True
        if condition.min_alive_hosts > 0:
            if len(findings.get("alive_hosts", [])) >= condition.min_alive_hosts:
                return True
        if condition.min_urls > 0:
            if len(findings.get("urls", [])) >= condition.min_urls:
                return True
        if condition.min_params > 0:
            if len(findings.get("params", [])) >= condition.min_params:
                return True
        if condition.min_vulnerabilities > 0:
            if len(findings.get("vulnerabilities", [])) >= condition.min_vulnerabilities:
                return True
        return False

    # ─── 统计与审计 ──────────────────────────────────────────

    def get_execution_log(self, last_n: int = 50) -> List[Dict]:
        """获取工具执行日志"""
        return [
            {
                "tool": r.tool,
                "phase": r.phase,
                "allowed": r.allowed,
                "reason": r.reason,
                "time": datetime.fromtimestamp(r.timestamp).isoformat() if r.timestamp else "",
            }
            for r in self._execution_log[-last_n:]
        ]

    def get_phase_history(self) -> List[Dict]:
        """获取阶段切换历史"""
        return self._phase_history

    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            **self.get_phase_info(),
            "phase_history_count": len(self._phase_history),
            "execution_log_size": len(self._execution_log),
            "block_rate": f"{self._blocked_count / max(self._total_checks, 1) * 100:.1f}%",
        }
