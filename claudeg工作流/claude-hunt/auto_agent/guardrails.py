#!/usr/bin/env python3
"""
Guardrails — 安全防护模块
移植自 CAI 框架的 Guardrails 系统

功能：
1. InputGuardrail: 检测 prompt 注入攻击
2. OutputGuardrail: 过滤敏感输出（防止泄露 key/token）
3. CommandBlocker: 拦截危险系统命令
4. TripwireDetector: 检测蜜罐/陷阱特征
5. SafetyGate: 统一安全门控（所有请求经过）

用法：
    from guardrails import SafetyGate
    
    gate = SafetyGate()
    
    # 检查用户输入
    result = gate.check_input(user_message)
    if result.blocked:
        print(f"输入被拦截: {result.reason}")
    
    # 检查命令
    result = gate.check_command("rm -rf /")
    if result.blocked:
        print(f"命令被拦截: {result.reason}")
    
    # 检查输出
    cleaned = gate.sanitize_output(ai_response)
"""

import re
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class GuardrailResult:
    """安全检查结果"""
    blocked: bool = False
    reason: str = ""
    severity: str = "info"  # info/warning/critical
    rule_id: str = ""
    original_input: str = ""
    sanitized: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class GuardrailConfig:
    """Guardrails 配置"""
    # 启用项
    enable_input_guard: bool = True
    enable_output_guard: bool = True
    enable_command_blocker: bool = True
    enable_tripwire: bool = True
    # 严格程度
    strict_mode: bool = False  # True=任何可疑都拦截
    # 白名单
    allowed_commands: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=lambda: [
        "/home", "/tmp", "/opt", "/var/www"
    ])
    # 日志
    log_blocked: bool = True
    audit_file: str = ""


# ═══════════════════════════════════════════════════════════════
# Input Guardrail — Prompt 注入检测
# ═══════════════════════════════════════════════════════════════

class InputGuardrail:
    """
    检测 Prompt Injection 攻击
    
    检测模式：
    1. 角色覆盖尝试（"ignore previous instructions"）
    2. 系统提示泄露尝试（"repeat your system prompt"）
    3. 编码绕过（base64/hex/unicode 混淆）
    4. 多语言绕过（用其他语言重述恶意指令）
    5. 间接注入（通过数据字段注入指令）
    """

    # 高危 prompt injection 模式
    INJECTION_PATTERNS = [
        # 角色覆盖
        (r"ignore\s+(all\s+)?previous\s+(instructions|rules|prompts)", "role_override"),
        (r"forget\s+(everything|all|your)\s+(instructions|rules|training)", "role_override"),
        (r"you\s+are\s+now\s+(a|an|the)\s+", "role_override"),
        (r"new\s+instructions?\s*[:：]", "role_override"),
        (r"override\s+(system|safety|security)", "role_override"),
        (r"disregard\s+(all|any|previous)", "role_override"),
        # 系统提示泄露
        (r"(show|print|repeat|display|output)\s+(your|the)\s+(system|initial)\s+(prompt|instructions|message)", "prompt_leak"),
        (r"what\s+(are|were)\s+your\s+(initial|system|original)\s+(instructions|prompt|rules)", "prompt_leak"),
        # DAN / jailbreak
        (r"\bDAN\b.*\bmode\b", "jailbreak"),
        (r"developer\s+mode\s+(enabled|on|activate)", "jailbreak"),
        (r"(enable|activate|enter)\s+(god|admin|root|sudo)\s+mode", "jailbreak"),
        # 输出操控
        (r"(say|respond|reply|output)\s*[\"'].*[\"']\s*(exactly|verbatim)", "output_control"),
        (r"respond\s+only\s+with", "output_control"),
    ]

    # 间接注入标记（在数据字段中发现的指令）
    INDIRECT_MARKERS = [
        "IMPORTANT:", "SYSTEM:", "ADMIN:", "NOTE TO AI:",
        "AI INSTRUCTIONS:", "HIDDEN PROMPT:",
        "[INST]", "[/INST]", "<|im_start|>", "<|system|>",
    ]

    def __init__(self, strict: bool = False):
        self.strict = strict
        self._compiled = [(re.compile(p, re.IGNORECASE), cat) for p, cat in self.INJECTION_PATTERNS]

    def check(self, text: str) -> GuardrailResult:
        """检查输入是否包含 prompt injection"""
        if not text:
            return GuardrailResult()

        # 1. 直接模式匹配
        for pattern, category in self._compiled:
            if pattern.search(text):
                return GuardrailResult(
                    blocked=True,
                    reason=f"Prompt injection detected: {category}",
                    severity="critical",
                    rule_id=f"INPUT-{category.upper()}",
                    original_input=text[:200],
                )

        # 2. 间接注入标记
        text_upper = text.upper()
        for marker in self.INDIRECT_MARKERS:
            if marker in text_upper:
                return GuardrailResult(
                    blocked=True if self.strict else False,
                    reason=f"Indirect injection marker: {marker}",
                    severity="warning",
                    rule_id="INPUT-INDIRECT",
                    original_input=text[:200],
                )

        # 3. 编码绕过检测
        if self._has_encoded_injection(text):
            return GuardrailResult(
                blocked=True,
                reason="Encoded injection attempt detected",
                severity="critical",
                rule_id="INPUT-ENCODED",
                original_input=text[:200],
            )

        # 4. 异常长度检测（超长输入可能试图溢出上下文）
        if len(text) > 50000:
            return GuardrailResult(
                blocked=self.strict,
                reason=f"Abnormally long input ({len(text)} chars)",
                severity="warning",
                rule_id="INPUT-LENGTH",
            )

        return GuardrailResult()

    def _has_encoded_injection(self, text: str) -> bool:
        """检测编码绕过"""
        import base64 as b64
        # base64 检测
        b64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        for candidate in b64_pattern[:5]:
            try:
                decoded = b64.b64decode(candidate).decode('utf-8', errors='ignore')
                for pattern, _ in self._compiled:
                    if pattern.search(decoded):
                        return True
            except Exception:
                continue

        # hex 检测
        hex_pattern = re.findall(r'(?:0x|\\x)?([0-9a-fA-F]{2}){10,}', text)
        for candidate in hex_pattern[:3]:
            try:
                decoded = bytes.fromhex(candidate).decode('utf-8', errors='ignore')
                for pattern, _ in self._compiled:
                    if pattern.search(decoded):
                        return True
            except Exception:
                continue

        return False


# ═══════════════════════════════════════════════════════════════
# Output Guardrail — 敏感信息过滤
# ═══════════════════════════════════════════════════════════════

class OutputGuardrail:
    """
    过滤 AI 输出中的敏感信息
    
    防止泄露：
    1. API Keys / Tokens
    2. 私钥 / 证书
    3. 密码
    4. 内部 IP / 路径
    5. 系统提示内容
    """

    SENSITIVE_PATTERNS = [
        # API Keys
        (r'(?:sk|pk|ak|api[_-]?key)[_-]?[a-zA-Z0-9]{20,}', "[REDACTED_API_KEY]"),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}', "[REDACTED_GITHUB_TOKEN]"),
        (r'Bearer\s+[A-Za-z0-9\-._~+/]{20,}', "Bearer [REDACTED]"),
        # AWS
        (r'AKIA[0-9A-Z]{16}', "[REDACTED_AWS_KEY]"),
        (r'(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*[A-Za-z0-9/+=]{30,}', "[REDACTED_AWS_SECRET]"),
        # 私钥
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END', "[REDACTED_PRIVATE_KEY]"),
        # JWT
        (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "[REDACTED_JWT]"),
        # 密码（在配置/环境变量中）
        (r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}', "[REDACTED_PASSWORD]"),
        # 内部路径
        (r'/root/\.[a-z]+/[^\s]+', "[REDACTED_PATH]"),
    ]

    def __init__(self):
        self._compiled = [(re.compile(p, re.IGNORECASE), repl) for p, repl in self.SENSITIVE_PATTERNS]

    def sanitize(self, text: str) -> Tuple[str, List[str]]:
        """
        过滤敏感信息
        
        Returns:
            (sanitized_text, list_of_redacted_items)
        """
        redacted = []
        result = text

        for pattern, replacement in self._compiled:
            matches = pattern.findall(result)
            if matches:
                for match in matches:
                    redacted.append(f"{replacement}: {match[:10]}...")
                result = pattern.sub(replacement, result)

        return result, redacted

    def check(self, text: str) -> GuardrailResult:
        """检查输出是否包含敏感信息"""
        sanitized, redacted = self.sanitize(text)
        if redacted:
            return GuardrailResult(
                blocked=False,  # 不拦截，只清洗
                reason=f"Sanitized {len(redacted)} sensitive items",
                severity="warning",
                rule_id="OUTPUT-SENSITIVE",
                sanitized=sanitized,
            )
        return GuardrailResult(sanitized=text)


# ═══════════════════════════════════════════════════════════════
# Command Blocker — 危险命令拦截
# ═══════════════════════════════════════════════════════════════

class CommandBlocker:
    """
    拦截危险系统命令
    
    三级分类：
    - CRITICAL: 绝对禁止（rm -rf /、mkfs、dd）
    - DANGEROUS: 需确认（chmod 777、wget 到可执行路径）
    - CAUTION: 警告但允许（nmap 无限速、大范围扫描）
    """

    # 绝对禁止的命令模式
    CRITICAL_PATTERNS = [
        (r'\brm\s+(-[rf]+\s+)*/', "删除根目录"),
        (r'\brm\s+(-[rf]+\s+)*~', "删除家目录"),
        (r'\bmkfs\b', "格式化磁盘"),
        (r'\bdd\s+.*of=/dev/', "直接写入设备"),
        (r'>\s*/dev/sd[a-z]', "覆盖磁盘"),
        (r'\b:(){ :\|:& };:', "Fork 炸弹"),
        (r'\bchmod\s+(-R\s+)?777\s+/', "递归 777 根目录"),
        (r'\bkill\s+-9\s+1\b', "杀死 init 进程"),
        (r'\bshutdown\b|\breboot\b|\bhalt\b', "关机/重启"),
        (r'\biptables\s+-F', "清空防火墙规则"),
        (r'\buserdel\b.*root', "删除 root"),
        (r'curl.*\|\s*(bash|sh|python)', "管道执行远程脚本（需审查）"),
    ]

    # 需要确认的命令模式
    DANGEROUS_PATTERNS = [
        (r'\bchmod\s+777\b', "设置 777 权限"),
        (r'\bchown\s+-R\b', "递归修改所有者"),
        (r'\bwget\s.*-O\s*/usr/', "下载到系统目录"),
        (r'\bcurl\s.*-o\s*/usr/', "下载到系统目录"),
        (r'\bsqlmap\b', "自动化 SQL 注入（需授权确认）"),
        (r'\bhydra\b.*-t\s*([5-9]\d|\d{3})', "暴力破解高线程"),
        (r'\bnmap\s.*-T5\b', "Nmap 最高速扫描"),
        (r'\bmetasploit\b|\bmsfconsole\b', "Metasploit（需授权）"),
        (r'\bgit\s+push\s+.*--force', "强制推送"),
        (r'\bgit\s+reset\s+--hard', "硬重置"),
    ]

    # 警告但允许
    CAUTION_PATTERNS = [
        (r'\bnmap\s.*-p-\b', "Nmap 全端口扫描（可能触发告警）"),
        (r'\bnikto\b', "Web 扫描器（流量明显）"),
        (r'\bdirbuster\b|\bgobuster\b|\bffuf\b.*-w\b', "目录爆破（流量大）"),
        (r'\bnuclei\s.*-severity\s+critical', "高危模板扫描"),
    ]

    def __init__(self, allowed_commands: List[str] = None):
        self.allowed = set(allowed_commands or [])
        self._critical = [(re.compile(p, re.IGNORECASE), desc) for p, desc in self.CRITICAL_PATTERNS]
        self._dangerous = [(re.compile(p, re.IGNORECASE), desc) for p, desc in self.DANGEROUS_PATTERNS]
        self._caution = [(re.compile(p, re.IGNORECASE), desc) for p, desc in self.CAUTION_PATTERNS]

    def check(self, command: str) -> GuardrailResult:
        """检查命令安全性"""
        if not command:
            return GuardrailResult()

        # 白名单放行
        cmd_base = command.strip().split()[0] if command.strip() else ""
        if cmd_base in self.allowed:
            return GuardrailResult()

        # Critical — 绝对禁止
        for pattern, desc in self._critical:
            if pattern.search(command):
                return GuardrailResult(
                    blocked=True,
                    reason=f"CRITICAL: {desc}",
                    severity="critical",
                    rule_id="CMD-CRITICAL",
                    original_input=command,
                )

        # Dangerous — 需确认
        for pattern, desc in self._dangerous:
            if pattern.search(command):
                return GuardrailResult(
                    blocked=True,
                    reason=f"DANGEROUS: {desc}（需人工确认）",
                    severity="warning",
                    rule_id="CMD-DANGEROUS",
                    original_input=command,
                )

        # Caution — 警告
        for pattern, desc in self._caution:
            if pattern.search(command):
                return GuardrailResult(
                    blocked=False,
                    reason=f"CAUTION: {desc}",
                    severity="info",
                    rule_id="CMD-CAUTION",
                    original_input=command,
                )

        return GuardrailResult()


# ═══════════════════════════════════════════════════════════════
# Tripwire Detector — 蜜罐/陷阱检测
# ═══════════════════════════════════════════════════════════════

class TripwireDetector:
    """
    检测目标是否为蜜罐或陷阱
    
    检测信号：
    1. 过于容易的漏洞（诱饵）
    2. 异常响应模式（所有请求都成功）
    3. 已知蜜罐指纹
    4. 可疑的开放端口组合
    """

    HONEYPOT_SIGNATURES = [
        # Web 蜜罐
        "Glastopf", "Cowrie", "Kippo", "Dionaea",
        "HoneyPress", "WordPot", "HonSSH",
        # 响应特征
        "It works!", "Apache2 Ubuntu Default Page",
    ]

    SUSPICIOUS_PATTERNS = [
        # 所有常见漏洞都"存在"
        "too_many_vulns",
        # 响应时间完全一致
        "uniform_response_time",
        # 默认凭据全部有效
        "all_defaults_work",
    ]

    def check_response(self, url: str, status: int, body: str, response_time: float) -> GuardrailResult:
        """检查单个响应是否有蜜罐特征"""
        # 检查蜜罐签名
        for sig in self.HONEYPOT_SIGNATURES:
            if sig.lower() in body.lower():
                return GuardrailResult(
                    blocked=False,
                    reason=f"Honeypot signature detected: {sig}",
                    severity="warning",
                    rule_id="TRIPWIRE-SIGNATURE",
                )

        return GuardrailResult()

    def check_scan_results(self, results: List[Dict]) -> GuardrailResult:
        """
        分析扫描结果是否异常
        
        蜜罐信号：
        - 所有端口都开放
        - 所有默认密码都能登录
        - 漏洞密度异常高
        """
        if not results:
            return GuardrailResult()

        # 漏洞密度检查
        vuln_count = len([r for r in results if r.get("type") == "vulnerability"])
        if vuln_count > 50:
            return GuardrailResult(
                blocked=False,
                reason=f"异常高漏洞密度 ({vuln_count})，可能是蜜罐",
                severity="warning",
                rule_id="TRIPWIRE-DENSITY",
            )

        # 开放端口数检查
        open_ports = [r for r in results if r.get("type") == "open_port"]
        if len(open_ports) > 100:
            return GuardrailResult(
                blocked=False,
                reason=f"异常多开放端口 ({len(open_ports)})，可能是蜜罐",
                severity="warning",
                rule_id="TRIPWIRE-PORTS",
            )

        return GuardrailResult()


# ═══════════════════════════════════════════════════════════════
# SafetyGate — 统一安全门控
# ═══════════════════════════════════════════════════════════════

class SafetyGate:
    """
    统一安全门控 — 所有安全检查的入口
    
    用法：
        gate = SafetyGate()
        
        # 每次执行前检查
        result = gate.check_command(cmd)
        if result.blocked:
            logger.warning(f"拦截: {result.reason}")
            return
        
        # 检查用户输入
        result = gate.check_input(user_msg)
        
        # 清洗输出
        clean_output = gate.sanitize_output(response)
    """

    def __init__(self, config: Optional[GuardrailConfig] = None):
        self.config = config or GuardrailConfig()
        self.input_guard = InputGuardrail(strict=self.config.strict_mode)
        self.output_guard = OutputGuardrail()
        self.command_blocker = CommandBlocker(allowed_commands=self.config.allowed_commands)
        self.tripwire = TripwireDetector()
        # 审计日志
        self._audit_log: List[Dict] = []
        self._blocked_count = 0
        self._total_checks = 0

    def check_input(self, text: str) -> GuardrailResult:
        """检查用户/外部输入"""
        self._total_checks += 1
        if not self.config.enable_input_guard:
            return GuardrailResult()

        result = self.input_guard.check(text)
        if result.blocked:
            self._blocked_count += 1
            self._log_audit("INPUT_BLOCKED", result)
        return result

    def check_command(self, command: str) -> GuardrailResult:
        """检查待执行的命令"""
        self._total_checks += 1
        if not self.config.enable_command_blocker:
            return GuardrailResult()

        result = self.command_blocker.check(command)
        if result.blocked:
            self._blocked_count += 1
            self._log_audit("CMD_BLOCKED", result)
        return result

    def sanitize_output(self, text: str) -> str:
        """清洗输出中的敏感信息"""
        if not self.config.enable_output_guard:
            return text

        result = self.output_guard.check(text)
        if result.sanitized:
            return result.sanitized
        return text

    def check_tripwire(self, url: str = "", status: int = 0, body: str = "", response_time: float = 0) -> GuardrailResult:
        """检查蜜罐特征"""
        if not self.config.enable_tripwire:
            return GuardrailResult()
        return self.tripwire.check_response(url, status, body, response_time)

    def get_stats(self) -> Dict:
        """获取安全统计"""
        return {
            "total_checks": self._total_checks,
            "blocked_count": self._blocked_count,
            "block_rate": f"{self._blocked_count / max(self._total_checks, 1) * 100:.1f}%",
            "recent_blocks": self._audit_log[-10:],
        }

    def _log_audit(self, event: str, result: GuardrailResult):
        """记录审计日志"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "severity": result.severity,
            "rule_id": result.rule_id,
            "reason": result.reason,
            "input_excerpt": result.original_input[:100] if result.original_input else "",
        }
        self._audit_log.append(entry)

        # 写入审计文件
        if self.config.audit_file:
            try:
                import json
                with open(self.config.audit_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except IOError:
                pass
