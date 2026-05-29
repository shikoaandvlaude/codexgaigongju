#!/usr/bin/env python3
"""
Anti-Loop — 反死循环检测模块
参考 VulnClaw 的 anti_loop.py 设计
防止 AI Agent 在同一攻击路径上反复尝试浪费时间

核心能力：
1. 检测重复失败的攻击路径
2. 强制路径切换（连续N次失败 → 换方向）
3. 追踪失败目标（连续3次访问失败 → 标记为blocked）
4. 判断步骤是否有意义（区分"真进展"和"重复失败"）
5. 检测完成信号

来源: 参考 VulnClaw anti_loop.py + ctf_mode.py
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# 失败模式检测
# ═══════════════════════════════════════════════════════════════

FAILED_ACCESS_PATTERNS = [
    "SSLError", "ReadTimeout", "连接超时", "连接失败",
    "502 Bad Gateway", "502", "503", "无法访问", "访问失败",
    "Connection refused", "ConnectionError", "TimeoutError",
    "Name or service not known", "No route to host",
    "SSL: CERTIFICATE_VERIFY_FAILED", "超时", "timeout",
    "404 Not Found", "请求失败",
]

PROGRESS_KEYWORDS = [
    "发现", "确认", "漏洞", "端口", "路径", "泄露",
    "flag", "成功", "CVE", "绕过", "注入",
    "验证通过", "已确认", "200", "可访问",
    "敏感信息", "密钥", "token", "secret",
]

COMPLETION_SIGNALS = [
    "[DONE]", "[COMPLETE]", "渗透测试已完成",
    "测试结束", "任务完成", "报告生成完毕",
    "所有阶段完成", "PHASE_COMPLETE",
]


# ═══════════════════════════════════════════════════════════════
# 攻击路径检测
# ═══════════════════════════════════════════════════════════════

ATTACK_PATH_PATTERNS = {
    "sqli": ["sql注入", "union select", "information_schema", "sqli", "sqlmap", "盲注"],
    "xss": ["xss", "cross-site", "script", "alert(", "反射", "存储型"],
    "ssrf": ["ssrf", "内网", "127.0.0.1", "169.254.169.254", "metadata"],
    "idor": ["越权", "idor", "水平越权", "垂直越权", "权限", "unauthorized"],
    "rce": ["rce", "命令执行", "command", "eval(", "exec(", "system("],
    "lfi": ["文件包含", "lfi", "../../", "path traversal", "目录遍历"],
    "ssti": ["ssti", "模板注入", "{{", "${", "template"],
    "auth_bypass": ["认证绕过", "auth bypass", "登录绕过", "权限提升"],
    "race_condition": ["竞态", "race", "并发", "重复", "条件竞争"],
    "business_logic": ["业务逻辑", "支付", "金额", "价格", "数量", "订单"],
}


# ═══════════════════════════════════════════════════════════════
# Anti-Loop 状态
# ═══════════════════════════════════════════════════════════════

@dataclass
class AntiLoopState:
    """反死循环状态追踪"""
    # 当前攻击路径
    current_path: str = ""
    # 路径失败计数: {path_name: consecutive_failures}
    path_failures: dict = field(default_factory=dict)
    # 已封锁的路径（失败次数过多）
    blocked_paths: set = field(default_factory=set)
    # 失败目标: {hostname: failure_count}
    failed_targets: dict = field(default_factory=dict)
    # 已封锁的目标
    blocked_targets: set = field(default_factory=set)
    # 无意义步骤连续计数
    stale_rounds: int = 0
    # 总步骤数
    total_steps: int = 0
    # 有意义步骤数
    meaningful_steps: int = 0
    # 强制切换阈值
    max_path_failures: int = 3
    stale_threshold: int = 5


# ═══════════════════════════════════════════════════════════════
# Anti-Loop 引擎
# ═══════════════════════════════════════════════════════════════

class AntiLoopEngine:
    """
    反死循环引擎
    
    用法:
        anti_loop = AntiLoopEngine(config={"max_path_failures": 3})
        
        # 每步结束后调用
        action = anti_loop.analyze_step(step_output, step_result)
        
        if action["should_switch"]:
            # 强制切换攻击路径
            new_suggestions = action["suggestions"]
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.state = AntiLoopState(
            max_path_failures=self.config.get("max_path_failures", 3),
            stale_threshold=self.config.get("stale_threshold", 5),
        )

    def analyze_step(self, step_output: str, step_success: bool = True) -> dict:
        """
        分析一个步骤的输出，返回决策建议
        
        返回:
            {
                "should_switch": bool,      # 是否应该切换攻击路径
                "is_meaningful": bool,      # 这步是否有意义
                "current_path": str,        # 当前检测到的攻击路径
                "blocked_paths": list,      # 已被封锁的路径
                "suggestions": list,        # 建议的下一步方向
                "stale_rounds": int,        # 连续无进展轮数
                "completion_detected": bool, # 是否检测到完成信号
            }
        """
        self.state.total_steps += 1

        # 检测完成信号
        if is_completion_signal(step_output):
            return {
                "should_switch": False,
                "is_meaningful": True,
                "current_path": self.state.current_path,
                "blocked_paths": list(self.state.blocked_paths),
                "suggestions": [],
                "stale_rounds": 0,
                "completion_detected": True,
            }

        # 检测当前攻击路径
        detected_path = detect_attack_path(step_output)
        if detected_path:
            self.state.current_path = detected_path

        # 判断步骤是否有意义
        meaningful = is_meaningful_step(step_output)
        
        if meaningful:
            self.state.meaningful_steps += 1
            self.state.stale_rounds = 0
            # 路径有进展，重置该路径的失败计数
            if self.state.current_path:
                self.state.path_failures[self.state.current_path] = 0
        else:
            self.state.stale_rounds += 1
            # 路径无进展，增加失败计数
            if self.state.current_path:
                current_fails = self.state.path_failures.get(self.state.current_path, 0)
                self.state.path_failures[self.state.current_path] = current_fails + 1

        # 追踪失败目标
        failed_host = track_failed_target(step_output, self.state)

        # 判断是否需要切换
        should_switch = False
        suggestions = []

        # 条件1: 当前路径失败次数超过阈值
        if self.state.current_path:
            fails = self.state.path_failures.get(self.state.current_path, 0)
            if fails >= self.state.max_path_failures:
                should_switch = True
                self.state.blocked_paths.add(self.state.current_path)
                suggestions = self._suggest_alternatives()

        # 条件2: 连续无进展轮数超过阈值
        if self.state.stale_rounds >= self.state.stale_threshold:
            should_switch = True
            if not suggestions:
                suggestions = self._suggest_alternatives()

        return {
            "should_switch": should_switch,
            "is_meaningful": meaningful,
            "current_path": self.state.current_path,
            "blocked_paths": list(self.state.blocked_paths),
            "suggestions": suggestions,
            "stale_rounds": self.state.stale_rounds,
            "completion_detected": False,
        }

    def _suggest_alternatives(self) -> list[str]:
        """建议替代攻击路径"""
        all_paths = list(ATTACK_PATH_PATTERNS.keys())
        available = [p for p in all_paths if p not in self.state.blocked_paths]
        
        # 优先推荐未尝试过的路径
        untried = [p for p in available if p not in self.state.path_failures]
        if untried:
            return untried[:3]
        
        # 其次推荐失败次数最少的
        available.sort(key=lambda p: self.state.path_failures.get(p, 0))
        return available[:3]

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            "total_steps": self.state.total_steps,
            "meaningful_steps": self.state.meaningful_steps,
            "efficiency": (self.state.meaningful_steps / max(1, self.state.total_steps)) * 100,
            "stale_rounds": self.state.stale_rounds,
            "blocked_paths": list(self.state.blocked_paths),
            "blocked_targets": list(self.state.blocked_targets),
            "current_path": self.state.current_path,
        }

    def reset(self):
        """重置状态"""
        self.state = AntiLoopState(
            max_path_failures=self.state.max_path_failures,
            stale_threshold=self.state.stale_threshold,
        )


# ═══════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════

def detect_attack_path(output: str) -> Optional[str]:
    """从输出中检测当前攻击路径"""
    output_lower = output.lower()
    for path_name, keywords in ATTACK_PATH_PATTERNS.items():
        if any(kw in output_lower for kw in keywords):
            return path_name
    return None


def is_completion_signal(output: str) -> bool:
    """检测是否有完成信号"""
    return any(signal in output for signal in COMPLETION_SIGNALS)


def is_meaningful_step(output: str) -> bool:
    """判断步骤是否有意义"""
    # 有进展关键词
    if any(kw in output for kw in PROGRESS_KEYWORDS):
        return True
    # 全是失败关键词
    if any(kw in output for kw in FAILED_ACCESS_PATTERNS):
        return False
    # 默认认为有意义（避免过早切换）
    return True


def track_failed_target(output: str, state: AntiLoopState) -> Optional[str]:
    """追踪失败目标"""
    # 提取 hostname
    url_match = re.search(r'https?://([^\s/<>"\')\]]+)', output)
    if not url_match:
        return None
    
    hostname = url_match.group(1)
    is_failed = any(p in output for p in FAILED_ACCESS_PATTERNS)
    
    if is_failed:
        state.failed_targets[hostname] = state.failed_targets.get(hostname, 0) + 1
        if state.failed_targets[hostname] >= 3:
            state.blocked_targets.add(hostname)
            return hostname
    else:
        # 成功访问，减少失败计数
        if hostname in state.failed_targets:
            state.failed_targets[hostname] = max(0, state.failed_targets[hostname] - 1)
    
    return None
