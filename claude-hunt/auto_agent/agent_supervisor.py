#!/usr/bin/env python3
"""
Agent Supervisor — Agent 监督 / 死循环检测
移植自 PentAGI 框架的 Advanced Agent Supervision

功能：
1. LoopDetector: 检测重复动作/死循环（同一命令连续执行）
2. ProgressMonitor: 检测长时间无进展
3. MentorIntervention: 自动纠正偏航的 Agent
4. ResourceGuard: 请求数/token 用量/时间预算控制
5. PatternDetector: 识别低效模式并建议优化

用法：
    from agent_supervisor import AgentSupervisor
    
    supervisor = AgentSupervisor(max_requests=500, max_duration=3600)
    
    # 每次 Agent 执行动作前
    action = {"tool": "nmap", "args": "-sV target.com", "output": "..."}
    verdict = supervisor.observe(action)
    
    if verdict.should_stop:
        print(f"Agent 停止: {verdict.reason}")
    elif verdict.suggestion:
        print(f"建议: {verdict.suggestion}")
"""

import time
import hashlib
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Deque
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class SupervisorVerdict:
    """监督判决"""
    should_stop: bool = False
    should_pause: bool = False
    reason: str = ""
    suggestion: str = ""
    severity: str = "info"  # info/warning/critical
    intervention_type: str = ""  # loop/stall/resource/pattern


@dataclass
class ActionRecord:
    """动作记录"""
    tool: str = ""
    args: str = ""
    output_hash: str = ""
    output_length: int = 0
    timestamp: float = 0
    success: bool = True
    duration: float = 0


@dataclass
class SupervisorConfig:
    """监督配置"""
    # 死循环检测
    max_identical_actions: int = 3  # 连续相同动作超过此数 = 死循环
    max_similar_actions: int = 5  # 相似动作（同工具不同参数）
    loop_window: int = 10  # 检测窗口大小
    # 进展检测
    stall_timeout: int = 120  # 秒，无新发现超过此时间 = 停滞
    min_progress_interval: int = 60  # 至少每 N 秒要有进展
    # 资源预算
    max_requests: int = 500
    max_duration: int = 3600  # 秒
    max_errors: int = 20  # 连续错误
    max_token_budget: int = 0  # 0=不限制
    # 模式检测
    detect_inefficient_patterns: bool = True
    # 自动干预
    auto_intervene: bool = True
    intervention_cooldown: int = 30  # 两次干预之间最少间隔


# ═══════════════════════════════════════════════════════════════
# Loop Detector — 死循环检测
# ═══════════════════════════════════════════════════════════════

class LoopDetector:
    """
    检测 Agent 陷入死循环
    
    检测方式：
    1. 完全相同的动作连续出现
    2. 输出完全相同（同一个错误反复触发）
    3. 工具-参数模式循环（ABCABC...）
    """

    def __init__(self, max_identical: int = 3, max_similar: int = 5, window: int = 10):
        self.max_identical = max_identical
        self.max_similar = max_similar
        self.window = window
        self._history: Deque[ActionRecord] = deque(maxlen=window * 2)

    def check(self, action: ActionRecord) -> Optional[SupervisorVerdict]:
        """检查是否陷入循环"""
        self._history.append(action)

        if len(self._history) < 2:
            return None

        # 1. 完全相同动作检测
        identical_count = self._count_identical_tail(action)
        if identical_count >= self.max_identical:
            return SupervisorVerdict(
                should_stop=True,
                reason=f"死循环: 相同动作连续执行 {identical_count} 次 ({action.tool} {action.args[:50]})",
                severity="critical",
                intervention_type="loop",
                suggestion="尝试不同的方法或参数，或跳过当前目标",
            )

        # 2. 相同输出检测（同一个错误反复出现）
        if action.output_hash:
            same_output_count = sum(
                1 for r in list(self._history)[-self.window:]
                if r.output_hash == action.output_hash and r.output_hash != ""
            )
            if same_output_count >= self.max_identical:
                return SupervisorVerdict(
                    should_pause=True,
                    reason=f"重复输出: 相同响应出现 {same_output_count} 次",
                    severity="warning",
                    intervention_type="loop",
                    suggestion="目标可能无响应变化，建议换一个攻击向量",
                )

        # 3. 同工具高频调用
        recent = list(self._history)[-self.window:]
        tool_counts = Counter(r.tool for r in recent)
        most_common_tool, count = tool_counts.most_common(1)[0]
        if count >= self.max_similar and most_common_tool == action.tool:
            return SupervisorVerdict(
                should_pause=True,
                reason=f"工具过度使用: {most_common_tool} 在最近 {self.window} 步中调用了 {count} 次",
                severity="warning",
                intervention_type="loop",
                suggestion=f"考虑切换到其他工具，{most_common_tool} 可能不适合当前目标",
            )

        # 4. 周期性循环检测（ABCABC...）
        cycle = self._detect_cycle(recent)
        if cycle:
            return SupervisorVerdict(
                should_pause=True,
                reason=f"周期性循环: 模式 [{' → '.join(cycle)}] 重复出现",
                severity="warning",
                intervention_type="loop",
                suggestion="Agent 在几个动作间循环，需要打破模式",
            )

        return None

    def _count_identical_tail(self, action: ActionRecord) -> int:
        """计算尾部连续相同动作数"""
        count = 0
        for record in reversed(list(self._history)):
            if record.tool == action.tool and record.args == action.args:
                count += 1
            else:
                break
        return count

    def _detect_cycle(self, records: List[ActionRecord]) -> Optional[List[str]]:
        """检测工具调用的周期性模式"""
        if len(records) < 6:
            return None

        tools = [r.tool for r in records]
        # 检测长度 2-4 的循环
        for cycle_len in range(2, 5):
            if len(tools) < cycle_len * 3:
                continue
            pattern = tools[-cycle_len:]
            # 检查是否重复了至少 3 次
            repeats = 0
            for i in range(len(tools) - cycle_len, -1, -cycle_len):
                if tools[i:i + cycle_len] == pattern:
                    repeats += 1
                else:
                    break
            if repeats >= 3:
                return pattern

        return None


# ═══════════════════════════════════════════════════════════════
# Progress Monitor — 进展监控
# ═══════════════════════════════════════════════════════════════

class ProgressMonitor:
    """
    监控 Agent 是否在取得进展
    
    "进展"的定义：
    - 发现新的 URL/参数/漏洞
    - 成功执行新类型的操作
    - 输出有新信息（不同于之前的输出）
    """

    def __init__(self, stall_timeout: int = 120):
        self.stall_timeout = stall_timeout
        self._last_progress_time = time.time()
        self._seen_outputs: set = set()
        self._findings_count = 0

    def update_findings(self, findings: Dict):
        """更新发现计数"""
        new_count = sum(len(v) for v in findings.values() if isinstance(v, list))
        if new_count > self._findings_count:
            self._findings_count = new_count
            self._last_progress_time = time.time()

    def check(self, action: ActionRecord) -> Optional[SupervisorVerdict]:
        """检查是否停滞"""
        # 新输出 = 进展
        if action.output_hash and action.output_hash not in self._seen_outputs:
            self._seen_outputs.add(action.output_hash)
            self._last_progress_time = time.time()
            return None

        # 检查停滞时间
        stall_duration = time.time() - self._last_progress_time
        if stall_duration > self.stall_timeout:
            return SupervisorVerdict(
                should_pause=True,
                reason=f"停滞 {int(stall_duration)}s 无新发现",
                severity="warning",
                intervention_type="stall",
                suggestion="建议: 1) 换目标 2) 换攻击方式 3) 检查网络连通性",
            )

        return None


# ═══════════════════════════════════════════════════════════════
# Resource Guard — 资源预算控制
# ═══════════════════════════════════════════════════════════════

class ResourceGuard:
    """控制资源使用不超预算"""

    def __init__(self, max_requests: int = 500, max_duration: int = 3600, max_errors: int = 20):
        self.max_requests = max_requests
        self.max_duration = max_duration
        self.max_errors = max_errors
        self._start_time = time.time()
        self._request_count = 0
        self._error_count = 0
        self._consecutive_errors = 0

    def record(self, success: bool = True):
        """记录一次请求"""
        self._request_count += 1
        if not success:
            self._error_count += 1
            self._consecutive_errors += 1
        else:
            self._consecutive_errors = 0

    def check(self) -> Optional[SupervisorVerdict]:
        """检查资源预算"""
        elapsed = time.time() - self._start_time

        if self._request_count >= self.max_requests:
            return SupervisorVerdict(
                should_stop=True,
                reason=f"请求数达到上限 ({self._request_count}/{self.max_requests})",
                severity="critical",
                intervention_type="resource",
            )

        if elapsed >= self.max_duration:
            return SupervisorVerdict(
                should_stop=True,
                reason=f"运行时间达到上限 ({int(elapsed)}s/{self.max_duration}s)",
                severity="critical",
                intervention_type="resource",
            )

        if self._consecutive_errors >= self.max_errors:
            return SupervisorVerdict(
                should_stop=True,
                reason=f"连续错误达到上限 ({self._consecutive_errors}/{self.max_errors})",
                severity="critical",
                intervention_type="resource",
                suggestion="目标可能已下线或 IP 被封",
            )

        # 警告阈值（80%）
        if self._request_count >= self.max_requests * 0.8:
            return SupervisorVerdict(
                should_pause=False,
                reason=f"请求数接近上限 ({self._request_count}/{self.max_requests})",
                severity="info",
                intervention_type="resource",
            )

        return None

    def get_remaining(self) -> Dict:
        """获取剩余预算"""
        elapsed = time.time() - self._start_time
        return {
            "requests_remaining": self.max_requests - self._request_count,
            "time_remaining_s": max(0, self.max_duration - int(elapsed)),
            "error_budget": self.max_errors - self._consecutive_errors,
        }


# ═══════════════════════════════════════════════════════════════
# Pattern Detector — 低效模式识别
# ═══════════════════════════════════════════════════════════════

class PatternDetector:
    """
    识别 Agent 的低效行为模式并建议优化
    
    已知低效模式：
    1. 对已知不存在的路径反复探测
    2. 用错误的 payload 类型（如对 PostgreSQL 用 MySQL 语法）
    3. 忽略 WAF 反馈继续用被拦截的 payload
    4. 在已确认安全的参数上反复测试
    """

    KNOWN_PATTERNS = [
        {
            "id": "wrong_db_syntax",
            "description": "数据库语法不匹配",
            "indicators": ["mysql", "syntax error", "postgresql"],
            "suggestion": "检测到 PostgreSQL 错误，但在使用 MySQL 语法。请切换到 PostgreSQL payload。",
        },
        {
            "id": "waf_blocked_repeat",
            "description": "WAF 拦截后继续使用相同 payload",
            "indicators": ["403", "blocked", "forbidden"],
            "suggestion": "WAF 持续拦截，建议: 1) 使用编码绕过 2) 换参数 3) 换 HTTP 方法",
        },
        {
            "id": "timeout_flood",
            "description": "大量超时请求",
            "indicators": ["timeout", "timed out"],
            "suggestion": "频繁超时，建议降低并发/增加延迟，或检查目标是否在线",
        },
    ]

    def __init__(self):
        self._output_keywords: Counter = Counter()

    def analyze(self, action: ActionRecord, output: str = "") -> Optional[SupervisorVerdict]:
        """分析动作输出是否匹配低效模式"""
        if not output:
            return None

        output_lower = output.lower()

        # 提取关键词
        for pattern in self.KNOWN_PATTERNS:
            match_count = sum(1 for ind in pattern["indicators"] if ind in output_lower)
            if match_count >= 2:
                return SupervisorVerdict(
                    should_pause=False,
                    reason=f"检测到低效模式: {pattern['description']}",
                    severity="info",
                    intervention_type="pattern",
                    suggestion=pattern["suggestion"],
                )

        return None


# ═══════════════════════════════════════════════════════════════
# Agent Supervisor — 统一入口
# ═══════════════════════════════════════════════════════════════

class AgentSupervisor:
    """
    Agent 监督系统 — 统一入口
    
    整合所有检测器，对每个 Agent 动作做综合判断。
    
    用法：
        supervisor = AgentSupervisor(max_requests=500)
        
        # Agent 每次执行动作后调用
        verdict = supervisor.observe({
            "tool": "nmap",
            "args": "-sV 192.168.1.1",
            "output": "PORT STATE SERVICE...",
            "success": True,
            "duration": 5.2,
        })
        
        if verdict.should_stop:
            break
        elif verdict.suggestion:
            # 将建议注入 Agent 的下一轮 prompt
            inject_suggestion(verdict.suggestion)
    """

    def __init__(self, config: Optional[SupervisorConfig] = None, **kwargs):
        # 支持快捷参数
        self.config = config or SupervisorConfig(**{
            k: v for k, v in kwargs.items()
            if k in SupervisorConfig.__dataclass_fields__
        })

        self.loop_detector = LoopDetector(
            max_identical=self.config.max_identical_actions,
            max_similar=self.config.max_similar_actions,
            window=self.config.loop_window,
        )
        self.progress_monitor = ProgressMonitor(stall_timeout=self.config.stall_timeout)
        self.resource_guard = ResourceGuard(
            max_requests=self.config.max_requests,
            max_duration=self.config.max_duration,
            max_errors=self.config.max_errors,
        )
        self.pattern_detector = PatternDetector()

        self._last_intervention_time = 0
        self._intervention_count = 0
        self._action_count = 0

    def observe(self, action_dict: Dict) -> SupervisorVerdict:
        """
        观察 Agent 的一次动作并给出判决
        
        Args:
            action_dict: {
                "tool": str,
                "args": str,
                "output": str,
                "success": bool,
                "duration": float,
            }
        """
        self._action_count += 1

        # 构建动作记录
        output = action_dict.get("output", "")
        action = ActionRecord(
            tool=action_dict.get("tool", ""),
            args=action_dict.get("args", ""),
            output_hash=hashlib.md5(output.encode()).hexdigest()[:16] if output else "",
            output_length=len(output),
            timestamp=time.time(),
            success=action_dict.get("success", True),
            duration=action_dict.get("duration", 0),
        )

        # 记录资源使用
        self.resource_guard.record(action.success)

        # 依次检查各检测器（优先级从高到低）
        checks = [
            self.resource_guard.check(),
            self.loop_detector.check(action),
            self.progress_monitor.check(action),
        ]

        if self.config.detect_inefficient_patterns:
            checks.append(self.pattern_detector.analyze(action, output))

        # 返回最高优先级的判决
        for verdict in checks:
            if verdict and (verdict.should_stop or verdict.should_pause):
                # 干预冷却
                if time.time() - self._last_intervention_time < self.config.intervention_cooldown:
                    if not verdict.should_stop:
                        continue  # 非致命的跳过（冷却中）

                self._last_intervention_time = time.time()
                self._intervention_count += 1
                return verdict

        # 信息性建议（不阻断）
        for verdict in checks:
            if verdict and verdict.suggestion:
                return verdict

        return SupervisorVerdict()

    def update_findings(self, findings: Dict):
        """通知发现更新（用于进展监控）"""
        self.progress_monitor.update_findings(findings)

    def get_stats(self) -> Dict:
        """获取监督统计"""
        return {
            "total_actions": self._action_count,
            "interventions": self._intervention_count,
            "resource_remaining": self.resource_guard.get_remaining(),
            "intervention_rate": f"{self._intervention_count / max(self._action_count, 1) * 100:.1f}%",
        }

    def reset(self):
        """重置（新目标时调用）"""
        self.loop_detector = LoopDetector(
            max_identical=self.config.max_identical_actions,
            max_similar=self.config.max_similar_actions,
            window=self.config.loop_window,
        )
        self.progress_monitor = ProgressMonitor(stall_timeout=self.config.stall_timeout)
        self.resource_guard = ResourceGuard(
            max_requests=self.config.max_requests,
            max_duration=self.config.max_duration,
            max_errors=self.config.max_errors,
        )
        self._action_count = 0
        self._intervention_count = 0
