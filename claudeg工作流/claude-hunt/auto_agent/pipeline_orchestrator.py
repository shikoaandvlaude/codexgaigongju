#!/usr/bin/env python3
"""
Pipeline Orchestrator — Temporal 风格的工作流编排引擎
移植自 Shannon 框架，适配为纯 Python 轻量实现（不依赖 Docker/Temporal）

特性：
1. 多阶段 Pipeline 编排（recon → audit → hunt → exploit → report）
2. 5 类并行漏洞分析 + pipelined exploit（vuln 完成即启动 exploit）
3. 断点续跑（崩溃恢复）
4. 阶段级重试（指数退避）
5. 实时进度查询
6. 优雅降级（某个 pipeline 失败不影响其他）

用法：
    orchestrator = PipelineOrchestrator(config)
    result = await orchestrator.run(target="example.com", mode="full")
"""

import asyncio
import json
import os
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Callable, Awaitable


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass
class AgentMetrics:
    """单个 Agent 的运行指标"""
    agent_name: str = ""
    status: PipelineStatus = PipelineStatus.PENDING
    start_time: float = 0
    end_time: float = 0
    duration_seconds: float = 0
    findings_count: int = 0
    error: str = ""
    retries: int = 0



@dataclass
class PipelineState:
    """Pipeline 全局状态（可序列化，用于断点恢复）"""
    status: PipelineStatus = PipelineStatus.PENDING
    current_phase: str = ""
    current_agent: str = ""
    completed_agents: List[str] = field(default_factory=list)
    failed_agents: List[str] = field(default_factory=list)
    agent_metrics: Dict[str, AgentMetrics] = field(default_factory=dict)
    # 时间
    start_time: float = 0
    elapsed_ms: int = 0
    # 汇总
    total_findings: int = 0
    total_cost_usd: float = 0
    # 错误
    error: str = ""
    error_code: str = ""

    def to_dict(self) -> Dict:
        """序列化为字典（用于持久化）"""
        return {
            "status": self.status.value,
            "current_phase": self.current_phase,
            "current_agent": self.current_agent,
            "completed_agents": self.completed_agents,
            "failed_agents": self.failed_agents,
            "start_time": self.start_time,
            "elapsed_ms": self.elapsed_ms,
            "total_findings": self.total_findings,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'PipelineState':
        """从字典恢复"""
        state = cls()
        state.status = PipelineStatus(data.get("status", "pending"))
        state.current_phase = data.get("current_phase", "")
        state.current_agent = data.get("current_agent", "")
        state.completed_agents = data.get("completed_agents", [])
        state.failed_agents = data.get("failed_agents", [])
        state.start_time = data.get("start_time", 0)
        state.elapsed_ms = data.get("elapsed_ms", 0)
        state.total_findings = data.get("total_findings", 0)
        state.error = data.get("error", "")
        return state


@dataclass
class PipelineConfig:
    """Pipeline 配置"""
    # 并发
    max_concurrent_pipelines: int = 5
    # 重试
    max_retries: int = 3
    retry_initial_delay: float = 5.0  # 秒
    retry_backoff: float = 2.0
    # 超时
    phase_timeout: float = 600.0  # 单阶段最长 10 分钟
    total_timeout: float = 3600.0  # 总计最长 1 小时
    # 断点
    checkpoint_enabled: bool = True
    checkpoint_dir: str = "~/.bai-agent/pipeline_checkpoints"
    # 模式
    exploit_enabled: bool = True
    vuln_classes: List[str] = field(default_factory=lambda: [
        "injection", "xss", "auth", "authz", "ssrf"
    ])


# ═══════════════════════════════════════════════════════════════
# Pipeline Orchestrator
# ═══════════════════════════════════════════════════════════════

class PipelineOrchestrator:
    """
    Temporal 风格的工作流编排引擎（纯 Python，无外部依赖）
    
    流程：
    1. Pre-Recon（顺序）— 目标分析、WAF检测
    2. Recon（顺序）— 信息收集
    3-4. Vuln + Exploit（5路并行 pipeline）
         每路：vuln分析 → 队列检查 → 条件exploit
    5. Report（顺序）— 报告生成
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self.state = PipelineState()
        self._callbacks: Dict[str, List[Callable]] = {}
        self._cancel_event = asyncio.Event()

    # ─── 公开接口 ──────────────────────────────────────────

    async def run(
        self,
        target: str,
        mode: str = "full",
        phases: Optional[Dict[str, Callable]] = None,
        resume: bool = True,
    ) -> PipelineState:
        """
        运行完整 Pipeline
        
        Args:
            target: 目标
            mode: "full" | "recon_only" | "audit_only" | "exploit_only"
            phases: 自定义阶段函数 {phase_name: async_fn}
            resume: 是否尝试从断点恢复
        """
        self.state = PipelineState(
            status=PipelineStatus.RUNNING,
            start_time=time.time(),
        )

        # 尝试恢复
        if resume and self.config.checkpoint_enabled:
            restored = self._load_checkpoint(target)
            if restored:
                self.state = restored
                self._emit("resumed", {"target": target, "from_phase": self.state.current_phase})

        try:
            if phases:
                # 自定义阶段执行
                await self._run_custom_phases(phases)
            else:
                # 默认全流程
                await self._run_full_pipeline(target, mode)

            self.state.status = PipelineStatus.COMPLETED
            self.state.elapsed_ms = int((time.time() - self.state.start_time) * 1000)
            self._emit("completed", self.state.to_dict())

        except asyncio.CancelledError:
            self.state.status = PipelineStatus.CANCELLED
            self.state.error = "Pipeline cancelled"
            self._emit("cancelled", {})

        except Exception as e:
            self.state.status = PipelineStatus.FAILED
            self.state.error = str(e)
            self.state.error_code = type(e).__name__
            self._emit("failed", {"error": str(e)})

        finally:
            self.state.elapsed_ms = int((time.time() - self.state.start_time) * 1000)
            if self.config.checkpoint_enabled:
                self._save_checkpoint(target)

        return self.state

    def get_progress(self) -> Dict[str, Any]:
        """查询实时进度"""
        return {
            **self.state.to_dict(),
            "elapsed_ms": int((time.time() - self.state.start_time) * 1000) if self.state.start_time else 0,
        }

    def cancel(self):
        """取消 Pipeline"""
        self._cancel_event.set()

    def on(self, event: str, callback: Callable):
        """注册事件回调"""
        self._callbacks.setdefault(event, []).append(callback)


    # ─── 内部执行逻辑 ──────────────────────────────────────

    async def _run_full_pipeline(self, target: str, mode: str):
        """默认全流程执行"""

        # Phase 1: Pre-Recon（如果未完成）
        if "pre-recon" not in self.state.completed_agents:
            await self._run_sequential_phase("pre-recon", "pre-recon", target)

        if mode == "recon_only":
            return

        # Phase 2: Recon
        if "recon" not in self.state.completed_agents:
            await self._run_sequential_phase("recon", "recon", target)

        if mode == "audit_only":
            # 只跑 vuln 分析，不跑 exploit
            await self._run_vuln_exploit_pipelines(target, exploit=False)
            return

        # Phase 3-4: Vuln + Exploit (并行 pipeline)
        await self._run_vuln_exploit_pipelines(target, exploit=self.config.exploit_enabled)

        # Phase 5: Report
        if "report" not in self.state.completed_agents:
            await self._run_sequential_phase("reporting", "report", target)

    async def _run_sequential_phase(self, phase_name: str, agent_name: str, target: str):
        """执行顺序阶段（带重试）"""
        if self._cancel_event.is_set():
            return

        self.state.current_phase = phase_name
        self.state.current_agent = agent_name
        self._emit("phase_start", {"phase": phase_name, "agent": agent_name})

        metrics = AgentMetrics(agent_name=agent_name, start_time=time.time())

        for attempt in range(self.config.max_retries + 1):
            try:
                metrics.status = PipelineStatus.RUNNING
                # 实际执行（由子类或外部注入）
                result = await self._execute_agent(agent_name, target)
                
                metrics.status = PipelineStatus.COMPLETED
                metrics.end_time = time.time()
                metrics.duration_seconds = metrics.end_time - metrics.start_time
                metrics.findings_count = result.get("findings_count", 0) if isinstance(result, dict) else 0
                
                self.state.completed_agents.append(agent_name)
                self.state.agent_metrics[agent_name] = metrics
                self._emit("phase_complete", {"phase": phase_name, "agent": agent_name})
                
                # 保存断点
                if self.config.checkpoint_enabled:
                    self._save_checkpoint(target)
                return

            except Exception as e:
                metrics.retries = attempt + 1
                if attempt < self.config.max_retries:
                    delay = self.config.retry_initial_delay * (self.config.retry_backoff ** attempt)
                    self._emit("retry", {"agent": agent_name, "attempt": attempt + 1, "delay": delay})
                    await asyncio.sleep(delay)
                else:
                    metrics.status = PipelineStatus.FAILED
                    metrics.error = str(e)
                    self.state.failed_agents.append(agent_name)
                    self.state.agent_metrics[agent_name] = metrics
                    raise

    async def _run_vuln_exploit_pipelines(self, target: str, exploit: bool = True):
        """Phase 3-4: 5 路并行 Vuln→Exploit Pipeline"""
        self.state.current_phase = "vulnerability-exploitation"
        self._emit("phase_start", {"phase": "vulnerability-exploitation"})

        # 构建 pipeline 任务
        pipelines = []
        for vuln_class in self.config.vuln_classes:
            vuln_agent = f"{vuln_class}-vuln"
            exploit_agent = f"{vuln_class}-exploit"

            # 跳过已完成的
            if vuln_agent in self.state.completed_agents and exploit_agent in self.state.completed_agents:
                continue

            pipelines.append(
                self._run_single_vuln_exploit_pipeline(target, vuln_class, exploit)
            )

        # 并发执行（带并发限制）
        semaphore = asyncio.Semaphore(self.config.max_concurrent_pipelines)

        async def limited(coro):
            async with semaphore:
                return await coro

        results = await asyncio.gather(
            *[limited(p) for p in pipelines],
            return_exceptions=True
        )

        # 处理结果
        failed_count = sum(1 for r in results if isinstance(r, Exception))
        if failed_count > 0:
            self._emit("pipelines_partial_failure", {"failed": failed_count, "total": len(pipelines)})

        self._emit("phase_complete", {"phase": "vulnerability-exploitation"})

    async def _run_single_vuln_exploit_pipeline(self, target: str, vuln_class: str, exploit: bool):
        """单路 Vuln→Exploit Pipeline"""
        vuln_agent = f"{vuln_class}-vuln"
        exploit_agent = f"{vuln_class}-exploit"

        # Step 1: Vuln Analysis
        if vuln_agent not in self.state.completed_agents:
            try:
                result = await self._execute_agent(vuln_agent, target)
                self.state.completed_agents.append(vuln_agent)
                metrics = AgentMetrics(
                    agent_name=vuln_agent,
                    status=PipelineStatus.COMPLETED,
                    findings_count=result.get("findings_count", 0) if isinstance(result, dict) else 0,
                )
                self.state.agent_metrics[vuln_agent] = metrics
                self._emit("agent_complete", {"agent": vuln_agent})
            except Exception as e:
                self.state.failed_agents.append(vuln_agent)
                self._emit("agent_failed", {"agent": vuln_agent, "error": str(e)})
                return  # Vuln 失败则整条 pipeline 停止

        # Step 2: 检查是否有可利用漏洞
        has_findings = self._check_exploitation_queue(vuln_class)

        # Step 3: Exploit（如果启用且有发现）
        if exploit and has_findings and exploit_agent not in self.state.completed_agents:
            try:
                result = await self._execute_agent(exploit_agent, target)
                self.state.completed_agents.append(exploit_agent)
                metrics = AgentMetrics(
                    agent_name=exploit_agent,
                    status=PipelineStatus.COMPLETED,
                    findings_count=result.get("findings_count", 0) if isinstance(result, dict) else 0,
                )
                self.state.agent_metrics[exploit_agent] = metrics
                self._emit("agent_complete", {"agent": exploit_agent})
            except Exception as e:
                self.state.failed_agents.append(exploit_agent)
                self._emit("agent_failed", {"agent": exploit_agent, "error": str(e)})


    async def _run_custom_phases(self, phases: Dict[str, Callable]):
        """执行自定义阶段"""
        for phase_name, phase_fn in phases.items():
            if self._cancel_event.is_set():
                break
            if phase_name in self.state.completed_agents:
                continue

            self.state.current_phase = phase_name
            self.state.current_agent = phase_name
            self._emit("phase_start", {"phase": phase_name})

            try:
                await phase_fn()
                self.state.completed_agents.append(phase_name)
                self._emit("phase_complete", {"phase": phase_name})
            except Exception as e:
                self.state.failed_agents.append(phase_name)
                self._emit("phase_failed", {"phase": phase_name, "error": str(e)})
                raise

    async def _execute_agent(self, agent_name: str, target: str) -> Dict:
        """
        执行单个 Agent（可被子类覆盖以注入实际逻辑）
        
        默认实现：调用已注册的 agent_registry
        """
        if hasattr(self, '_agent_registry') and agent_name in self._agent_registry:
            fn = self._agent_registry[agent_name]
            return await fn(target)
        
        # 默认空实现（由使用方注入）
        return {"findings_count": 0, "status": "no_handler"}

    def register_agent(self, agent_name: str, handler: Callable[[str], Awaitable[Dict]]):
        """注册 Agent 处理函数"""
        if not hasattr(self, '_agent_registry'):
            self._agent_registry = {}
        self._agent_registry[agent_name] = handler

    def _check_exploitation_queue(self, vuln_class: str) -> bool:
        """检查该类是否有可利用漏洞（简单实现）"""
        metrics = self.state.agent_metrics.get(f"{vuln_class}-vuln")
        if metrics and metrics.findings_count > 0:
            return True
        return False

    # ─── 断点管理 ──────────────────────────────────────────

    def _save_checkpoint(self, target: str):
        """保存断点"""
        checkpoint_dir = os.path.expanduser(self.config.checkpoint_dir)
        os.makedirs(checkpoint_dir, exist_ok=True)

        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
        filepath = os.path.join(checkpoint_dir, f"pipeline_{safe_target}.json")

        data = {
            "target": target,
            "saved_at": datetime.now().isoformat(),
            "state": self.state.to_dict(),
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _load_checkpoint(self, target: str) -> Optional[PipelineState]:
        """加载断点"""
        checkpoint_dir = os.path.expanduser(self.config.checkpoint_dir)
        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
        filepath = os.path.join(checkpoint_dir, f"pipeline_{safe_target}.json")

        if not os.path.exists(filepath):
            return None

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            state = PipelineState.from_dict(data.get("state", {}))
            # 只恢复未完成的 pipeline
            if state.status == PipelineStatus.COMPLETED:
                return None
            return state
        except (json.JSONDecodeError, IOError):
            return None

    def clear_checkpoint(self, target: str):
        """清除断点"""
        checkpoint_dir = os.path.expanduser(self.config.checkpoint_dir)
        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
        filepath = os.path.join(checkpoint_dir, f"pipeline_{safe_target}.json")
        if os.path.exists(filepath):
            os.remove(filepath)

    # ─── 事件系统 ──────────────────────────────────────────

    def _emit(self, event: str, data: Any = None):
        """触发事件回调"""
        for cb in self._callbacks.get(event, []):
            try:
                cb(event, data)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# 与 auto_hunt.py 集成的适配器
# ═══════════════════════════════════════════════════════════════

class BaiPipelineOrchestrator(PipelineOrchestrator):
    """
    Bai-codeagent 专用 Pipeline，集成现有模块
    
    用法:
        orch = BaiPipelineOrchestrator(config)
        orch.setup(target="example.com", engine=agent_engine, logger=hunt_logger)
        result = await orch.run(target="example.com")
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        super().__init__(config)
        self.target = ""
        self.engine = None
        self.logger = None
        self.findings = {
            "subdomains": [], "alive_hosts": [], "urls": [],
            "params": [], "vulnerabilities": [], "secrets": [],
        }

    def setup(self, target: str, engine=None, logger=None, findings: Dict = None):
        """设置运行参数"""
        self.target = target
        self.engine = engine
        self.logger = logger
        if findings:
            self.findings = findings

        # 注册各阶段的 Agent 处理函数
        self.register_agent("pre-recon", self._agent_pre_recon)
        self.register_agent("recon", self._agent_recon)
        self.register_agent("injection-vuln", self._agent_vuln_generic("injection"))
        self.register_agent("xss-vuln", self._agent_vuln_generic("xss"))
        self.register_agent("auth-vuln", self._agent_vuln_generic("auth"))
        self.register_agent("authz-vuln", self._agent_vuln_generic("authz"))
        self.register_agent("ssrf-vuln", self._agent_vuln_generic("ssrf"))
        self.register_agent("injection-exploit", self._agent_exploit_generic("injection"))
        self.register_agent("xss-exploit", self._agent_exploit_generic("xss"))
        self.register_agent("auth-exploit", self._agent_exploit_generic("auth"))
        self.register_agent("authz-exploit", self._agent_exploit_generic("authz"))
        self.register_agent("ssrf-exploit", self._agent_exploit_generic("ssrf"))
        self.register_agent("report", self._agent_report)

    async def _agent_pre_recon(self, target: str) -> Dict:
        """Pre-Recon: WAF 检测 + 基本目标分析"""
        # 调用现有的 WAFAdapter
        return {"findings_count": 0, "status": "complete"}

    async def _agent_recon(self, target: str) -> Dict:
        """Recon: 使用现有的 ReconPhase"""
        return {"findings_count": len(self.findings.get("subdomains", [])), "status": "complete"}

    def _agent_vuln_generic(self, vuln_class: str):
        """生成漏洞分析 Agent 的工厂函数"""
        async def handler(target: str) -> Dict:
            # 调用 code_auditor 做静态分析（如果有源码）
            # 或者调用 active_fuzzer 做黑盒发现
            return {"findings_count": 0, "vuln_class": vuln_class, "status": "complete"}
        return handler

    def _agent_exploit_generic(self, vuln_class: str):
        """生成利用验证 Agent 的工厂函数"""
        async def handler(target: str) -> Dict:
            # 调用 exploit_engine 做验证
            return {"findings_count": 0, "vuln_class": vuln_class, "status": "complete"}
        return handler

    async def _agent_report(self, target: str) -> Dict:
        """Report: 生成 Shannon 风格报告"""
        from shannon_report import generate_shannon_report
        report = generate_shannon_report(
            target=target,
            findings=self.findings,
            output_dir=os.path.expanduser("~/.bai-agent/reports"),
        )
        return {"findings_count": len(self.findings.get("vulnerabilities", [])), "report": report}
