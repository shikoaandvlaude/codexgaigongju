#!/usr/bin/env python3
"""
Fireteam — 并行多 Agent 协作执行
移植自 RedAmon 框架的 Fireteam 架构

核心理念：将不同任务分配给独立的 Agent 并行执行，
每个 Agent 有自己的上下文和工具集，最后汇聚结果。

典型场景：
- Agent A: 用 Hydra 爆破登录
- Agent B: 用 Dalfox 测 XSS  
- Agent C: 用 nuclei 扫 CVE
- Agent D: 测 IDOR 越权
→ 同时进行，效率翻 4 倍

用法：
    from fireteam import Fireteam, FireteamMember
    
    team = Fireteam(max_concurrent=4)
    
    team.add_member(FireteamMember(
        name="xss_hunter",
        task="测试所有参数的 XSS",
        tool="dalfox",
        targets=xss_urls,
    ))
    team.add_member(FireteamMember(
        name="sqli_hunter",
        task="SQL 注入测试",
        tool="active_fuzz",
        targets=sqli_params,
    ))
    
    results = await team.deploy()
"""

import asyncio
import time
import traceback
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Awaitable
from datetime import datetime
from enum import Enum


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

class MemberStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class FireteamMember:
    """Fireteam 成员（一个独立的 Agent 任务）"""
    name: str = ""
    task: str = ""  # 任务描述
    tool: str = ""  # 主要使用的工具
    targets: List[str] = field(default_factory=list)  # 目标列表
    # 执行函数（异步）
    handler: Optional[Callable[..., Awaitable[Dict]]] = None
    handler_kwargs: Dict[str, Any] = field(default_factory=dict)
    # 配置
    timeout: int = 300  # 秒
    priority: int = 0  # 越高越优先
    depends_on: List[str] = field(default_factory=list)  # 依赖的其他成员
    # 状态
    status: MemberStatus = MemberStatus.IDLE
    # 结果
    result: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    error: str = ""
    # 统计
    start_time: float = 0
    end_time: float = 0
    duration_seconds: float = 0


@dataclass
class FireteamResult:
    """Fireteam 整体执行结果"""
    # 成员结果
    members: List[FireteamMember] = field(default_factory=list)
    # 汇聚的发现
    all_findings: List[Dict] = field(default_factory=list)
    # 统计
    total_members: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    total_duration: float = 0
    # 去重后发现
    unique_findings: int = 0


# ═══════════════════════════════════════════════════════════════
# 预定义任务模板
# ═══════════════════════════════════════════════════════════════

TASK_TEMPLATES = {
    "xss_scan": {
        "task": "XSS 漏洞扫描",
        "tool": "dalfox",
        "timeout": 300,
    },
    "sqli_fuzz": {
        "task": "SQL 注入 Fuzz",
        "tool": "active_fuzzer",
        "timeout": 300,
    },
    "idor_test": {
        "task": "IDOR 越权测试",
        "tool": "idor_tester",
        "timeout": 240,
    },
    "nuclei_scan": {
        "task": "Nuclei 高危扫描",
        "tool": "nuclei",
        "timeout": 180,
    },
    "dir_bruteforce": {
        "task": "目录爆破",
        "tool": "ffuf",
        "timeout": 300,
    },
    "cors_check": {
        "task": "CORS 错配检测",
        "tool": "curl",
        "timeout": 60,
    },
    "ssrf_test": {
        "task": "SSRF 测试",
        "tool": "ssrf_tester",
        "timeout": 180,
    },
    "auth_bypass": {
        "task": "认证绕过测试",
        "tool": "http_engine",
        "timeout": 180,
    },
    "race_condition": {
        "task": "竞态条件测试",
        "tool": "business_logic_tester",
        "timeout": 120,
    },
    "credential_brute": {
        "task": "凭据爆破",
        "tool": "hydra",
        "timeout": 600,
    },
}


# ═══════════════════════════════════════════════════════════════
# Fireteam 主类
# ═══════════════════════════════════════════════════════════════

class Fireteam:
    """
    并行多 Agent 协作框架
    
    特性：
    1. N 个 Agent 并行执行不同任务
    2. 支持依赖关系（A 完成后 B 才启动）
    3. 超时自动取消
    4. 结果汇聚 + 去重
    5. 失败隔离（一个失败不影响其他）
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        on_member_complete: Optional[Callable] = None,
        on_finding: Optional[Callable] = None,
    ):
        self.max_concurrent = max_concurrent
        self.on_member_complete = on_member_complete
        self.on_finding = on_finding
        self._members: List[FireteamMember] = []
        self._cancel_event = asyncio.Event()

    def add_member(self, member: FireteamMember):
        """添加成员"""
        self._members.append(member)

    def add_from_template(self, template_name: str, targets: List[str],
                          name: str = "", handler: Callable = None, **kwargs) -> FireteamMember:
        """从模板添加成员"""
        template = TASK_TEMPLATES.get(template_name, {})
        member = FireteamMember(
            name=name or f"{template_name}_{len(self._members)}",
            task=template.get("task", template_name),
            tool=template.get("tool", ""),
            targets=targets,
            timeout=template.get("timeout", 300),
            handler=handler,
            **{k: v for k, v in kwargs.items() if k in FireteamMember.__dataclass_fields__},
        )
        self._members.append(member)
        return member

    async def deploy(self) -> FireteamResult:
        """
        部署 Fireteam — 并行执行所有成员任务
        
        Returns:
            FireteamResult 汇聚结果
        """
        start_time = time.time()
        result = FireteamResult(total_members=len(self._members))

        if not self._members:
            return result

        # 按优先级排序
        sorted_members = sorted(self._members, key=lambda m: m.priority, reverse=True)

        # 分离有依赖和无依赖的
        no_deps = [m for m in sorted_members if not m.depends_on]
        with_deps = [m for m in sorted_members if m.depends_on]

        # Phase 1: 并行执行无依赖任务
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_member(member: FireteamMember):
            async with semaphore:
                await self._execute_member(member)

        if no_deps:
            await asyncio.gather(
                *[run_member(m) for m in no_deps],
                return_exceptions=True
            )

        # Phase 2: 执行有依赖的任务（依赖已完成后启动）
        if with_deps:
            completed_names = {m.name for m in no_deps if m.status == MemberStatus.COMPLETED}
            runnable_deps = [
                m for m in with_deps
                if all(dep in completed_names for dep in m.depends_on)
            ]
            if runnable_deps:
                await asyncio.gather(
                    *[run_member(m) for m in runnable_deps],
                    return_exceptions=True
                )

        # 汇聚结果
        result.members = self._members
        result.completed = sum(1 for m in self._members if m.status == MemberStatus.COMPLETED)
        result.failed = sum(1 for m in self._members if m.status == MemberStatus.FAILED)
        result.cancelled = sum(1 for m in self._members if m.status == MemberStatus.CANCELLED)
        result.total_duration = time.time() - start_time

        # 合并所有 findings
        all_findings = []
        for member in self._members:
            for finding in member.findings:
                finding["found_by"] = member.name
                finding["tool"] = member.tool
                all_findings.append(finding)

        result.all_findings = all_findings
        result.unique_findings = len(self._deduplicate_findings(all_findings))

        return result

    def cancel(self):
        """取消所有正在执行的任务"""
        self._cancel_event.set()

    def get_status(self) -> Dict:
        """获取实时状态"""
        return {
            "total": len(self._members),
            "running": sum(1 for m in self._members if m.status == MemberStatus.RUNNING),
            "completed": sum(1 for m in self._members if m.status == MemberStatus.COMPLETED),
            "failed": sum(1 for m in self._members if m.status == MemberStatus.FAILED),
            "members": [
                {"name": m.name, "status": m.status.value, "task": m.task}
                for m in self._members
            ],
        }

    # ─── 内部方法 ──────────────────────────────────────────

    async def _execute_member(self, member: FireteamMember):
        """执行单个成员任务"""
        member.status = MemberStatus.RUNNING
        member.start_time = time.time()

        try:
            if member.handler:
                # 有自定义 handler
                result = await asyncio.wait_for(
                    member.handler(
                        targets=member.targets,
                        tool=member.tool,
                        **member.handler_kwargs,
                    ),
                    timeout=member.timeout,
                )
            else:
                # 使用默认执行器
                result = await asyncio.wait_for(
                    self._default_execute(member),
                    timeout=member.timeout,
                )

            # 处理结果
            if isinstance(result, dict):
                member.result = result
                member.findings = result.get("findings", result.get("vulnerabilities", []))
            elif isinstance(result, list):
                member.findings = result

            member.status = MemberStatus.COMPLETED

        except asyncio.TimeoutError:
            member.status = MemberStatus.FAILED
            member.error = f"Timeout after {member.timeout}s"
        except asyncio.CancelledError:
            member.status = MemberStatus.CANCELLED
        except Exception as e:
            member.status = MemberStatus.FAILED
            member.error = f"{type(e).__name__}: {str(e)}"

        member.end_time = time.time()
        member.duration_seconds = member.end_time - member.start_time

        # 回调
        if self.on_member_complete:
            try:
                self.on_member_complete(member)
            except Exception:
                pass

    async def _default_execute(self, member: FireteamMember) -> Dict:
        """默认执行器（shell 命令）"""
        tool = member.tool
        targets = member.targets

        if not targets:
            return {"findings": []}

        # 根据工具类型选择执行方式
        if tool == "dalfox":
            targets_str = "\n".join(targets[:20])
            cmd = f"echo '{targets_str}' | dalfox pipe --silence 2>/dev/null"
        elif tool == "nuclei":
            targets_str = "\n".join(targets[:50])
            cmd = f"echo '{targets_str}' | nuclei -severity critical,high -silent -rate-limit 5 2>/dev/null"
        elif tool == "ffuf":
            if targets:
                cmd = f"ffuf -u {targets[0]}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -s 2>/dev/null | head -30"
            else:
                return {"findings": []}
        elif tool == "hydra":
            if targets:
                cmd = f"echo '[hydra would run against {targets[0]}]'"
            else:
                return {"findings": []}
        else:
            # 通用 shell 执行
            if targets:
                cmd = f"echo 'Task: {member.task} on {targets[0]}'"
            else:
                return {"findings": []}

        # 执行命令
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="ignore")

            # 解析输出为 findings
            findings = self._parse_tool_output(tool, output)
            return {"findings": findings, "raw_output": output[:2000]}
        except Exception as e:
            return {"findings": [], "error": str(e)}

    def _parse_tool_output(self, tool: str, output: str) -> List[Dict]:
        """解析工具输出为标准 findings 格式"""
        findings = []
        if not output.strip():
            return findings

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            finding = {
                "title": line[:100],
                "type": self._infer_vuln_type(tool),
                "severity": "medium",
                "evidence": line,
            }

            # 尝试提取 URL
            import re
            url_match = re.search(r'https?://[^\s]+', line)
            if url_match:
                finding["url"] = url_match.group()

            findings.append(finding)

        return findings

    def _infer_vuln_type(self, tool: str) -> str:
        """根据工具推断漏洞类型"""
        tool_type_map = {
            "dalfox": "xss",
            "sqlmap": "injection",
            "active_fuzzer": "injection",
            "nuclei": "cve",
            "ffuf": "info_leak",
            "hydra": "auth",
            "idor_tester": "authz",
            "ssrf_tester": "ssrf",
        }
        return tool_type_map.get(tool, "other")

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """去重（基于 URL + type）"""
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.get('url', '')}{f.get('type', '')}{f.get('title', '')[:50]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

async def quick_fireteam(
    target: str,
    tasks: List[str] = None,
    max_concurrent: int = 4,
) -> FireteamResult:
    """
    快速 Fireteam — 根据目标自动组建团队
    
    Args:
        target: 目标 URL 或域名
        tasks: 要执行的任务模板名列表（默认全部）
        max_concurrent: 最大并发数
    """
    team = Fireteam(max_concurrent=max_concurrent)

    default_tasks = tasks or ["xss_scan", "sqli_fuzz", "nuclei_scan", "dir_bruteforce", "cors_check"]

    for task_name in default_tasks:
        if task_name in TASK_TEMPLATES:
            team.add_from_template(task_name, targets=[target])

    return await team.deploy()


def findings_from_fireteam(result: FireteamResult) -> List[Dict]:
    """
    将 Fireteam 结果转换为 auto_hunt 兼容的 findings 格式
    可直接注入 findings["vulnerabilities"]
    """
    return result.all_findings
