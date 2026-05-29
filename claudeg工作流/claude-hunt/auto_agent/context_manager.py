#!/usr/bin/env python3
"""
Context Manager — Chain Summarization 上下文管理
移植自 PentAGI 框架的 Chain Summarization Engine

解决的问题：LLM 上下文窗口有限，长时间运行的 Agent 会丢失早期信息。

核心算法：
1. SlidingWindow: 保留最近 N 条消息 + 摘要前缀
2. ChainSummarizer: 分段摘要，递归压缩旧内容
3. SectionCompressor: 按主题分区，保留每区的关键结论
4. MemoryIndex: 关键发现持久索引，随时可检索

用法：
    from context_manager import ContextManager
    
    ctx = ContextManager(max_tokens=8000)
    
    # Agent 每步操作后记录
    ctx.add_message("user", "扫描 example.com")
    ctx.add_message("assistant", "发现 3 个子域名...")
    ctx.add_tool_output("nmap", "-sV example.com", "PORT STATE SERVICE\n22 open ssh...")
    
    # 获取当前可用上下文（自动压缩）
    messages = ctx.get_context()  # 始终在 token 预算内
    
    # 检索历史发现
    relevant = ctx.search("SQL injection findings")
"""

import json
import time
import hashlib
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Deque
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class Message:
    """单条消息"""
    role: str = ""  # user/assistant/system/tool
    content: str = ""
    timestamp: float = 0
    # 元数据
    tool_name: str = ""
    token_estimate: int = 0
    importance: float = 0.5  # 0-1, 越高越不容易被压缩
    section: str = ""  # 所属段落标签
    summary_of: List[int] = field(default_factory=list)  # 如果是摘要，记录原始消息ID


@dataclass
class MemoryEntry:
    """持久记忆条目"""
    key: str = ""
    content: str = ""
    category: str = ""  # finding/decision/error/config
    timestamp: float = 0
    importance: float = 0.5
    tags: List[str] = field(default_factory=list)


@dataclass
class ContextConfig:
    """上下文管理配置"""
    # Token 预算
    max_tokens: int = 8000  # 最大上下文 token 数
    reserved_for_response: int = 2000  # 为响应预留
    # 滑动窗口
    window_size: int = 20  # 保留最近 N 条消息
    min_messages: int = 5  # 最少保留条数（即使超预算）
    # 摘要
    summary_trigger_ratio: float = 0.8  # 使用率超过此比例触发摘要
    summary_batch_size: int = 10  # 每次摘要的消息数
    # 重要性
    high_importance_threshold: float = 0.8  # 高于此值不被压缩
    tool_output_max_lines: int = 50  # 工具输出截断行数
    # 持久记忆
    max_memory_entries: int = 100


# ═══════════════════════════════════════════════════════════════
# Token 估算器（简易版，无需 tiktoken）
# ═══════════════════════════════════════════════════════════════

class TokenEstimator:
    """简易 token 估算（中英文混合）"""

    @staticmethod
    def estimate(text: str) -> int:
        """估算 token 数（粗略：英文 ~4字符/token，中文 ~2字符/token）"""
        if not text:
            return 0
        # 中文字符数
        cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        # 英文+符号
        en_chars = len(text) - cn_chars
        return int(cn_chars * 0.7 + en_chars / 4) + 1

    @staticmethod
    def estimate_messages(messages: List[Dict]) -> int:
        """估算消息列表的总 token"""
        total = 0
        for msg in messages:
            total += TokenEstimator.estimate(msg.get("content", ""))
            total += 4  # 消息格式开销
        return total


# ═══════════════════════════════════════════════════════════════
# Chain Summarizer — 链式摘要引擎
# ═══════════════════════════════════════════════════════════════

class ChainSummarizer:
    """
    链式摘要：将旧消息压缩为摘要，保留关键信息
    
    压缩策略：
    1. 工具输出 → 只保留关键发现行
    2. 重复模式 → 合并为统计
    3. 旧对话 → 提取结论性句子
    """

    # 关键行标识（这些行优先保留）
    IMPORTANT_LINE_PATTERNS = [
        "发现", "漏洞", "vulnerable", "critical", "high",
        "open", "成功", "失败", "error", "warning",
        "子域名", "alive", "端口", "port", "secret",
        "注入", "injection", "xss", "ssrf", "idor",
        "bypass", "绕过", "泄露", "leak",
    ]

    def summarize_messages(self, messages: List[Message], max_tokens: int = 500) -> str:
        """将一批消息压缩为摘要"""
        if not messages:
            return ""

        # 提取关键内容
        key_points = []
        tools_used = set()
        findings = []

        for msg in messages:
            if msg.tool_name:
                tools_used.add(msg.tool_name)

            # 提取重要行
            for line in msg.content.split("\n"):
                line_lower = line.lower()
                if any(p in line_lower for p in self.IMPORTANT_LINE_PATTERNS):
                    key_points.append(line.strip()[:100])

            # 高重要性消息完整保留摘要
            if msg.importance >= 0.8:
                findings.append(msg.content[:200])

        # 构建摘要
        parts = []
        if tools_used:
            parts.append(f"[使用工具: {', '.join(sorted(tools_used))}]")
        if findings:
            parts.append("关键发现:")
            parts.extend([f"  - {f}" for f in findings[:5]])
        if key_points:
            # 去重
            unique_points = list(dict.fromkeys(key_points))[:10]
            parts.append("要点:")
            parts.extend([f"  • {p}" for p in unique_points])

        summary = "\n".join(parts)

        # 确保不超预算
        while TokenEstimator.estimate(summary) > max_tokens and parts:
            parts.pop()
            summary = "\n".join(parts)

        return summary or "[已压缩的历史消息]"

    def compress_tool_output(self, output: str, max_lines: int = 50) -> str:
        """压缩工具输出（保留关键行）"""
        if not output:
            return ""

        lines = output.split("\n")
        if len(lines) <= max_lines:
            return output

        # 优先保留重要行
        important = []
        other = []
        for line in lines:
            line_lower = line.lower()
            if any(p in line_lower for p in self.IMPORTANT_LINE_PATTERNS):
                important.append(line)
            else:
                other.append(line)

        # 组合：重要行 + 头尾
        result_lines = important[:max_lines // 2]
        remaining_slots = max_lines - len(result_lines)
        if remaining_slots > 0:
            # 头部几行（通常是标题/格式）
            head = other[:min(5, remaining_slots // 2)]
            # 尾部几行（通常是总结）
            tail = other[-(remaining_slots - len(head)):] if other else []
            result_lines = head + result_lines + [f"... ({len(lines) - max_lines} 行已省略) ..."] + tail

        return "\n".join(result_lines[:max_lines])


# ═══════════════════════════════════════════════════════════════
# Memory Index — 持久记忆索引
# ═══════════════════════════════════════════════════════════════

class MemoryIndex:
    """
    关键发现的持久索引
    不受滑动窗口影响，随时可检索
    """

    def __init__(self, max_entries: int = 100):
        self.max_entries = max_entries
        self._entries: List[MemoryEntry] = []

    def add(self, key: str, content: str, category: str = "finding",
            importance: float = 0.5, tags: List[str] = None):
        """添加记忆条目"""
        entry = MemoryEntry(
            key=key,
            content=content[:500],
            category=category,
            timestamp=time.time(),
            importance=importance,
            tags=tags or [],
        )
        self._entries.append(entry)

        # 超过上限时移除最低重要性的旧条目
        if len(self._entries) > self.max_entries:
            self._entries.sort(key=lambda e: (e.importance, e.timestamp))
            self._entries = self._entries[-(self.max_entries):]

    def search(self, query: str, limit: int = 5) -> List[MemoryEntry]:
        """简易关键词搜索"""
        query_lower = query.lower()
        keywords = query_lower.split()

        scored = []
        for entry in self._entries:
            score = 0
            text = f"{entry.key} {entry.content} {' '.join(entry.tags)}".lower()
            for kw in keywords:
                if kw in text:
                    score += 1
            if score > 0:
                scored.append((score + entry.importance, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:limit]]

    def get_by_category(self, category: str) -> List[MemoryEntry]:
        """按类别获取"""
        return [e for e in self._entries if e.category == category]

    def get_summary(self) -> str:
        """生成记忆摘要（注入上下文用）"""
        if not self._entries:
            return ""

        by_category: Dict[str, List[str]] = {}
        for entry in sorted(self._entries, key=lambda e: e.timestamp, reverse=True):
            by_category.setdefault(entry.category, []).append(entry.content[:100])

        parts = ["[持久记忆]"]
        for cat, items in by_category.items():
            parts.append(f"  {cat}: {len(items)} 条")
            for item in items[:3]:
                parts.append(f"    - {item}")

        return "\n".join(parts)

    def export(self) -> List[Dict]:
        """导出为字典列表"""
        return [
            {
                "key": e.key,
                "content": e.content,
                "category": e.category,
                "importance": e.importance,
                "tags": e.tags,
                "time": datetime.fromtimestamp(e.timestamp).isoformat(),
            }
            for e in self._entries
        ]


# ═══════════════════════════════════════════════════════════════
# Context Manager — 主类
# ═══════════════════════════════════════════════════════════════

class ContextManager:
    """
    上下文管理器 — 解决 LLM 上下文窗口限制
    
    自动在 token 预算内管理消息历史：
    - 新消息正常追加
    - 超预算时自动触发 Chain Summarization
    - 关键发现存入持久 MemoryIndex
    - 任何时候调 get_context() 都在预算内
    
    用法：
        ctx = ContextManager(max_tokens=8000)
        
        ctx.add_message("user", "扫描 target.com")
        ctx.add_tool_output("nmap", "-sV target.com", nmap_output)
        ctx.add_message("assistant", "发现 22, 80, 443 端口开放")
        
        # 记录关键发现到持久记忆
        ctx.remember("target_ports", "22,80,443 开放", category="finding")
        
        # 获取上下文（自动压缩到预算内）
        messages = ctx.get_context()
    """

    def __init__(self, config: Optional[ContextConfig] = None, **kwargs):
        self.config = config or ContextConfig(**{
            k: v for k, v in kwargs.items()
            if k in ContextConfig.__dataclass_fields__
        })

        self.summarizer = ChainSummarizer()
        self.memory = MemoryIndex(max_entries=self.config.max_memory_entries)

        # 消息存储
        self._messages: List[Message] = []
        self._summaries: List[str] = []  # 历史摘要栈
        self._total_messages_added = 0

        # 系统消息（始终保留在最前面）
        self._system_message: str = ""

    def set_system_message(self, content: str):
        """设置系统消息（始终保留）"""
        self._system_message = content

    def add_message(self, role: str, content: str, importance: float = 0.5, section: str = ""):
        """添加消息"""
        msg = Message(
            role=role,
            content=content,
            timestamp=time.time(),
            token_estimate=TokenEstimator.estimate(content),
            importance=importance,
            section=section,
        )
        self._messages.append(msg)
        self._total_messages_added += 1

        # 自动提取关键发现到持久记忆
        if importance >= 0.8:
            self.memory.add(
                key=f"msg_{self._total_messages_added}",
                content=content[:300],
                category="finding" if role == "assistant" else "input",
                importance=importance,
            )

        # 检查是否需要压缩
        self._maybe_compress()

    def add_tool_output(self, tool_name: str, args: str, output: str, importance: float = 0.5):
        """添加工具输出（自动截断长输出）"""
        # 压缩长输出
        compressed = self.summarizer.compress_tool_output(
            output, max_lines=self.config.tool_output_max_lines
        )

        content = f"[{tool_name} {args}]\n{compressed}"
        msg = Message(
            role="tool",
            content=content,
            timestamp=time.time(),
            tool_name=tool_name,
            token_estimate=TokenEstimator.estimate(content),
            importance=importance,
        )
        self._messages.append(msg)
        self._total_messages_added += 1
        self._maybe_compress()

    def remember(self, key: str, content: str, category: str = "finding",
                 importance: float = 0.7, tags: List[str] = None):
        """存入持久记忆（不受窗口压缩影响）"""
        self.memory.add(key, content, category, importance, tags)

    def search_memory(self, query: str, limit: int = 5) -> List[Dict]:
        """搜索持久记忆"""
        entries = self.memory.search(query, limit)
        return [{"key": e.key, "content": e.content, "category": e.category} for e in entries]

    def get_context(self) -> List[Dict]:
        """
        获取当前上下文（始终在 token 预算内）
        
        Returns:
            OpenAI 格式的消息列表 [{"role": "...", "content": "..."}]
        """
        budget = self.config.max_tokens - self.config.reserved_for_response
        messages = []

        # 1. 系统消息
        if self._system_message:
            messages.append({"role": "system", "content": self._system_message})
            budget -= TokenEstimator.estimate(self._system_message)

        # 2. 历史摘要前缀
        if self._summaries:
            summary_text = "\n---\n".join(self._summaries[-3:])  # 最多保留 3 层摘要
            memory_text = self.memory.get_summary()
            prefix = f"[历史摘要]\n{summary_text}"
            if memory_text:
                prefix += f"\n\n{memory_text}"

            prefix_tokens = TokenEstimator.estimate(prefix)
            if prefix_tokens < budget * 0.3:  # 摘要最多占 30%
                messages.append({"role": "system", "content": prefix})
                budget -= prefix_tokens

        # 3. 最近消息（从后往前填充）
        recent_messages = []
        for msg in reversed(self._messages):
            msg_tokens = msg.token_estimate + 4
            if budget - msg_tokens < 0 and len(recent_messages) >= self.config.min_messages:
                break
            recent_messages.append({"role": msg.role if msg.role != "tool" else "user", "content": msg.content})
            budget -= msg_tokens

        recent_messages.reverse()
        messages.extend(recent_messages)

        return messages

    def get_stats(self) -> Dict:
        """获取上下文统计"""
        total_tokens = sum(m.token_estimate for m in self._messages)
        return {
            "total_messages": len(self._messages),
            "total_added": self._total_messages_added,
            "compressions": len(self._summaries),
            "current_tokens": total_tokens,
            "budget": self.config.max_tokens,
            "usage_ratio": f"{total_tokens / self.config.max_tokens * 100:.0f}%",
            "memory_entries": len(self.memory._entries),
        }

    # ─── 内部方法 ──────────────────────────────────────────

    def _maybe_compress(self):
        """检查是否需要压缩"""
        total_tokens = sum(m.token_estimate for m in self._messages)
        threshold = self.config.max_tokens * self.config.summary_trigger_ratio

        if total_tokens > threshold and len(self._messages) > self.config.window_size:
            self._compress()

    def _compress(self):
        """执行压缩：将旧消息摘要化"""
        # 保留最近 window_size 条
        keep_count = self.config.window_size
        to_summarize = self._messages[:-keep_count]
        to_keep = self._messages[-keep_count:]

        if not to_summarize:
            return

        # 分离高重要性消息（不压缩）
        high_importance = [m for m in to_summarize if m.importance >= self.config.high_importance_threshold]
        normal = [m for m in to_summarize if m.importance < self.config.high_importance_threshold]

        # 生成摘要
        summary = self.summarizer.summarize_messages(normal, max_tokens=500)
        self._summaries.append(summary)

        # 重建消息列表：高重要性 + 保留的近期
        self._messages = high_importance + to_keep

    def clear(self):
        """清空上下文（保留持久记忆）"""
        self._messages.clear()
        self._summaries.clear()
        self._total_messages_added = 0

    def export_state(self) -> Dict:
        """导出状态（用于持久化/断点恢复）"""
        return {
            "messages_count": len(self._messages),
            "summaries": self._summaries,
            "memory": self.memory.export(),
            "stats": self.get_stats(),
        }
