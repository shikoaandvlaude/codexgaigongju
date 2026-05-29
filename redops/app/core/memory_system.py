"""
RedOps Web - 记忆系统模块
模仿OpenClaw的记忆功能和上下文联动
"""

import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict


class MemoryNode:
    """记忆节点"""
    
    def __init__(self, node_id: str, content: str, node_type: str = "fact"):
        self.id = node_id
        self.content = content
        self.type = node_type  # fact, action, result, finding
        self.timestamp = datetime.now().isoformat()
        self.importance = 0.5  # 重要性 0-1
        self.access_count = 0
        self.last_access = self.timestamp
        self.connections: List[str] = []  # 关联的记忆ID
        self.metadata: Dict[str, Any] = {}
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "content": self.content,
            "type": self.type,
            "timestamp": self.timestamp,
            "importance": self.importance,
            "access_count": self.access_count,
            "last_access": self.last_access,
            "connections": self.connections,
            "metadata": self.metadata
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'MemoryNode':
        node = MemoryNode(data["id"], data["content"], data["type"])
        node.timestamp = data.get("timestamp", node.timestamp)
        node.importance = data.get("importance", 0.5)
        node.access_count = data.get("access_count", 0)
        node.last_access = data.get("last_access", node.timestamp)
        node.connections = data.get("connections", [])
        node.metadata = data.get("metadata", {})
        return node


class MemorySystem:
    """
    记忆系统 - 模仿OpenClaw
    核心功能：
    1. 情景记忆 - 存储测试过程中的重要发现
    2. 语义关联 - 建立记忆之间的关联
    3. 上下文提取 - 从历史中提取相关内容
    4. 记忆衰减 - 定期清理低价值记忆
    """
    
    def __init__(self, storage_path: str = "./data/memory.json"):
        self.storage_path = storage_path
        self.memories: Dict[str, MemoryNode] = {}
        self.target_memories: Dict[str, List[str]] = defaultdict(list)  # target -> memory_ids
        self.session_memories: Dict[str, List[str]] = defaultdict(list)  # session_id -> memory_ids
        self._load()
    
    def _load(self):
        """加载记忆"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for node_data in data.get("memories", []):
                        node = MemoryNode.from_dict(node_data)
                        self.memories[node.id] = node
                    
                    self.target_memories = defaultdict(list, data.get("target_memories", {}))
                    self.session_memories = defaultdict(list, data.get("session_memories", {}))
            except Exception as e:
                print(f"加载记忆失败: {e}")
    
    def _save(self):
        """保存记忆"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                data = {
                    "memories": [node.to_dict() for node in self.memories.values()],
                    "target_memories": dict(self.target_memories),
                    "session_memories": dict(self.session_memories)
                }
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存记忆失败: {e}")
    
    def add_memory(self, content: str, memory_type: str = "fact", 
                   target: str = None, session_id: str = None,
                   importance: float = 0.5, metadata: Dict = None) -> str:
        """添加记忆"""
        import uuid
        node_id = str(uuid.uuid4())
        
        node = MemoryNode(node_id, content, memory_type)
        node.importance = importance
        if metadata:
            node.metadata = metadata
        
        self.memories[node_id] = node
        
        # 关联目标
        if target:
            self.target_memories[target].append(node_id)
        
        # 关联会话
        if session_id:
            self.session_memories[session_id].append(node_id)
        
        # 建立语义关联
        self._connect_similar_memories(node_id)
        
        self._save()
        return node_id
    
    def _connect_similar_memories(self, node_id: str):
        """建立相似记忆的关联"""
        node = self.memories.get(node_id)
        if not node:
            return
        
        # 简单关键词匹配
        keywords = set(node.content.lower().split())
        
        for other_id, other_node in self.memories.items():
            if other_id == node_id:
                continue
            
            other_keywords = set(other_node.content.lower().split())
            common = keywords & other_keywords
            
            if len(common) >= 2:  # 至少2个共同关键词
                node.connections.append(other_id)
                other_node.connections.append(node_id)
    
    def get_memories_by_target(self, target: str) -> List[MemoryNode]:
        """获取目标相关的记忆"""
        memory_ids = self.target_memories.get(target, [])
        return [self.memories[mid] for mid in memory_ids if mid in self.memories]
    
    def get_memories_by_session(self, session_id: str) -> List[MemoryNode]:
        """获取会话相关的记忆"""
        memory_ids = self.session_memories.get(session_id, [])
        return [self.memories[mid] for mid in memory_ids if mid in self.memories]
    
    def get_related_memories(self, content: str, limit: int = 5) -> List[MemoryNode]:
        """获取相关内容"""
        keywords = set(content.lower().split())
        
        scored = []
        for node in self.memories.values():
            node_keywords = set(node.content.lower().split())
            common = keywords & node_keywords
            
            if common:
                score = len(common) * node.importance
                scored.append((score, node))
        
        scored.sort(reverse=True)
        return [node for _, node in scored[:limit]]
    
    def get_context_for_session(self, session_id: str, max_memories: int = 10) -> str:
        """为会话生成上下文摘要"""
        # 获取当前会话记忆
        session_mems = self.get_memories_by_session(session_id)
        
        # 获取相关记忆
        related = []
        for mem in session_mems[-3:]:  # 最近3条
            related.extend(self._get_connected_memories(mem.id))
        
        # 去重并排序
        all_mems = {m.id: m for m in session_mems + related}.values()
        all_mems = sorted(all_mems, key=lambda x: x.importance, reverse=True)
        
        context_parts = ["=== 相关上下文 ==="]
        for mem in all_mems[:max_memories]:
            context_parts.append(f"[{mem.type}] {mem.content}")
        
        return "\n".join(context_parts)
    
    def _get_connected_memories(self, node_id: str) -> List[MemoryNode]:
        """获取关联记忆"""
        node = self.memories.get(node_id)
        if not node:
            return []
        
        return [self.memories[cid] for cid in node.connections if cid in self.memories]
    
    def add_finding(self, target: str, session_id: str, finding: str, severity: str = "info"):
        """添加发现"""
        self.add_memory(
            content=finding,
            memory_type="finding",
            target=target,
            session_id=session_id,
            importance=0.9 if severity == "critical" else 0.7,
            metadata={"severity": severity}
        )
    
    def add_action(self, target: str, session_id: str, action: str, result: str):
        """添加行动记录"""
        self.add_memory(
            content=f"执行: {action} -> 结果: {result}",
            memory_type="action",
            target=target,
            session_id=session_id,
            importance=0.6,
            metadata={"action": action, "result": result}
        )
    
    def search(self, query: str, limit: int = 10) -> List[MemoryNode]:
        """搜索记忆"""
        query_lower = query.lower()
        results = []
        
        for node in self.memories.values():
            if query_lower in node.content.lower():
                results.append((node.importance, node))
        
        results.sort(reverse=True)
        return [node for _, node in results[:limit]]
    
    def clear_session(self, session_id: str):
        """清除会话记忆（可选）"""
        # 不真正删除，只是从会话记忆中移除
        if session_id in self.session_memories:
            del self.session_memories[session_id]
            self._save()
    
    def get_stats(self) -> Dict:
        """获取记忆统计"""
        type_count = defaultdict(int)
        for node in self.memories.values():
            type_count[node.type] += 1
        
        return {
            "total": len(self.memories),
            "by_type": dict(type_count),
            "targets": len(self.target_memories),
            "sessions": len(self.session_memories)
        }


# 全局记忆系统实例
_memory_system: Optional[MemorySystem] = None


def get_memory_system() -> MemorySystem:
    """获取记忆系统实例"""
    global _memory_system
    if _memory_system is None:
        _memory_system = MemorySystem()
    return _memory_system
