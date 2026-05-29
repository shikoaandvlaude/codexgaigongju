"""
Checkpoint Manager — 断点续跑模块
在每个阶段完成后保存进度，崩溃后可恢复继续执行
"""

import json
import os
import glob
from datetime import datetime


class CheckpointManager:
    """断点续跑管理器"""

    def __init__(self, config: dict):
        self.config = config
        self.checkpoint_config = config.get("checkpoint", {})
        self.enabled = self.checkpoint_config.get("enabled", True)
        self.auto_resume = self.checkpoint_config.get("auto_resume", True)
        # 检查点保存目录
        directory = self.checkpoint_config.get("directory", "~/.bai-agent/checkpoints")
        self.directory = os.path.expanduser(directory)
        # 自动创建目录
        if self.enabled and not os.path.exists(self.directory):
            os.makedirs(self.directory, exist_ok=True)

    def save_checkpoint(self, target: str, mode: str, phase_index: int,
                        findings: dict, step_count: int, waf_result: dict) -> str:
        """
        保存检查点
        返回检查点文件路径
        """
        if not self.enabled:
            return ""

        # 确保目录存在
        os.makedirs(self.directory, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 清理target中的特殊字符作为文件名
        safe_target = target.replace("/", "_").replace(":", "_").replace("*", "_")
        filename = f"{safe_target}_{timestamp}.json"
        filepath = os.path.join(self.directory, filename)

        state = {
            "target": target,
            "mode": mode,
            "current_phase_index": phase_index,
            "findings": findings,
            "step_count": step_count,
            "waf_result": waf_result,
            "timestamp": timestamp,
            "status": "in_progress",
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

        return filepath

    def load_latest_checkpoint(self, target: str) -> dict:
        """
        加载指定目标最近的 in_progress 检查点
        返回检查点数据字典，未找到返回 None
        """
        if not self.enabled:
            return None

        if not os.path.exists(self.directory):
            return None

        # 清理target中的特殊字符
        safe_target = target.replace("/", "_").replace(":", "_").replace("*", "_")
        pattern = os.path.join(self.directory, f"{safe_target}_*.json")
        files = glob.glob(pattern)

        if not files:
            return None

        # 按修改时间降序排列，找最新的 in_progress
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)

        for filepath in files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("status") == "in_progress":
                    data["_checkpoint_path"] = filepath
                    return data
            except (json.JSONDecodeError, IOError):
                continue

        return None

    def mark_completed(self, checkpoint_path: str):
        """将检查点标记为已完成"""
        if not checkpoint_path or not os.path.exists(checkpoint_path):
            return

        try:
            with open(checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["status"] = "completed"
            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, IOError):
            pass
