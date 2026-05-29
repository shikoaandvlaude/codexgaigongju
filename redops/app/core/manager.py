"""
RedOps Web - 扫描管理器
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid
import subprocess
import json


class ScanTask:
    """扫描任务"""
    
    def __init__(self, task_id: str, target: str, scan_type: str, options: Dict[str, Any]):
        self.task_id = task_id
        self.target = target
        self.scan_type = scan_type
        self.options = options
        self.status = "pending"  # pending, running, completed, failed
        self.results = []
        self.started_at = None
        self.completed_at = None
        self.logs = []
    
    def add_log(self, message: str):
        """添加日志"""
        self.logs.append({
            "timestamp": datetime.now().isoformat(),
            "message": message
        })


class ScanManager:
    """扫描管理器"""
    
    def __init__(self):
        self.tasks: Dict[str, ScanTask] = {}
        self.targets: List[str] = []
    
    def create_task(self, target: str, scan_type: str, options: Dict[str, Any] = None) -> str:
        """创建扫描任务"""
        task_id = str(uuid.uuid4())
        task = ScanTask(task_id, target, scan_type, options or {})
        self.tasks[task_id] = task
        if target not in self.targets:
            self.targets.append(target)
        return task_id
    
    def create_batch_tasks(self, targets: List[str], scan_type: str, options: Dict[str, Any] = None) -> List[str]:
        """批量创建扫描任务"""
        task_ids = []
        for target in targets:
            task_id = self.create_task(target, scan_type, options)
            task_ids.append(task_id)
        return task_ids
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        """获取任务"""
        return self.tasks.get(task_id)
    
    def get_all_tasks(self) -> List[Dict[str, Any]]:
        """获取所有任务"""
        return [
            {
                "task_id": task.task_id,
                "target": task.target,
                "scan_type": task.scan_type,
                "status": task.status,
                "started_at": task.started_at,
                "completed_at": task.completed_at,
                "result_count": len(task.results)
            }
            for task in self.tasks.values()
        ]
    
    def get_active_count(self) -> int:
        """获取活跃任务数"""
        return sum(1 for task in self.tasks.values() if task.status == "running")
    
    async def run_nuclei_scan(self, task_id: str, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """运行Nuclei扫描"""
        task = self.get_task(task_id)
        if not task:
            return {"error": "Task not found"}
        
        task.status = "running"
        task.started_at = datetime.now().isoformat()
        
        try:
            # 构建nuclei命令
            cmd = ["nuclei", "-u", target, "-json", "-silent"]
            
            # 添加选项
            if options:
                if options.get("severity"):
                    severity = ",".join(options["severity"])
                    cmd.extend(["-severity", severity])
                if options.get("tags"):
                    tags = ",".join(options["tags"])
                    cmd.extend(["-tags", tags])
                if options.get("rate_limit"):
                    cmd.extend(["-rate-limit", str(options["rate_limit"])])
                if options.get("threads"):
                    cmd.extend(["-threads", str(options["threads"])])
            
            # 添加自定义POC目录
            poc_dir = options.get("poc_dir") if options else None
            if poc_dir:
                cmd.extend(["-d", poc_dir])
            
            task.add_log(f"Starting nuclei scan: {' '.join(cmd)}")
            
            # 执行扫描
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                # 解析JSON结果
                for line in stdout.decode().strip().split("\n"):
                    if line:
                        try:
                            result = json.loads(line)
                            task.results.append(result)
                            task.add_log(f"Found: {result.get('info', {}).get('name', 'Unknown')}")
                        except:
                            pass
            
            if stderr:
                task.add_log(f"Error: {stderr.decode()}")
            
            task.status = "completed"
            task.completed_at = datetime.now().isoformat()
            
            return {
                "task_id": task_id,
                "status": "completed",
                "results_count": len(task.results),
                "results": task.results
            }
            
        except Exception as e:
            task.status = "failed"
            task.completed_at = datetime.now().isoformat()
            task.add_log(f"Failed: {str(e)}")
            
            return {
                "task_id": task_id,
                "status": "failed",
                "error": str(e)
            }
    
    async def run_poc_scan(self, task_id: str, target: str, poc_name: str = None) -> Dict[str, Any]:
        """运行POC扫描"""
        task = self.get_task(task_id)
        if not task:
            return {"error": "Task not found"}
        
        task.status= "running"
        task.started_at = datetime.now().isoformat()
        
        try:
            task.add_log(f"Starting POC scan on {target}")
            
            # POC扫描逻辑
            # 这里可以集成自定义POC
            # 暂时返回模拟结果
            task.results.append({
                "target": target,
                "poc": poc_name or "default",
                "vulnerable": False,
                "timestamp": datetime.now().isoformat()
            })
            
            task.status = "completed"
            task.completed_at = datetime.now().isoformat()
            
            return {
                "task_id": task_id,
                "status": "completed",
                "results_count": len(task.results),
                "results": task.results
            }
            
        except Exception as e:
            task.status = "failed"
            task.completed_at = datetime.now().isoformat()
            task.add_log(f"Failed: {str(e)}")
            
            return {
                "task_id": task_id,
                "status": "failed",
                "error": str(e)
            }
    
    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        if task_id in self.tasks:
            del self.tasks[task_id]
            return True
        return False
    
    def clear_completed(self):
        """清除已完成任务"""
        completed = [tid for tid, task in self.tasks.items() if task.status in ["completed", "failed"]]
        for tid in completed:
            del self.tasks[tid]
