"""
RedOps - 系统执行器模块
具有权限控制的系统命令执行器，类似OpenClaw
"""

import os
import sys
import subprocess
import platform
import re
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
import threading
import time

# 权限守卫
class PermissionGuard:
    """路径权限守卫 - 防止越权操作"""
    
    def __init__(self):
        # 默认允许的目录（相对路径）
        self.allowed_paths: List[str] = []
        # 是否启用root模式
        self.root_mode = False
        # 危险路径列表（即使在白名单也不允许）
        self.dangerous_paths = [
            "/boot", "/sys", "/proc", "/dev",
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "C:\\Windows\\System32", "C:\\Windows\\SysWOW64"
        ]
    
    def set_allowed_paths(self, paths: List[str]):
        """设置允许的路径列表"""
        self.allowed_paths = [os.path.abspath(p) for p in paths]
    
    def set_root_mode(self, enabled: bool):
        """设置root模式"""
        self.root_mode = enabled
    
    def is_path_allowed(self, path: str) -> bool:
        """检查路径是否在允许范围内"""
        if not path:
            return True  # 空路径不检查
        
        # 转换为绝对路径
        abs_path = os.path.abspath(path)
        
        # 检查是否在危险路径
        for danger in self.dangerous_paths:
            if abs_path.startswith(danger) or abs_path == danger:
                return False
        
        # 如果没有设置白名单，且不在root模式，则拒绝所有文件操作
        if not self.allowed_paths and not self.root_mode:
            return False
        
        # 检查是否在白名单内
        for allowed in self.allowed_paths:
            if abs_path.startswith(allowed):
                return True
        
        # root模式下允许所有非危险路径
        return self.root_mode
    
    def check_command(self, command: str) -> Dict[str, Any]:
        """检查命令是否安全"""
        cmd_lower = command.lower()
        
        # 危险命令列表
        dangerous_cmds = [
            "rm -rf /", "mkfs", "dd if=/dev/zero",
            "> /dev/sda", "format c:", "del /f /s /q C:",
            "chmod 777 /", "chown -r"
        ]
        
        for danger in dangerous_cmds:
            if danger in cmd_lower:
                return {"allowed": False, "reason": f"危险命令: {danger}"}
        
        return {"allowed": True}


# 全局权限守卫实例
_permission_guard = PermissionGuard()


def get_permission_guard() -> PermissionGuard:
    """获取权限守卫实例"""
    return _permission_guard


class SystemExecutor:
    """
    系统执行器 - 类似OpenClaw的命令执行能力
    支持Windows和Linux系统
    """
    
    def __init__(self):
        self.platform = platform.system()
        self.permission_guard = _permission_guard
        self.command_history: List[Dict] = []
        self._lock = threading.Lock()
    
    def execute(self, command: str, cwd: str = None, timeout: int = 30, 
                capture_output: bool = True) -> Dict[str, Any]:
        """
        执行系统命令
        
        Args:
            command: 要执行的命令
            cwd: 工作目录
            timeout: 超时时间（秒）
            capture_output: 是否捕获输出
        
        Returns:
            dict: {
                "success": bool,
                "returncode": int,
                "stdout": str,
                "stderr": str,
                "error": str (如果有)
            }
        """
        # 安全检查
        safety = self.permission_guard.check_command(command)
        if not safety["allowed"]:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": "",
                "error": safety["reason"]
            }
        
        # 记录命令
        with self._lock:
            self.command_history.append({
                "command": command,
                "cwd": cwd,
                "timestamp": time.time()
            })
        
        try:
            # 构建执行参数
            shell = True if self.platform == "Windows" else False
            
            # Windows使用cmd，Linux使用bash
            if self.platform == "Windows":
                cmd = command
            else:
                cmd = f"/bin/bash -c '{command}'"
            
            kwargs = {
                "shell": shell,
                "timeout": timeout,
                "capture_output": capture_output
            }
            
            if cwd:
                kwargs["cwd"] = cwd
            
            # 执行命令
            result = subprocess.run(
                cmd,
                **kwargs
            )
            
            return {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout.decode("utf-8", errors="ignore") if result.stdout else "",
                "stderr": result.stderr.decode("utf-8", errors="ignore") if result.stderr else "",
                "error": None
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": "",
                "error": f"命令执行超时 ({timeout}秒)"
            }
        except Exception as e:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": "",
                "error": str(e)
            }
    
    def execute_with_workdir(self, command: str, workdir: str) -> Dict[str, Any]:
        """在指定目录下执行命令"""
        # 检查目录权限
        if not self.permission_guard.is_path_allowed(workdir):
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": "",
                "error": f"没有权限访问目录: {workdir}"
            }
        
        return self.execute(command, cwd=workdir)
    
    def read_file(self, filepath: str) -> Dict[str, Any]:
        """读取文件"""
        if not self.permission_guard.is_path_allowed(filepath):
            return {
                "success": False,
                "content": "",
                "error": f"没有权限读取文件: {filepath}"
            }
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return {
                "success": True,
                "content": content,
                "error": None
            }
        except Exception as e:
            return {
                "success": False,
                "content": "",
                "error": str(e)
            }
    
    def write_file(self, filepath: str, content: str) -> Dict[str, Any]:
        """写入文件"""
        if not self.permission_guard.is_path_allowed(filepath):
            return {
                "success": False,
                "error": f"没有权限写入文件: {filepath}"
            }
        
        try:
            # 确保目录存在
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            
            return {
                "success": True,
                "error": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_directory(self, path: str = ".") -> Dict[str, Any]:
        """列出目录内容"""
        if not self.permission_guard.is_path_allowed(path):
            return {
                "success": False,
                "files": [],
                "error": f"没有权限访问目录: {path}"
            }
        
        try:
            items = []
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                try:
                    stat = os.stat(item_path)
                    items.append({
                        "name": item,
                        "is_dir": os.path.isdir(item_path),
                        "size": stat.st_size,
                        "modified": stat.st_mtime
                    })
                except:
                    items.append({
                        "name": item,
                        "is_dir": os.path.isdir(item_path),
                        "size": 0,
                        "modified": 0
                    })
            
            return {
                "success": True,
                "files": items,
                "error": None
            }
        except Exception as e:
            return {
                "success": False,
                "files": [],
                "error": str(e)
            }
    
    def get_system_info(self) -> Dict[str, Any]:
        """获取系统信息"""
        info = {
            "platform": self.platform,
            "platform_version": platform.version(),
            "platform_release": platform.release(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": sys.version,
            "root_mode": self.permission_guard.root_mode,
            "allowed_paths": self.permission_guard.allowed_paths
        }
        
        # 执行命令获取更多信息
        if self.platform == "Linux":
            result = self.execute("uname -a")
            if result["success"]:
                info["kernel"] = result["stdout"].strip()
            
            result = self.execute("whoami")
            if result["success"]:
                info["current_user"] = result["stdout"].strip()
                
        elif self.platform == "Windows":
            result = self.execute("ver")
            if result["success"]:
                info["windows_version"] = result["stdout"].strip()
            
            result = self.execute("whoami")
            if result["success"]:
                info["current_user"] = result["stdout"].strip()
        
        return info
    
    def get_command_history(self) -> List[Dict]:
        """获取命令历史"""
        return self.command_history.copy()


# 全局执行器实例
_executor: Optional[SystemExecutor] = None


def get_executor() -> SystemExecutor:
    """获取执行器实例"""
    global _executor
    if _executor is None:
        _executor = SystemExecutor()
    return _executor


def init_executor(root_mode: bool = False, allowed_paths: List[str] = None):
    """初始化执行器"""
    global _executor
    _executor = SystemExecutor()
    
    # 设置权限
    if allowed_paths:
        _executor.permission_guard.set_allowed_paths(allowed_paths)
    _executor.permission_guard.set_root_mode(root_mode)
    
    return _executor
