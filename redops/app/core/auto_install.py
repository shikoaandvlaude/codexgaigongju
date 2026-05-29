"""
RedOps - 自动安装模块
自动检测并安装缺失的渗透测试工具
"""

import os
import platform
import subprocess
import re
from typing import Dict, Any, Optional, List
from .executor import get_executor


class AutoInstaller:
    """自动安装缺失工具"""
    
    def __init__(self):
        self.platform = platform.system()
        self.executor = get_executor()
        self.install_history: List[Dict] = []
        
        # 常用渗透测试工具映射
        self.tools_map = {
            # 工具名: (安装命令, 包管理器)
            "nmap": {
                "linux": "apt-get install -y nmap",
                "windows": "choco install nmap -y",
                "mac": "brew install nmap"
            },
            "nuclei": {
                "linux": "go install github.com/projectdiscovery/nuclei/v3@latest",
                "windows": "go install github.com/projectdiscovery/nuclei/v3@latest",
                "mac": "go install github.com/projectdiscovery/nuclei/v3@latest"
            },
            "sqlmap": {
                "linux": "apt-get install -y sqlmap",
                "windows": "git clone https://github.com/sqlmapproject/sqlmap.git",
                "mac": "brew install sqlmap"
            },
            "dirb": {
                "linux": "apt-get install -y dirb",
                "windows": "choco install dirb -y",
                "mac": "brew install dirb"
            },
            "gobuster": {
                "linux": "apt-get install -y gobuster",
                "windows": "choco install gobuster -y",
                "mac": "brew install gobuster"
            },
            "nikto": {
                "linux": "apt-get install -y nikto",
                "windows": "choco install nikto -y",
                "mac": "brew install nikto"
            },
            "hydra": {
                "linux": "apt-get install -y hydra",
                "windows": "choco install hydra -y",
                "mac": "brew install hydra"
            },
            "john": {
                "linux": "apt-get install -y john",
                "windows": "choco install john -y",
                "mac": "brew install john"
            },
            "hashcat": {
                "linux": "apt-get install -y hashcat",
                "windows": "choco install hashcat -y",
                "mac": "brew install hashcat"
            },
            "wireshark": {
                "linux": "apt-get install -y wireshark",
                "windows": "choco install wireshark -y",
                "mac": "brew install wireshark"
            },
            "burpsuite": {
                "linux": "apt-get install -y burpsuite",
                "windows": "choco install burp-free -y",
                "mac": "brew install burp-suite"
            },
            "msfconsole": {
                "linux": "apt-get install -y metasploit-framework",
                "windows": "choco install metasploit -y",
                "mac": "brew install metasploit"
            },
            "netcat": {
                "linux": "apt-get install -y netcat-openbsd",
                "windows": "choco install netcat -y",
                "mac": "brew install netcat"
            },
            "socat": {
                "linux": "apt-get install -y socat",
                "windows": "choco install socat -y",
                "mac": "brew install socat"
            },
            "curl": {
                "linux": "apt-get install -y curl",
                "windows": "choco install curl -y",
                "mac": "brew install curl"
            },
            "wget": {
                "linux": "apt-get install -y wget",
                "windows": "choco install wget -y",
                "mac": "brew install wget"
            },
            "git": {
                "linux": "apt-get install -y git",
                "windows": "choco install git -y",
                "mac": "brew install git"
            },
            "python": {
                "linux": "apt-get install -y python3 python3-pip",
                "windows": "choco install python3 -y",
                "mac": "brew install python3"
            },
            "jq": {
                "linux": "apt-get install -y jq",
                "windows": "choco install jq -y",
                "mac": "brew install jq"
            },
            "tree": {
                "linux": "apt-get install -y tree",
                "windows": "choco install tree -y",
                "mac": "brew install tree"
            },
            "htop": {
                "linux": "apt-get install -y htop",
                "windows": "choco install htop -y",
                "mac": "brew install htop"
            },
            "ranger": {
                "linux": "apt-get install -y ranger",
                "windows": "pip install ranger-fm",
                "mac": "brew install ranger"
            },
            "vim": {
                "linux": "apt-get install -y vim",
                "windows": "choco install vim -y",
                "mac": "brew install vim"
            },
            "nano": {
                "linux": "apt-get install -y nano",
                "windows": "choco install nano -y",
                "mac": "brew install nano"
            },
            "unzip": {
                "linux": "apt-get install -y unzip",
                "windows": "choco install unzip -y",
                "mac": "brew install unzip"
            },
            "zip": {
                "linux": "apt-get install -y zip",
                "windows": "choco install zip -y",
                "mac": "brew install zip"
            },
            "tar": {
                "linux": "apt-get install -y tar",
                "windows": "choco install tar -y",
                "mac": "brew install tar"
            },
            "ping": {
                "linux": "apt-get install -y iputils-ping",
                "windows": "自带",
                "mac": "自带"
            },
            "traceroute": {
                "linux": "apt-get install -y traceroute",
                "windows": "choco install tracert -y",
                "mac": "brew install traceroute"
            },
            "netstat": {
                "linux": "apt-get install -y net-tools",
                "windows": "自带",
                "mac": "自带"
            },
            "ifconfig": {
                "linux": "apt-get install -y net-tools",
                "windows": "ipconfig",
                "mac": "ifconfig"
            },
            "ss": {
                "linux": "apt-get install -y iproute2",
                "windows": "netsh",
                "mac": "自带"
            }
        }
    
    def get_platform_key(self) -> str:
        """获取当前平台键"""
        if self.platform == "Windows":
            return "windows"
        elif self.platform == "Darwin":
            return "mac"
        else:
            return "linux"
    
    def check_tool_exists(self, tool_name: str) -> bool:
        """检查工具是否存在"""
        # 使用 which/where 命令
        if self.platform == "Windows":
            cmd = f"where {tool_name}"
        else:
            cmd = f"which {tool_name}"
        
        result = self.executor.execute(cmd)
        return result["success"] and result["returncode"] == 0
    
    def detect_missing_tool(self, command: str) -> Optional[str]:
        """
        从命令输出中检测缺失的工具
        返回工具名，如果无法检测则返回None
        """
        command_lower = command.lower()
        
        # 常见"命令未找到"模式
        patterns = [
            r"command not found",
            r"不是内部或外部命令",
            r"不是可运行的程序",
            r"'[^']' is not recognized",
            r"no such file or directory",
            r"未找到命令"
        ]
        
        for pattern in patterns:
            if re.search(pattern, command_lower):
                # 尝试提取工具名
                # 常见格式: "nmap: command not found"
                match = re.search(r"'?([a-z0-9_-]+)'?\s+(?:command not found|不是)", command_lower)
                if match:
                    return match.group(1)
                
                # 检查已知工具
                for tool in self.tools_map.keys():
                    if tool in command_lower:
                        return tool
        
        return None
    
    def get_install_command(self, tool_name: str) -> Optional[str]:
        """获取工具的安装命令"""
        # 精确匹配
        if tool_name in self.tools_map:
            platform_key = self.get_platform_key()
            return self.tools_map[tool_name].get(platform_key)
        
        # 模糊匹配
        tool_lower = tool_name.lower()
        for known_tool, commands in self.tools_map.items():
            if tool_lower in known_tool or known_tool in tool_lower:
                platform_key = self.get_platform_key()
                return commands.get(platform_key)
        
        return None
    
    def install_tool(self, tool_name: str, auto_yes: bool = True) -> Dict[str, Any]:
        """
        安装工具
        
        Args:
            tool_name: 工具名称
            auto_yes: 是否自动确认
        
        Returns:
            dict: {
"success": bool,
                "tool": str,
                "command": str,
                "output": str,
                "error": str (如果有)
            }
        """
        # 检查是否已存在
        if self.check_tool_exists(tool_name):
            return {
                "success": True,
                "tool": tool_name,
                "command": "",
                "output": f"{tool_name} 已存在",
                "error": None
            }
        
        # 获取安装命令
        install_cmd = self.get_install_command(tool_name)
        
        if not install_cmd:
            return {
                "success": False,
                "tool": tool_name,
                "command": "",
                "output": "",
                "error": f"未知工具: {tool_name}，无法确定安装方法"
            }
        
        # 检查权限
        if not self.executor.permission_guard.root_mode:
            # 非root模式，尝试使用sudo
            if self.platform != "Windows":
                install_cmd = f"sudo {install_cmd}"
        
        # 执行安装
        print(f"[AutoInstall] 正在安装 {tool_name}...")
        print(f"[AutoInstall] 命令: {install_cmd}")
        
        result = self.executor.execute(install_cmd, timeout=300)
        
        # 记录安装历史
        self.install_history.append({
            "tool": tool_name,
            "command": install_cmd,
            "success": result["success"],
            "timestamp": result.get("timestamp", "")
        })
        
        return {
            "success": result["success"],
            "tool": tool_name,
            "command": install_cmd,
            "output": result.get("stdout", ""),
            "error": result.get("error")
        }
    
    def install_missing_tool(self, command_output: str, original_command: str) -> Dict[str, Any]:
        """
        根据命令输出自动安装缺失的工具
        
        Args:
            command_output: 命令的错误输出
            original_command: 原始命令
        
        Returns:
            dict: 安装结果
        """
        # 检测缺失的工具
        tool_name = self.detect_missing_tool(command_output)
        
        if not tool_name:
            return {
                "success": False,
                "error": "无法识别缺失的工具",
                "output": command_output
            }
        
        # 安装工具
        return self.install_tool(tool_name)
    
    def get_install_history(self) -> List[Dict]:
        """获取安装历史"""
        return self.install_history.copy()
    
    def get_available_tools(self) -> List[Dict]:
        """获取可用工具列表及其状态"""
        tools = []
        for tool_name in self.tools_map.keys():
            exists = self.check_tool_exists(tool_name)
            install_cmd = self.get_install_command(tool_name)
            tools.append({
                "name": tool_name,
                "installed": exists,
                "install_command": install_cmd
            })
        return tools


# 全局自动安装实例
_installer: Optional[AutoInstaller] = None


def get_auto_installer() -> AutoInstaller:
    """获取自动安装器实例"""
    global _installer
    if _installer is None:
        _installer = AutoInstaller()
    return _installer
