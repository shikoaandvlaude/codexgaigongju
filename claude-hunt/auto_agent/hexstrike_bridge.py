"""
HexStrike Bridge — HexStrike AI Server 桥接模块
让 Auto-Hunt Agent 可以通过 HexStrike 的 HTTP API 执行工具命令。

使用场景：
  1. HexStrike server 运行中 → 通过 API 调用（参数优化+缓存+错误恢复）
  2. HexStrike server 未启动 → 自动 fallback 到本地 subprocess 直接执行
  3. 配置中关闭 HexStrike → 始终直接执行

配置方式（config.yaml）：
  hexstrike:
    enabled: true
    server_url: "http://127.0.0.1:8888"
    timeout: 120
    fallback_to_local: true   # server不可用时自动降级为本地执行

工具映射：
  HexStrike 封装了150+工具的参数优化，本模块将 auto_agent 的命令
  映射到 HexStrike 的对应 API endpoint，获得更好的参数优化和错误恢复。
"""

import requests
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# HexStrike API 工具映射表
# 左边是 auto_agent 里用的工具名，右边是 HexStrike API 对应的 endpoint/参数
TOOL_MAP = {
    "nmap": {"endpoint": "/api/command", "tool": "nmap"},
    "nuclei": {"endpoint": "/api/command", "tool": "nuclei"},
    "subfinder": {"endpoint": "/api/command", "tool": "subfinder"},
    "httpx": {"endpoint": "/api/command", "tool": "httpx"},
    "ffuf": {"endpoint": "/api/command", "tool": "ffuf"},
    "dalfox": {"endpoint": "/api/command", "tool": "dalfox"},
    "katana": {"endpoint": "/api/command", "tool": "katana"},
    "gau": {"endpoint": "/api/command", "tool": "gau"},
    "waybackurls": {"endpoint": "/api/command", "tool": "waybackurls"},
    "dnsx": {"endpoint": "/api/command", "tool": "dnsx"},
    "naabu": {"endpoint": "/api/command", "tool": "naabu"},
    "trufflehog": {"endpoint": "/api/command", "tool": "trufflehog"},
    "gitleaks": {"endpoint": "/api/command", "tool": "gitleaks"},
    "arjun": {"endpoint": "/api/command", "tool": "arjun"},
    "paramspider": {"endpoint": "/api/command", "tool": "paramspider"},
    "wafw00f": {"endpoint": "/api/command", "tool": "wafw00f"},
    "amass": {"endpoint": "/api/command", "tool": "amass"},
    "gospider": {"endpoint": "/api/command", "tool": "gospider"},
    "hakrawler": {"endpoint": "/api/command", "tool": "hakrawler"},
    "interactsh-client": {"endpoint": "/api/command", "tool": "interactsh-client"},
}

# HexStrike 高级 API（比直接命令更智能）
INTELLIGENCE_ENDPOINTS = {
    "analyze_target": "/api/intelligence/analyze-target",
    "select_tools": "/api/intelligence/select-tools",
    "optimize_params": "/api/intelligence/optimize-parameters",
}


class HexStrikeBridge:
    """
    HexStrike AI Server 桥接器
    
    功能：
    1. 检测 HexStrike server 是否可用
    2. 可用时通过 API 调用工具（享受参数优化+缓存）
    3. 不可用时自动降级为本地 subprocess
    4. 提供 HexStrike 高级智能分析 API
    """

    def __init__(self, config: dict):
        self.config = config
        self.hexstrike_config = config.get("hexstrike", {})
        self.enabled = self.hexstrike_config.get("enabled", False)
        self.server_url = self.hexstrike_config.get("server_url", "http://127.0.0.1:8888").rstrip("/")
        self.timeout = self.hexstrike_config.get("timeout", 120)
        self.fallback_to_local = self.hexstrike_config.get("fallback_to_local", True)
        self.is_available = False
        self.session = requests.Session()
        
        # 如果启用了 HexStrike，尝试连接
        if self.enabled:
            self.is_available = self._check_health()

    def _check_health(self) -> bool:
        """检查 HexStrike server 是否在线"""
        try:
            resp = self.session.get(
                f"{self.server_url}/health",
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                logger.info(f"[HexStrike] 连接成功! 版本: {data.get('version', '?')}, 状态: {data.get('status', '?')}")
                return True
        except requests.exceptions.ConnectionError:
            logger.warning(f"[HexStrike] Server 未启动 ({self.server_url})，将使用本地执行")
        except Exception as e:
            logger.warning(f"[HexStrike] 连接失败: {e}")
        return False

    def should_use_hexstrike(self, command: str) -> bool:
        """
        判断是否应该通过 HexStrike 执行这条命令
        
        条件：
        1. HexStrike 已启用 (config)
        2. Server 在线
        3. 命令中的工具在映射表里
        """
        if not self.enabled or not self.is_available:
            return False
        
        # 检查命令是否包含已映射的工具
        for tool_name in TOOL_MAP:
            if tool_name in command:
                return True
        
        return False

    def execute_via_hexstrike(self, command: str, timeout: int = None) -> dict:
        """
        通过 HexStrike API 执行命令
        
        返回格式与 agent_engine.execute_command() 一致：
        {"success": bool, "output": str, "returncode": int, "command": str, "via": "hexstrike"}
        """
        if timeout is None:
            timeout = self.timeout

        try:
            # 通用命令执行 API
            resp = self.session.post(
                f"{self.server_url}/api/command",
                json={"command": command, "timeout": timeout},
                timeout=timeout + 10  # 网络超时比命令超时多10s
            )

            if resp.status_code == 200:
                data = resp.json()
                return {
                    "success": data.get("success", False),
                    "output": data.get("output", data.get("stdout", ""))[:5000],
                    "returncode": data.get("returncode", data.get("exit_code", -1)),
                    "command": command,
                    "via": "hexstrike",
                    "cached": data.get("cached", False),
                }
            else:
                return {
                    "success": False,
                    "output": f"[HexStrike API错误] HTTP {resp.status_code}: {resp.text[:500]}",
                    "returncode": -1,
                    "command": command,
                    "via": "hexstrike",
                }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "output": f"[HexStrike超时] 命令超过 {timeout}s",
                "returncode": -1,
                "command": command,
                "via": "hexstrike",
            }
        except requests.exceptions.ConnectionError:
            # Server 掉线了，标记不可用
            self.is_available = False
            logger.warning("[HexStrike] Server 断开连接，后续将使用本地执行")
            
            if self.fallback_to_local:
                return {"fallback": True}  # 告诉调用者要 fallback
            else:
                return {
                    "success": False,
                    "output": "[HexStrike] Server 不可用且未启用 fallback",
                    "returncode": -1,
                    "command": command,
                    "via": "hexstrike",
                }
        except Exception as e:
            return {
                "success": False,
                "output": f"[HexStrike异常] {e}",
                "returncode": -1,
                "command": command,
                "via": "hexstrike",
            }

    def analyze_target(self, target: str, analysis_type: str = "comprehensive") -> dict:
        """
        使用 HexStrike 的 AI 智能分析目标
        
        analysis_type: "comprehensive" / "quick" / "stealth"
        返回: HexStrike 的分析结果（推荐工具/攻击路径/技术栈等）
        """
        if not self.is_available:
            return {"available": False, "reason": "HexStrike server 不可用"}

        try:
            resp = self.session.post(
                f"{self.server_url}{INTELLIGENCE_ENDPOINTS['analyze_target']}",
                json={"target": target, "analysis_type": analysis_type},
                timeout=60
            )
            if resp.status_code == 200:
                return {"available": True, "data": resp.json()}
        except Exception as e:
            logger.warning(f"[HexStrike] 智能分析失败: {e}")
        
        return {"available": False, "reason": "API调用失败"}

    def get_optimized_params(self, tool: str, target: str, context: dict = None) -> dict:
        """
        让 HexStrike 的 AI 优化工具参数
        
        例如：输入 "nuclei" + 目标，返回最佳的 nuclei 命令参数
        """
        if not self.is_available:
            return {"optimized": False}

        try:
            resp = self.session.post(
                f"{self.server_url}{INTELLIGENCE_ENDPOINTS['optimize_params']}",
                json={"tool": tool, "target": target, "context": context or {}},
                timeout=30
            )
            if resp.status_code == 200:
                return {"optimized": True, "data": resp.json()}
        except Exception:
            pass
        
        return {"optimized": False}

    def get_status(self) -> dict:
        """获取 HexStrike 当前状态（用于日志/调试）"""
        return {
            "enabled": self.enabled,
            "server_url": self.server_url,
            "is_available": self.is_available,
            "fallback_to_local": self.fallback_to_local,
        }

    def reconnect(self) -> bool:
        """尝试重新连接（用于 server 恢复后）"""
        if self.enabled:
            self.is_available = self._check_health()
        return self.is_available
