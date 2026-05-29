"""Base Phase — 阶段基类"""

import re
import time
import sys
import os

# 添加父目录到路径以导入 shell_utils
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, safe_echo_lines, sanitize_target, sanitize_url


class BasePhase:
    """所有阶段的基类"""
    
    def __init__(self, engine, logger, redline, tracer, mode):
        self.engine = engine
        self.logger = logger
        self.redline = redline
        self.tracer = tracer
        self.mode = mode  # "auto" or "semi"
    
    def execute(self, target: str, findings: dict) -> dict:
        """子类实现"""
        raise NotImplementedError
    
    def _step(self, step_name: str, target: str, phase_findings: dict, 
              global_findings: dict, command: str, parser, result_key: str):
        """执行一个步骤"""
        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            class C:
                def print(self, *a, **k): print(*a)
            console = C()
        
        console.print(f"  [dim]→ {step_name}...[/dim]")
        
        # 半自动模式确认
        if self.mode == "semi":
            try:
                from rich.prompt import Confirm
                if not Confirm.ask(f"    执行 {step_name}?", default=True):
                    self.logger.log_event("SKIP", f"用户跳过: {step_name}")
                    return
            except ImportError:
                pass
        
        # 执行命令
        result = self.engine.execute_command(command)
        
        # AI 分析输出
        analysis = ""
        if result["success"] and result["output"]:
            analysis = self.engine.think(
                f"分析以下 {step_name} 的输出，简要说明发现了什么（一句话）:\n{result['output'][:2000]}",
            )
        
        # 记录日志
        self.logger.log_command(command, result, analysis)
        
        # 从输出中提取 HTTP 状态码并记录到红线检查器
        self._record_status_codes(result)
        
        # 红线即时检查（每步都查）
        redline_result = self.redline.check({}, 0)
        if redline_result["stop"]:
            self.logger.log_event("REDLINE_STOP", redline_result["reason"])
            console.print(f"    [bold red]🚨 红线触发: {redline_result['reason']}[/bold red]")
            return
        
        # 解析结果
        if result["success"] and result["output"] and parser and result_key:
            parsed = parser(result["output"])
            if parsed:
                phase_findings[result_key].extend(parsed)
                console.print(f"    [green]✓ 发现 {len(parsed)} 条[/green]")
            else:
                console.print(f"    [dim]○ 无新发现[/dim]")
        elif not result["success"]:
            console.print(f"    [red]✗ 失败[/red]")
        
        # 限速
        time.sleep(self.engine.config.get('rate_limit', {}).get('delay_between_phases', 2))
    
    def _record_status_codes(self, result: dict):
        """
        从命令输出中智能提取 HTTP 状态码并记录到红线检查器。
        比旧版仅靠 returncode==0 判断 200 更准确。
        """
        output = result.get("output", "")
        returncode = result.get("returncode", -1)
        
        # 尝试从输出中提取实际的 HTTP 状态码
        # 匹配常见模式: "HTTP/1.1 403", "[403]", "status: 403", "HTTP_CODE:403"
        status_patterns = [
            r'HTTP/\d\.\d\s+(\d{3})',
            r'\[(\d{3})\]',
            r'HTTP_CODE:(\d{3})',
            r'status[:\s]+(\d{3})',
        ]
        
        found_codes = []
        for pattern in status_patterns:
            matches = re.findall(pattern, output)
            found_codes.extend(int(m) for m in matches)
        
        if found_codes:
            # 记录实际提取到的状态码
            for code in found_codes[:20]:  # 最多记录20个，防止刷量
                self.redline.record_response(code, output)
        elif returncode == 0:
            # 命令成功但没有明确状态码，记录为 200
            self.redline.record_response(200, output)
        elif returncode != 0 and output:
            # 命令失败，尝试判断是网络错误还是 HTTP 错误
            if "connection refused" in output.lower() or "timeout" in output.lower():
                pass  # 网络错误不记录为 HTTP 状态码
            elif "403" in output:
                self.redline.record_response(403, output)
            elif "404" in output:
                self.redline.record_response(404, output)
    
    def _safe_command(self, command: str, target: str) -> bool:
        """检查命令是否安全（增强版）"""
        # 绝对禁止的命令/模式
        dangerous = [
            'sqlmap', 'rm -rf', 'rm -f /', 'mkfs', 'dd if=',
            ':(){', 'fork bomb', '> /dev/sda',
            'wget -O', 'curl -o',  # 防止覆盖文件
            '> /', 'sudo', 'chmod 777',
            'eval ', 'exec ', 'python -c', 'python3 -c',
            'bash -c', 'sh -c',  # 防止嵌套 shell
            '/etc/passwd', '/etc/shadow',
        ]
        command_lower = command.lower()
        for d in dangerous:
            if d.lower() in command_lower:
                return False
        
        # 检查是否有重定向到敏感路径
        if re.search(r'>\s*/(?:etc|usr|var|root|home)', command):
            return False
        
        return True
    
    def _pipe_lines(self, lines: list, max_lines: int = 100) -> str:
        """
        安全地将多行数据准备为管道输入。
        使用 safe_echo_lines 防止 shell 注入。
        """
        return safe_echo_lines(lines, max_lines)
