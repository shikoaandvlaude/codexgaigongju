"""
Agent Engine — 核心 AI 引擎
负责：LLM调用、命令执行、输出解析、决策

命令执行支持两种后端（自动选择）：
  1. HexStrike API — 如果配置了且 server 在线，通过 API 调用（参数优化+缓存）
  2. 本地 subprocess — 直接执行 shell 命令（默认/fallback）
"""

import subprocess
import time
import os
import json
from typing import Optional


class AgentEngine:
    """AI Agent 核心引擎"""
    
    def __init__(self, config: dict):
        self.config = config
        self.llm_config = config.get('llm', {})
        self.rate_config = config.get('rate_limit', {})
        self.request_count = 0
        self.last_request_time = 0


        # API Key: 优先从环境变量读取，其次 config
        api_key = (
            os.environ.get('DEEPSEEK_API_KEY') or
            os.environ.get('OPENAI_API_KEY') or
            self.llm_config.get('api_key', '')
        )
        base_url = (
            os.environ.get('LLM_BASE_URL') or
            self.llm_config.get('base_url', 'https://api.deepseek.com/v1')
        )
        
        # 初始化 HexStrike 桥接（如果配置了）
        self.hexstrike = None
        if config.get('hexstrike', {}).get('enabled', False):
            try:
                from hexstrike_bridge import HexStrikeBridge
                self.hexstrike = HexStrikeBridge(config)
                hs_status = self.hexstrike.get_status()
                if hs_status['is_available']:
                    print(f"[+] HexStrike AI 后端已连接: {hs_status['server_url']}")
                else:
                    print(f"[!] HexStrike 配置已启用但 server 未在线，将使用本地执行")
            except ImportError:
                print("[!] hexstrike_bridge.py 未找到，将使用本地执行")
            except Exception as e:
                print(f"[!] HexStrike 初始化失败: {e}，将使用本地执行")
        
        # 初始化 LLM 客户端
        if not api_key:
            print("[!] 警告: 未配置 API Key (设置 DEEPSEEK_API_KEY 环境变量或 config.yaml)")
        
        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=api_key,
                base_url=base_url
            )
        except ImportError:
            print("[!] 请安装 openai: pip install openai")
            raise


    def think(self, prompt: str, context: str = "", system_prompt: str = None) -> str:
        """让 AI 思考/决策"""
        if not system_prompt:
            system_prompt = """你是一个专业的 SRC 漏洞猎人 AI 助手。你的任务是：
1. 分析目标信息，制定测试计划
2. 根据工具输出判断下一步行动
3. 识别潜在漏洞线索
4. 始终遵守 SRC 红线规则（不破坏、不泄露、不越权）

回答要求：
- 简洁明确
- 给出具体的命令或操作建议
- 如果发现危险行为要立即警告
- 用中文回答"""
        
        messages = [
            {"role": "system", "content": system_prompt},
        ]
        
        if context:
            messages.append({"role": "user", "content": f"当前上下文:\n{context}"})
        
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = self.client.chat.completions.create(
                model=os.environ.get('LLM_MODEL') or self.llm_config.get('model', 'deepseek-chat'),
                messages=messages,
                max_tokens=self.llm_config.get('max_tokens', 4096),
                temperature=self.llm_config.get('temperature', 0.3),
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"[LLM错误] {e}"


    def execute_command(self, command: str, timeout: int = 120) -> dict:
        """
        执行系统命令（带限速 + HexStrike路由）
        
        执行优先级：
        1. HexStrike API（如果启用且在线且命令匹配）
        2. 本地 subprocess（默认/fallback）
        """
        
        # 限速检查
        self._rate_limit()
        
        # 安全检查：拒绝危险命令
        dangerous = ['rm -rf', 'mkfs', 'dd if=', ':(){', 'fork bomb', '> /dev/sda']
        for d in dangerous:
            if d in command:
                return {"success": False, "output": f"[安全拒绝] 危险命令: {command}", "returncode": -1}
        
        self.request_count += 1
        
        # 检查是否超过最大请求数
        max_requests = self.rate_config.get('max_total_requests', 500)
        if self.request_count > max_requests:
            return {"success": False, "output": f"[限制] 已达最大请求数 {max_requests}，停止执行", "returncode": -1}
        
        # === HexStrike 路由 ===
        if self.hexstrike and self.hexstrike.should_use_hexstrike(command):
            result = self.hexstrike.execute_via_hexstrike(command, timeout)
            
            # 如果返回 fallback 标记，降级到本地执行
            if result.get("fallback"):
                return self._execute_local(command, timeout)
            else:
                result["command"] = command
                return result
        
        # === 本地执行 ===
        return self._execute_local(command, timeout)


    def _execute_local(self, command: str, timeout: int = 120) -> dict:
        """本地 subprocess 执行命令"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "PATH": f"{os.path.expanduser('~/go/bin')}:{os.environ.get('PATH', '')}"}
            )
            
            output = result.stdout.strip()
            if result.stderr and not output:
                output = result.stderr.strip()
            
            return {
                "success": result.returncode == 0,
                "output": output[:5000],  # 限制输出长度
                "returncode": result.returncode,
                "command": command,
                "via": "local",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "output": f"[超时] 命令超过 {timeout}s", "returncode": -1, "command": command, "via": "local"}
        except Exception as e:
            return {"success": False, "output": f"[异常] {e}", "returncode": -1, "command": command, "via": "local"}


    def decide_next_action(self, phase: str, current_findings: dict, target: str) -> dict:
        """AI 决策下一步行动"""
        
        context = f"""当前阶段: {phase}
目标: {target}
已发现:
- 子域名 {len(current_findings.get('subdomains', []))} 个
- 存活主机 {len(current_findings.get('alive_hosts', []))} 个
- URL {len(current_findings.get('urls', []))} 个
- 参数 {len(current_findings.get('params', []))} 个
- 漏洞 {len(current_findings.get('vulnerabilities', []))} 个
- 密钥泄露 {len(current_findings.get('secrets', []))} 个

最近发现的一些数据（前20条）:
子域名: {current_findings.get('subdomains', [])[:20]}
URL: {current_findings.get('urls', [])[:20]}
"""
        
        prompt = f"""基于当前发现，请决定下一步要执行什么命令。

要求：
1. 只给出一条具体的 shell 命令
2. 命令必须带限速参数（对SRC目标每秒不超过5个请求）
3. 不要用 sqlmap 等自动化注入工具
4. 如果觉得当前阶段已经足够，回答 "PHASE_COMPLETE"

回答格式（JSON）：
{{"action": "execute", "command": "具体命令", "reason": "为什么执行这个"}}
或
{{"action": "phase_complete", "reason": "为什么结束当前阶段"}}
"""
        
        response = self.think(prompt, context)
        
        # 尝试解析 JSON
        try:
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "{" in response and "}" in response:
                start = response.index("{")
                end = response.rindex("}") + 1
                json_str = response[start:end]
            else:
                return {"action": "phase_complete", "reason": response}
            
            return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            return {"action": "phase_complete", "reason": response}
    
    def _rate_limit(self):
        """限速：确保请求间隔"""
        min_interval = 1.0 / self.rate_config.get('requests_per_second', 3)
        elapsed = time.time() - self.last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_request_time = time.time()
    
    def get_request_count(self) -> int:
        """获取已发送请求数"""
        return self.request_count
