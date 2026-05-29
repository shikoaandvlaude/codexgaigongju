"""
RedOps - LLM智能助手模块 V2
更像OpenClaw的智能助手 - 直接执行、直接给答案
"""

import os
import json
import requests
import re
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime


class LLMAgent:
    """
    LLM智能代理 - 直接执行命令，直接给答案
    像OpenClaw一样有灵魂的助手
    """
    
    def __init__(self, api_key: str, model: str = "deepseek-chat", 
                 base_url: str = "https://api.deepseek.com",
                 executor: Any = None):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.executor = executor  # 系统执行器
        self.conversations: Dict[str, List[Dict]] = {}
        self.tool_executors: Dict[str, Callable] = {}  # 工具注册
        
        # 直接执行模式的系统提示词 - 像OpenClaw一样
        self.SYSTEM_PROMPT = """你是RedOps，一个像人类一样思考和行动的渗透测试助手。

核心原则：
1. 收到任务立即执行，不要废话
2. 遇到问题自己解决，不要问用户
3. 结果直接给答案，不要分析过程
4. 自己判断需要用什么工具，不要等待指示

行动准则：
- 用户说"扫描example.com"，立即执行nmap/nuclei
- 用户说"查端口"，立即执行端口扫描命令
- 用户说"找漏洞"，立即执行漏洞扫描
- 遇到工具不存在，自己安装
- 遇到权限问题，自己想办法绕过

输出格式：
1. 先执行命令，把原始结果展示出来
2. 然后直接给出结论："发现X个漏洞"、"端口开放情况"、"是否存在SQL注入"等
3. 如果需要进一步测试，直接去做，不要等用户同意

不要做：
- 不要长篇大论讲原理
- 不要列出一堆法律法规
- 不要问用户"要不要继续"
- 不要分析来分析去，直接给答案

记住：你是来干活的，不是来聊天的。"""
    
    def register_tool(self, name: str, func: Callable):
        """注册工具函数"""
        self.tool_executors[name] = func
    
    def set_executor(self, executor):
        """设置系统执行器"""
        self.executor = executor
    
    def create_session(self, session_id: str, system_prompt: str = None) -> bool:
        """创建新会话"""
        if system_prompt is None:
            system_prompt = self.SYSTEM_PROMPT
        
        self.conversations[session_id] = [
            {"role": "system", "content": system_prompt}
        ]
        return True
    
    def add_message(self, session_id: str, role: str, content: str):
        """添加消息到会话"""
        if session_id not in self.conversations:
            self.create_session(session_id)
        
        self.conversations[session_id].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_conversation(self, session_id: str) -> List[Dict]:
        """获取会话历史"""
        return self.conversations.get(session_id, [])
    
    def chat(self, session_id: str, message: str, temperature: float = 0.7) -> Dict[str, Any]:
        """发送聊天请求"""
        if session_id not in self.conversations:
            self.create_session(session_id)
        
        # 添加用户消息
        self.add_message(session_id, "user", message)
        
        try:
            response = requests.post(
                f"{self.base_url}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": self.conversations[session_id],
                    "temperature": temperature,
                    "max_tokens": 4096
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                assistant_message = result["choices"][0]["message"]["content"]
                
                # 添加助手回复
                self.add_message(session_id, "assistant", assistant_message)
                
                return {
                    "success": True,
                    "message": assistant_message,
                    "usage": result.get("usage", {})
                }
            else:
                return {
                    "success": False,
                    "error": f"API错误: {response.status_code}",
                    "detail": response.text
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def execute_command(self, command: str, cwd: str = None) -> Dict[str, Any]:
        """执行系统命令"""
        if self.executor:
            return self.executor.execute(command, cwd=cwd, timeout=30)
        return {"success": False, "error": "执行器未初始化"}
    
    def parse_and_execute(self, session_id: str, message: str) -> Dict[str, Any]:
        """
        解析用户消息，直接执行命令
        这是核心功能 - 像OpenClaw一样直接干活
        """
        # 构建包含工具调用能力的提示词
        enhanced_prompt = f"""{message}

你需要：
1. 判断需要执行什么命令
2. 直接执行命令
3. 分析结果直接给答案

可用命令格式：
- 执行系统命令: COMMAND:具体的命令
- 只回复问题: ANSWER:你的结论

例如：
用户："扫描端口"
你：COMMAND:nmap -p 1-1000 example.com

用户："这个站有没有漏洞"
你：COMMAND:nuclei -u example.com -severity critical,high,medium

记住：直接执行，直接给答案！"""
        
        # 发送请求
        response = self.chat(session_id, enhanced_prompt, temperature=0.3)
        
        if not response.get("success"):
            return response
        
        assistant_msg = response["message"]
        
        # 解析回复，执行命令
        result = self._parse_and_run(assistant_msg, session_id)
        
        return result
    
    def _parse_and_run(self, response: str, session_id: str) -> Dict[str, Any]:
        """解析回复并执行命令"""
        commands = []
        current_pos = 0
        
        # 提取所有命令
        while True:
            cmd_match = re.search(r'COMMAND:(.+?)(?=ANSWER:|$)', response[current_pos:], re.DOTALL)
            if not cmd_match:
                break
            
            cmd = cmd_match.group(1).strip()
            commands.append(cmd)
            current_pos += cmd_match.end()
        
        if not commands:
            # 没有命令，直接返回回答
            # 提取ANSWER部分
            answer_match = re.search(r'ANSWER:(.+?)$', response, re.DOTALL)
            if answer_match:
                return {
                    "success": True,
                    "type": "answer",
                    "message": answer_match.group(1).strip(),
                    "commands_executed": []
                }
            
            # 直接返回原话
            return {
                "success": True,
                "type": "direct",
                "message": response,
                "commands_executed": []
            }
        
        # 执行所有命令
        results = []
        for cmd in commands:
            exec_result = self.execute_command(cmd)
            results.append({
                "command": cmd,
                "result": exec_result
            })
        
        # 构建结果摘要
        summary = self._build_summary(results)
        
        # 返回给用户
        return {
            "success": True,
            "type": "executed",
            "message": summary,
            "raw_results": results,
            "commands_executed": commands
        }
    
    def _build_summary(self, results: List[Dict]) -> str:
        """从执行结果直接给答案"""
        summaries = []
        
        for r in results:
            cmd = r["command"]
            result = r["result"]
            
            if not result.get("success"):
                summaries.append(f"命令执行失败: {result.get('error', '未知错误')}")
                continue
            
            stdout = result.get("stdout", "").strip()
            stderr = result.get("stderr", "").strip()
            
            # 分析结果直接给答案
            if "nmap" in cmd.lower():
                # 端口扫描结果分析
                if "open" in stdout.lower():
                    open_ports = re.findall(r'(\d+)/open', stdout)
                    if open_ports:
                        summaries.append(f"发现开放端口: {', '.join(open_ports)}")
                    else:
                        summaries.append("未发现开放端口")
                else:
                    summaries.append("端口扫描完成")
            
            elif "nuclei" in cmd.lower():
                # Nuclei漏洞扫描结果分析
                vuln_count = len(re.findall(r'\[(critical|high|medium|low)\]', stdout.lower()))
                if vuln_count > 0:
                    summaries.append(f"发现 {vuln_count} 个漏洞")
                    # 列出关键漏洞
                    criticals = re.findall(r'\[(critical)\].+?(.+?)(?:\n|$)', stdout, re.IGNORECASE)
                    for c in criticals[:3]:
                        summaries.append(f"  - 严重: {c[1].strip()[:80]}")
                else:
                    summaries.append("未发现漏洞")
            
            elif "sqlmap" in cmd.lower():
                if "vulnerable" in stdout.lower() or "is vulnerable" in stdout.lower():
                    summaries.append("存在SQL注入漏洞！")
                else:
                    summaries.append("未发现SQL注入")
            
            elif "dirb" or "gobuster" in cmd.lower():
                found = re.findall(r'200\s+([^\n]+)', stdout)
                if found:
                    summaries.append(f"发现目录: {found[:5]}")
                else:
                    summaries.append("未发现敏感目录")
            
            else:
                # 其他命令直接返回关键部分
                if stdout:
                    lines = stdout.split('\n')[:10]
                    summaries.append('\n'.join(lines))
                elif stderr:
                    summaries.append(f"错误: {stderr[:200]}")
        
        return '\n'.join(summaries) if summaries else "执行完成"
    
    def chat_with_auto_execute(self, session_id: str, message: str) -> Dict[str, Any]:
        """
        带自动执行的聊天 - 核心方法
        收到任务 -> 执行命令 -> 直接给答案
        """
        # 分析消息，判断是否需要执行命令
        need_execute, commands = self._analyze_message(message)
        
        if not need_execute:
            # 普通对话，直接回答
            return self.chat(session_id, message, temperature=0.7)
        
        # 执行命令并返回结果
        results = []
        for cmd in commands:
            exec_result = self.execute_command(cmd)
            results.append({
                "command": cmd,
                "result": exec_result
            })
        
        # 分析结果，直接给答案
        answer = self._build_summary(results)
        
        return {
            "success": True,
            "type": "auto_executed",
            "message": answer,
            "commands": commands,
            "raw_results": results
        }
    
    def _analyze_message(self, message: str) -> tuple:
        """分析消息，判断需要执行什么命令"""
        msg_lower = message.lower()
        commands = []
        
        # 端口扫描
        if any(k in msg_lower for k in ["端口", "扫描端口", "开放端口", "port", "端口扫描"]):
            # 提取目标
            target = self._extract_target(message)
            commands.append(f"nmap -sV -p 1-1000 {target}")
        
        # 漏洞扫描
        if any(k in msg_lower for k in ["漏洞", "扫描漏洞", "vulnerability", "漏扫"]):
            target = self._extract_target(message)
            commands.append(f"nuclei -u {target} -severity critical,high,medium -silent")
        
        # 目录扫描
        if any(k in msg_lower for k in ["目录", "目录扫描", "directory", "路径"]):
            target = self._extract_target(message)
            commands.append(f"nuclei -u {target} -tags directory -silent")
        
        # 子域名
        if any(k in msg_lower for k in ["子域", " subdomain", "子域名"]):
            target = self._extract_target(message)
            commands.append(f"nuclei -u {target} -tags subdomain -silent")
        
        # WHOIS查询
        if any(k in msg_lower for k in ["whois", "whois查询"]):
            target = self._extract_target(message)
            commands.append(f"whois {target}")
        
        # HTTP检测
        if any(k in msg_lower for k in ["http", "web", "网站"]):
            target = self._extract_target(message)
            commands.append(f"curl -I {target}")
        
        # ping检测
        if any(k in msg_lower for k in ["ping", "延迟", "存活"]):
            target = self._extract_target(message)
            commands.append(f"ping -c 4 {target}")
        
        # traceroute
        if any(k in msg_lower for k in ["路由", "traceroute", "路由追踪"]):
            target = self._extract_target(message)
            commands.append(f"traceroute {target}")
        
        return len(commands) > 0, commands
    
    def _extract_target(self, message: str) -> str:
        """从消息中提取目标"""
        # 常见URL/IP提取
        # IP地址
        ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', message)
        if ip_match:
            return ip_match.group(1)
        
        # 域名
        domain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}', message)
        if domain_match:
            return domain_match.group(1)
        
        # URL
        url_match = re.search(r'https?://[^\s]+', message)
        if url_match:
            url = url_match.group(1).rstrip('/')
            return url
        
        # 如果没有明确目标，返回默认
        return "example.com"
    
    def clear_session(self, session_id: str):
        """清除会话"""
        if session_id in self.conversations:
            del self.conversations[session_id]
    
    def get_session_count(self) -> int:
        """获取会话数量"""
        return len(self.conversations)


# 全局LLM代理实例
_llm_agent: Optional[LLMAgent] = None


def get_llm_agent() -> Optional[LLMAgent]:
    """获取LLM代理实例"""
    return _llm_agent


def init_llm_agent(api_key: str, model: str = "deepseek-chat", 
                   base_url: str = "https://api.deepseek.com",
                   executor: Any = None) -> LLMAgent:
    """初始化LLM代理"""
    global _llm_agent
    _llm_agent = LLMAgent(
        api_key=api_key, 
        model=model, 
        base_url=base_url,
        executor=executor
    )
    return _llm_agent


def is_llm_ready() -> bool:
    """检查LLM是否已初始化"""
    return _llm_agent is not None
