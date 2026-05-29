"""
RedOps Web - 聊天API V2
像OpenClaw一样直接执行命令，直接给答案
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import re
import sys
import os

# 添加路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from web.app.core.llm_agent import get_llm_agent, is_llm_ready
from web.app.core.executor import get_executor

router = APIRouter()

sessions: Dict[str, Dict] = {}


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    target: Optional[str] = None
    auto_execute: bool = True  # 默认自动执行命令


class ChatResponse(BaseModel):
    message: str
    session_id: str
    actions: Optional[List[Dict]] = None
    executed: Optional[bool] = None
    commands: Optional[List[str]] = None


@router.post("/message", response_model=ChatResponse)
async def chat_message(request: ChatRequest):
    session_id = request.session_id or str(uuid.uuid4())
    
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [], 
            "created_at": datetime.now().isoformat(), 
            "target": request.target
        }
    
    sessions[session_id]["messages"].append({
        "role": "user", 
        "content": request.message, 
        "timestamp": datetime.now().isoformat()
    })
    
    # 检查是否启用LLM
    if is_llm_ready() and request.auto_execute:
        agent = get_llm_agent()
        
        # 注入执行器
        if not agent.executor:
            agent.set_executor(get_executor())
        
        # 使用自动执行模式 - 像OpenClaw一样
        result = agent.chat_with_auto_execute(session_id, request.message)
        
        if result.get("success"):
            response_msg = result["message"]
            executed = result.get("type") in ["executed", "auto_executed"]
            commands = result.get("commands", [])
        else:
            response_msg = f"执行出错: {result.get('error', '未知错误')}"
            executed = False
            commands = []
    else:
        # 没有LLM，使用本地分析
        response_msg, executed, commands = local_execute(request.message)
    
    sessions[session_id]["messages"].append({
        "role": "assistant", 
        "content": response_msg, 
        "timestamp": datetime.now().isoformat()
    })
    
    return ChatResponse(
        message=response_msg, 
        session_id=session_id, 
        actions=None,
        executed=executed,
        commands=commands
    )


def local_execute(message: str) -> tuple:
    """
    本地执行命令（不调用LLM时的fallback）
    """
    msg_lower = message.lower()
    commands = []
    results = []
    executor = get_executor()
    
    # 端口扫描
    if any(k in msg_lower for k in ["端口", "扫描端口", "开放端口", "port"]):
        target = extract_target(message)
        cmd = f"nmap -sV -p 1-1000 {target}"
        commands.append(cmd)
        result = executor.execute(cmd, timeout=60)
        if result.get("success"):
            output = result.get("stdout", "")
            if "open" in output.lower():
                ports = re.findall(r'(\d+)/open', output)
                results.append(f"发现开放端口: {', '.join(ports)}" if ports else "未发现开放端口")
            else:
                results.append("端口扫描完成")
        else:
            results.append(f"执行失败: {result.get('error', '')}")
    
    # 漏洞扫描
    elif any(k in msg_lower for k in ["漏洞", "漏扫", "vulnerability"]):
        target = extract_target(message)
        cmd = f"nuclei -u {target} -severity critical,high,medium -silent"
        commands.append(cmd)
        result = executor.execute(cmd, timeout=120)
        if result.get("success"):
            output = result.get("stdout", "")
            count = len(output.split('\n')) if output else 0
            if count > 0:
                results.append(f"发现 {count} 个漏洞")
                # 列出关键漏洞
                for line in output.split('\n')[:5]:
                    if line.strip():
                        results.append(f"  - {line[:100]}")
            else:
                results.append("未发现漏洞")
        else:
            results.append(f"执行失败: {result.get('error', '')}")
    
    # 目录扫描
    elif any(k in msg_lower for k in ["目录", "路径", "directory"]):
        target = extract_target(message)
        cmd = f"nuclei -u {target} -tags directory -silent"
        commands.append(cmd)
        result = executor.execute(cmd, timeout=60)
        if result.get("success"):
            output = result.get("stdout", "")
            if output:
                results.append("发现目录:")
                for line in output.split('\n')[:5]:
                    if line.strip():
                        results.append(f"  - {line[:80]}")
            else:
                results.append("未发现敏感目录")
    
    # ping检测
    elif any(k in msg_lower for k in ["ping", "存活", "延迟"]):
        target = extract_target(message)
        cmd = f"ping -c 4 {target}"
        commands.append(cmd)
        result = executor.execute(cmd, timeout=10)
        if result.get("success"):
            output = result.get("stdout", "")
            # 提取延迟
            avg_match = re.search(r'average = ([\d.]+)', output)
            if avg_match:
                results.append(f"目标存活，延迟: {avg_match.group(1)} ms")
            else:
                results.append("目标存活")
        else:
            results.append("目标不可达")
    
    # curl检测
    elif any(k in msg_lower for k in ["curl", "http", "web", "网站"]):
        target = extract_target(message)
        if not target.startswith("http"):
            target = f"http://{target}"
        cmd = f"curl -I {target}"
        commands.append(cmd)
        result = executor.execute(cmd, timeout=10)
        if result.get("success"):
            output = result.get("stdout", "")
            # 提取状态码
            status_match = re.search(r'HTTP/[\d\.]+ (\d+)', output)
            if status_match:
                status = status_match.group(1)
                results.append(f"HTTP状态: {status}")
            # 提取server
            server_match = re.search(r'Server: (.+)', output)
            if server_match:
                results.append(f"服务器: {server_match.group(1).strip()}")
        else:
            results.append(f"请求失败: {result.get('error', '')}")
    
    # whois查询
    elif "whois" in msg_lower:
        target = extract_target(message)
        cmd = f"whois {target}"
        commands.append(cmd)
        result = executor.execute(cmd, timeout=15)
        if result.get("success"):
            output = result.get("stdout", "")
            # 提取关键信息
            for field in ["Registrar", "Creation Date", "Expiry Date", "Name Server"]:
                match = re.search(rf'{field}:?\s*(.+)', output, re.IGNORECASE)
                if match:
                    results.append(f"{field}: {match.group(1).strip()}")
    
    # 帮助
    else:
        results.append("""我可以直接执行以下命令：
• 端口扫描 - "扫描 example.com 的端口"
• 漏洞扫描 - "扫描漏洞" 或 "漏扫"
• 目录扫描 - "扫描目录"
• HTTP检测 - "检查网站" 或 "curl"
• 存活检测 - "ping" 或 "检测存活"
• WHOIS查询 - "whois xxx.com"

直接告诉我做什么，我立即执行！""")
    
    message = '\n'.join(results) if results else "好的，还需要做什么？"
    executed = len(commands) > 0
    
    return message, executed, commands


def extract_target(message: str) -> str:
    """提取目标"""
    # URL
    url_match = re.search(r'https?://[^\s]+', message)
    if url_match:
        return url_match.group(1).rstrip('/')
    
    # IP
    ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', message)
    if ip_match:
        return ip_match.group(1)
    
    # 域名
    domain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}', message)
    if domain_match:
        return domain_match.group(1)
    
    return "example.com"


@router.get("/sessions")
async def list_sessions():
    return [
        {
            "session_id": sid, 
            "created_at": s["created_at"], 
            "message_count": len(s["messages"])
        } 
        for sid, s in sessions.items()
    ]


@router.delete("/session/{session_id}")
async def delete_session(session_id: str):
    if session_id in sessions:
        del sessions[session_id]
        return {"status": "deleted"}
    return {"error": "Session not found"}
