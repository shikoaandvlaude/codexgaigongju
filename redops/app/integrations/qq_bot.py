"""
RedOps - QQ机器人模块
支持通过go-cqhttp/OneBot协议与Agent交互
"""

import os
import json
import asyncio
import threading
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime

# 可选导入websockets
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


class QQBot:
    """QQ机器人 (基于go-cqhttp WebSocket)"""
    
    def __init__(self, ws_url: str, access_token: str = None, 
                 allowed_groups: List[int] = None, allowed_qqs: List[int] = None):
        self.ws_url = ws_url
        self.access_token = access_token
        self.allowed_groups = allowed_groups or []
        self.allowed_qqs = allowed_qqs or []
        self.running = False
        self.ws = None
        self.message_callback: Optional[Callable] = None
        self._connect_task = None
    
    def is_allowed(self, group_id: int = None, user_id: int = None) -> bool:
        """检查是否允许"""
        # 如果没有设置白名单，允许所有
        if not self.allowed_groups and not self.allowed_qqs:
            return True
        
        if group_id and group_id in self.allowed_groups:
            return True
        if user_id and user_id in self.allowed_qqs:
            return True
        
        return False
    
    async def send_message(self, message_type: str, target_id: int, message: str) -> Dict[str, Any]:
        """发送消息"""
        if not self.ws or self.ws.closed:
            return {"status": "failed", "error": "WebSocket未连接"}
        
        # 构建CQ码消息
        data = {
            "action": "send_msg" if message_type == "private" else "send_group_msg",
            "params": {
                "message": message
            }
        }
        
        if message_type == "private":
            data["params"]["user_id"] = target_id
        else:
            data["params"]["group_id"] = target_id
        
        try:
            await self.ws.send(json.dumps(data))
            return {"status": "ok"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    async def send_private_msg(self, user_id: int, message: str) -> Dict[str, Any]:
        """发送私聊消息"""
        return await self.send_message("private", user_id, message)
    
    async def send_group_msg(self, group_id: int, message: str) -> Dict[str, Any]:
        """发送群消息"""
        return await self.send_message("group", group_id, message)
    
    async def connect(self):
        """连接到WebSocket服务器"""
        if not WEBSOCKETS_AVAILABLE:
            print("[QQBot] 错误: websockets库未安装，请运行: pip install websockets")
            self.running = False
            return
            
        headers = {}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        
        try:
            async with websockets.connect(self.ws_url, extra_headers=headers) as ws:
                self.ws = ws
                print(f"[QQBot] 已连接到 {self.ws_url}")
                
                # 发送上线消息
                await ws.send(json.dumps({
                    "action": "get_login_info",
                    "params": {}
                }))
                
                # 处理消息
                async for raw_message in ws:
                    try:
                        await self.handle_message(raw_message)
                    except Exception as e:
                        print(f"[QQBot] 处理消息出错: {e}")
                        
        except Exception as e:
            print(f"[QQBot] 连接失败: {e}")
            self.running = False
    
    async def handle_message(self, raw_message: str):
        """处理接收到的消息"""
        try:
            message = json.loads(raw_message)
            
            # 处理CQ事件
            if "post_type" in message:
                post_type = message.get("post_type")
                
                if post_type == "message":
                    # 私聊或群消息
                    message_type = message.get("message_type")
                    raw_msg = message.get("raw_message", "")
                    
                    if message_type == "private":
                        user_id = message.get("user_id")
                        if not self.is_allowed(user_id=user_id):
                            return
                    
                    elif message_type == "group":
                        group_id = message.get("group_id")
                        user_id = message.get("user_id")
                        if not self.is_allowed(group_id=group_id, user_id=user_id):
                            return
                    
                    # 调用消息回调
                    if self.message_callback:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(
                            None, 
                            self.message_callback, 
                            message_type, 
                            message
                        )
                        
        except json.JSONDecodeError:
            pass
    
    def start(self, message_callback: Callable[[str, Dict], None] = None):
        """启动机器人"""
        if message_callback:
            self.message_callback = message_callback
        
        self.running = True
        
        def run_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            while self.running:
                try:
                    loop.run_until_complete(self.connect())
                except Exception as e:
                    print(f"[QQBot] 连接错误: {e}")
                    import time
                    time.sleep(5)  # 重连等待
        
        thread = threading.Thread(target=run_loop, daemon=True)
        thread.start()
        return thread
    
    def stop(self):
        """停止机器人"""
        self.running = False
        if self.ws:
            asyncio.run(self.ws.close())


# 全局机器人实例
_qq_bot: Optional[QQBot] = None


def get_qq_bot() -> Optional[QQBot]:
    """获取QQ机器人实例"""
    return _qq_bot


def init_qq_bot(ws_url: str, access_token: str = None, 
                allowed_groups: List[int] = None, allowed_qqs: List[int] = None) -> QQBot:
    """初始化QQ机器人"""
    global _qq_bot
    _qq_bot = QQBot(ws_url, access_token, allowed_groups, allowed_qqs)
    return _qq_bot


def start_qq_bot(ws_url: str, access_token: str = None,
                 allowed_groups: List[int] = None, allowed_qqs: List[int] = None,
                 message_callback: Callable[[str, Dict], None] = None) -> QQBot:
    """启动QQ机器人"""
    global _qq_bot
    _qq_bot = QQBot(ws_url, access_token, allowed_groups, allowed_qqs)
    _qq_bot.start(message_callback)
    return _qq_bot


def stop_qq_bot():
    """停止QQ机器人"""
    global _qq_bot
    if _qq_bot:
        _qq_bot.stop()
        _qq_bot = None
