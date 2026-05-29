"""
RedOps - Telegram机器人模块
支持通过Telegram与Agent交互
"""

import os
import json
import threading
import time
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
import requests


class TelegramBot:
    """Telegram机器人"""
    
    def __init__(self, bot_token: str, allowed_chats: List[int] = None):
        self.bot_token = bot_token
        self.allowed_chats = allowed_chats or []
        self.api_base = f"https://api.telegram.org/bot{bot_token}"
        self.running = False
        self.offset = 0
        self.message_callback: Optional[Callable] = None
        self._poll_thread = None
    
    def is_allowed(self, chat_id: int) -> bool:
        """检查是否允许该聊天"""
        if not self.allowed_chats:
            return True  # 如果没有白名单，允许所有
        return chat_id in self.allowed_chats
    
    def send_message(self, chat_id: int, text: str, parse_mode: str = None) -> Dict[str, Any]:
        """发送消息"""
        url = f"{self.api_base}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": text
        }
        if parse_mode:
            data["parse_mode"] = parse_mode
        
        try:
            resp = requests.post(url, json=data, timeout=10)
            return resp.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def send_document(self, chat_id: int, document: str, caption: str = None) -> Dict[str, Any]:
        """发送文档"""
        url = f"{self.api_base}/sendDocument"
        data = {
            "chat_id": chat_id,
            "document": document
        }
        if caption:
            data["caption"] = caption
        
        try:
            resp = requests.post(url, json=data, timeout=10)
            return resp.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def get_updates(self, timeout: int = 60) -> List[Dict]:
        """获取更新"""
        url = f"{self.api_base}/getUpdates"
        params = {
            "offset": self.offset,
            "timeout": timeout
        }
        
        try:
            resp = requests.get(url, params=params, timeout=timeout + 5)
            data = resp.json()
            if data.get("ok"):
                return data.get("result", [])
            return []
        except Exception as e:
            print(f"获取更新失败: {e}")
            return []
    
    def process_updates(self):
        """处理更新"""
        while self.running:
            try:
                updates = self.get_updates(timeout=30)
                
                for update in updates:
                    # 更新offset
                    self.offset = max(self.offset, update.get("update_id", 0) + 1)
                    
                    if "message" not in update:
                        continue
                    
                    message = update["message"]
                    chat_id = message["chat"]["id"]
                    text = message.get("text", "")
                    
                    # 检查权限
                    if not self.is_allowed(chat_id):
                        self.send_message(chat_id, "❌ 您没有权限使用此机器人")
                        continue
                    
                    # 调用回调
                    if self.message_callback:
                        try:
                            self.message_callback(chat_id, text)
                        except Exception as e:
                            print(f"处理消息出错: {e}")
                
                time.sleep(1)
                
            except Exception as e:
                print(f"处理更新出错: {e}")
                time.sleep(5)
    
    def start(self, message_callback: Callable[[int, str], None] = None):
        """启动机器人"""
        if message_callback:
            self.message_callback = message_callback
        
        self.running = True
        
        # 在新线程中运行轮询
        self._poll_thread = threading.Thread(target=self.process_updates, daemon=True)
        self._poll_thread.start()
        return self._poll_thread
    
    def stop(self):
        """停止机器人"""
        self.running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=2)
    
    def get_me(self) -> Dict[str, Any]:
        """获取机器人信息"""
        try:
            resp = requests.get(f"{self.api_base}/getMe", timeout=10)
            return resp.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}


# 全局机器人实例
_telegram_bot: Optional[TelegramBot] = None


def get_telegram_bot() -> Optional[TelegramBot]:
    """获取Telegram机器人实例"""
    return _telegram_bot


def init_telegram_bot(bot_token: str, allowed_chats: List[int] = None) -> TelegramBot:
    """初始化Telegram机器人"""
    global _telegram_bot
    _telegram_bot = TelegramBot(bot_token, allowed_chats)
    return _telegram_bot


def start_telegram_bot(bot_token: str, allowed_chats: List[int] = None, 
                       message_callback: Callable[[int, str], None] = None) -> TelegramBot:
    """启动Telegram机器人"""
    global _telegram_bot
    _telegram_bot = TelegramBot(bot_token, allowed_chats)
    _telegram_bot.start(message_callback)
    return _telegram_bot


def stop_telegram_bot():
    """停止Telegram机器人"""
    global _telegram_bot
    if _telegram_bot:
        _telegram_bot.stop()
        _telegram_bot = None
