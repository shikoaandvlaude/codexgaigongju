"""
RedOps - 连接器API (Telegram/QQ)
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from web.app.core.config_manager import get_config_manager
from web.app.integrations.telegram_bot import (
    get_telegram_bot, init_telegram_bot, start_telegram_bot, stop_telegram_bot
)
from web.app.integrations.qq_bot import (
    get_qq_bot, init_qq_bot, start_qq_bot, stop_qq_bot
)

router = APIRouter(prefix="/api/connectors", tags=["连接器"])


# ==================== Telegram API ====================

class TelegramConfigRequest(BaseModel):
    """Telegram配置请求"""
    enabled: bool
    bot_token: str
    allowed_chats: List[int] = []


@router.get("/telegram/status")
async def get_telegram_status():
    """获取Telegram机器人状态"""
    bot = get_telegram_bot()
    config = get_config_manager()
    
    if bot:
        me = bot.get_me()
        return {
            "enabled": True,
            "connected": bot.running,
            "bot_info": me if me.get("ok") else None
        }
    else:
        return {
            "enabled": config.get("telegram.enabled", False),
            "connected": False
        }


@router.post("/telegram/config")
async def configure_telegram(request: TelegramConfigRequest):
    """配置Telegram机器人"""
    config = get_config_manager()
    
    # 保存配置
    config.set("telegram.enabled", request.enabled)
    config.set("telegram.bot_token", request.bot_token)
    config.set("telegram.allowed_chats", request.allowed_chats)
    config.save()
    
    if request.enabled and request.bot_token:
        # 停止现有机器人
        stop_telegram_bot()
        
        # 启动新机器人
        start_telegram_bot(
            bot_token=request.bot_token,
            allowed_chats=request.allowed_chats
        )
        
        return {"success": True, "message": "Telegram机器人已启动"}
    else:
        # 停止机器人
        stop_telegram_bot()
        return {"success": True, "message": "Telegram机器人已停止"}


# ==================== QQ API ====================

class QQConfigRequest(BaseModel):
    """QQ配置请求"""
    enabled: bool
    ws_url: str = "ws://127.0.0.1:6700"
    access_token: Optional[str] = None
    allowed_groups: List[int] = []
    allowed_qqs: List[int] = []


@router.get("/qq/status")
async def get_qq_status():
    """获取QQ机器人状态"""
    bot = get_qq_bot()
    config = get_config_manager()
    
    if bot:
        return {
            "enabled": True,
            "connected": bot.running,
            "ws_url": bot.ws_url
        }
    else:
        return {
            "enabled": config.get("qq.enabled", False),
            "connected": False
        }


@router.post("/qq/config")
async def configure_qq(request: QQConfigRequest):
    """配置QQ机器人"""
    config = get_config_manager()
    
    # 保存配置
    config.set("qq.enabled", request.enabled)
    config.set("qq.ws_url", request.ws_url)
    config.set("qq.access_token", request.access_token or "")
    config.set("qq.allowed_groups", request.allowed_groups)
    config.set("qq.allowed_qqs", request.allowed_qqs)
    config.save()
    
    if request.enabled and request.ws_url:
        # 停止现有机器人
        stop_qq_bot()
        
        # 启动新机器人
        start_qq_bot(
            ws_url=request.ws_url,
            access_token=request.access_token,
            allowed_groups=request.allowed_groups,
            allowed_qqs=request.allowed_qqs
        )
        
        return {"success": True, "message": "QQ机器人已启动"}
    else:
        # 停止机器人
        stop_qq_bot()
        return {"success": True, "message": "QQ机器人已停止"}


# ==================== 通用状态 ====================

@router.get("/status")
async def get_all_connectors_status():
    """获取所有连接器状态"""
    telegram_status = await get_telegram_status()
    qq_status = await get_qq_status()
    
    return {
        "telegram": telegram_status,
        "qq": qq_status
    }
