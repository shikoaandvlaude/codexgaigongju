"""
RedOps Web - 配置API
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.core import init_llm_agent, is_llm_ready, get_memory_system

router = APIRouter()

current_config = {}


class LLMConfig(BaseModel):
    provider: str = "deepseek"
    api_key: Optional[str] = None
    model: str = "deepseek-chat"


@router.get("/")
async def get_config():
    config = current_config.copy()
    if config.get("llm") and config["llm"].get("api_key"):
        config["llm"]["api_key"] = "***"
    config["llm_ready"] = is_llm_ready()
    return config


@router.post("/llm")
async def update_llm_config(config: LLMConfig):
    global current_config
    current_config["llm"] = config.dict()
    if config.api_key:
        init_llm_agent(api_key=config.api_key, model=config.model)
    return {"status": "updated", "llm_ready": is_llm_ready()}


@router.get("/llm/status")
async def get_llm_status():
    return {"ready": is_llm_ready(), "model": current_config.get("llm", {}).get("model") if current_config.get("llm") else None}


@router.post("/llm/init")
async def init_llm(api_key: str, model: str = "deepseek-chat"):
    try:
        init_llm_agent(api_key=api_key, model=model)
        return {"status": "success", "llm_ready": is_llm_ready(), "model": model}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/providers")
async def list_llm_providers():
    return {"providers": [
        {"id": "deepseek", "name": "DeepSeek", "models": ["deepseek-chat"]},
        {"id": "openai", "name": "OpenAI", "models": ["gpt-4", "gpt-3.5-turbo"]},
        {"id": "anthropic", "name": "Anthropic", "models": ["claude-3"]},
        {"id": "ollama", "name": "Ollama", "models": ["llama2", "mistral"]},
    ]}


@router.get("/memory/stats")
async def get_memory_stats():
    memory = get_memory_system()
    return memory.get_stats()
