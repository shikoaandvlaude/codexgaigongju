"""
RedOps - Web后端主程序
渗透测试Agent Web界面后端 V2.0
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
import json
import uuid
import os
import sys

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app.api import chat, targets, scan, config as api_config, skills, system, connectors
from web.app.core.manager import ScanManager
from web.app.core.config_manager import get_config_manager, init_config_manager
from web.app.core.executor import init_executor, get_executor
from web.app.core.auto_install import get_auto_installer

# 初始化配置管理器
config_manager = init_config_manager()

# 初始化执行器
root_mode = config_manager.get("system.root_mode", True)
allowed_paths = config_manager.get("system.allowed_paths", [])
init_executor(root_mode=root_mode, allowed_paths=allowed_paths)

# 创建应用
app = FastAPI(title="RedOps Agent", version="2.0.0", description="智能渗透测试Agent框架")

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 扫描管理器
scan_manager = ScanManager()

# 挂载静态文件
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")


class Message(BaseModel):
    """聊天消息"""
    role: str
    content: str
    timestamp: Optional[str] = None


class ScanRequest(BaseModel):
    """扫描请求"""
    targets: List[str]
    scan_type: str  # "nuclei", "poc", "all"
    options: Optional[Dict[str, Any]] = {}


class FOFARequest(BaseModel):
    """FOFA查询请求"""
    query: str
    limit: int = 10


# 前端页面路由
@app.get("/", response_class=HTMLResponse)
async def read_root():
    """返回Web界面"""
    index_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>RedOps Agent</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>RedOps Agent</h1>
        <p>Frontend not found. Please create frontend/index.html</p>
    </body>
    </html>
    """


# API路由
app.include_router(chat.router, prefix="/api/chat", tags=["Chat"])
app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scan"])
app.include_router(api_config.router, prefix="/api/config", tags=["Config"])
app.include_router(skills.router, prefix="/api/skills", tags=["Skills"])
app.include_router(system.router, prefix="/api/system", tags=["System"])
app.include_router(connectors.router, prefix="/api/connectors", tags=["Connectors"])


# WebSocket连接管理器
class ConnectionManager:
    """WebSocket连接管理器"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def send_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass


manager = ConnectionManager()


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket实时通信"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # 处理接收到的消息
            message = json.loads(data)
            
            if message.get("type") == "scan_log":
                # 广播扫描日志
                await manager.broadcast(json.dumps({
                    "type": "scan_log",
                    "data": message.get("data")
                }))
            elif message.get("type") == "scan_complete":
                # 扫描完成通知
                await manager.broadcast(json.dumps({
                    "type": "scan_complete",
                    "data": message.get("data")
                }))
            elif message.get("type") == "execute_command":
                # 执行命令
                from web.app.core.executor import get_executor
                executor = get_executor()
                cmd = message.get("command")
                result = executor.execute(cmd, timeout=30)
                await websocket.send_text(json.dumps({
                    "type": "command_result",
                    "result": result
                }))
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/api/status")
async def get_status():
    """获取系统状态"""
    executor = get_executor()
    sys_info = executor.get_system_info()
    
    return {
        "status": "online",
        "version": "2.0.0",
        "active_scans": scan_manager.get_active_count(),
        "targets_count": len(scan_manager.targets),
        "system_info": sys_info
    }


# FOFA API
from web.app.integrations.fofa import FOFAClient, FOFA_QUERIES, build_query

fofa_client = FOFAClient()


@app.post("/api/fofa/search")
async def fofa_search(query: str, limit: int = 100, page: int = 1):
    """FOFA搜索"""
    result = fofa_client.search(query, size=limit, page=page)
    return result


@app.get("/api/fofa/queries")
async def get_fofa_queries():
    """获取常用FOFA查询"""
    return FOFA_QUERIES


@app.post("/api/fofa/build")
async def fofa_build_query(keyword: str, **kwargs):
    """构建FOFA查询"""
    query = build_query(keyword, **kwargs)
    return {"query": query}


@app.post("/api/fofa/quick/{query_type}")
async def fofa_quick_search(query_type: str, limit: int = 100):
    """快速FOFA查询"""
    if query_type not in FOFA_QUERIES:
        return {"error": "Unknown query type"}
    
    query = FOFA_QUERIES[query_type]
    result = fofa_client.search(query, size=limit)
    return result


@app.on_event("startup")
async def startup_event():
    """启动时初始化"""
    print("=" * 50)
    print("RedOps Agent V2.0 启动中...")
    print("像OpenClaw一样直接执行命令！")
    print("=" * 50)
    
    # 初始化配置
    config = get_config_manager()
    print(f"配置文件: {config.config_path}")
    
    # 初始化执行器
    executor = get_executor()
    print(f"Root模式: {executor.permission_guard.root_mode}")
    print(f"允许路径: {executor.permission_guard.allowed_paths}")
    
    # 初始化LLM Agent（如果配置了API Key）
    llm_config = config.get("llm", {})
    api_key = llm_config.get("api_key", "")
    if api_key:
        from web.app.core.llm_agent import init_llm_agent
        model = llm_config.get("model", "deepseek-chat")
        base_url = llm_config.get("base_url", "https://api.deepseek.com/v1")
        
        # 初始化LLM并传入executor
        init_llm_agent(
            api_key=api_key,
            model=model,
            base_url=base_url,
            executor=executor
        )
        print(f"LLM: {model} 已就绪")
    else:
        print("LLM: 未配置API Key，将使用本地执行模式")
    
    # 检查自动安装
    installer = get_auto_installer()
    print(f"自动安装: 已就绪")
    
    print("=" * 50)
    print("启动完成！访问 http://localhost:8000")
    print("=" * 50)


if __name__ == "__main__":
    import uvicorn
    # 从配置读取 host 和 port
    host = config_manager.get("web.host", "0.0.0.0")
    port = config_manager.get("web.port", 8000)
    uvicorn.run(app, host=host, port=port)
