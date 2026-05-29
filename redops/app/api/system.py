"""
RedOps - 系统控制API
提供执行命令、文件管理等接口
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from web.app.core.executor import get_executor, init_executor
from web.app.core.auto_install import get_auto_installer
from web.app.core.config_manager import get_config_manager

router = APIRouter(prefix="/api/system", tags=["系统控制"])


# ==================== 请求模型 ====================

class CommandRequest(BaseModel):
    """命令执行请求"""
    command: str
    cwd: Optional[str] = None
    timeout: Optional[int] = 30


class FileReadRequest(BaseModel):
    """文件读取请求"""
    path: str


class FileWriteRequest(BaseModel):
    """文件写入请求"""
    path: str
    content: str


class DirectoryListRequest(BaseModel):
    """目录列表请求"""
    path: str = "."


class PermissionConfigRequest(BaseModel):
    """权限配置请求"""
    root_mode: bool
    allowed_paths: List[str]


class ToolInstallRequest(BaseModel):
    """工具安装请求"""
    tool_name: str


# ==================== 系统接口 ====================

@router.get("/info")
async def get_system_info():
    """获取系统信息"""
    executor = get_executor()
    return executor.get_system_info()


@router.post("/execute")
async def execute_command(request: CommandRequest):
    """执行系统命令"""
    executor = get_executor()
    
    try:
        if request.cwd:
            result = executor.execute_with_workdir(request.command, request.cwd)
        else:
            result = executor.execute(request.command, timeout=request.timeout)
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_command_history():
    """获取命令历史"""
    executor = get_executor()
    return {"history": executor.get_command_history()}


# ==================== 文件管理接口 ====================

@router.post("/file/read")
async def read_file(request: FileReadRequest):
    """读取文件"""
    executor = get_executor()
    result = executor.read_file(request.path)
    
    if not result.get("success"):
        raise HTTPException(status_code=403, detail=result.get("error", "读取失败"))
    
    return result


@router.post("/file/write")
async def write_file(request: FileWriteRequest):
    """写入文件"""
    executor = get_executor()
    result = executor.write_file(request.path, request.content)
    
    if not result.get("success"):
        raise HTTPException(status_code=403, detail=result.get("error", "写入失败"))
    
    return result


@router.post("/directory/list")
async def list_directory(request: DirectoryListRequest):
    """列出目录内容"""
    executor = get_executor()
    result = executor.list_directory(request.path)
    
    if not result.get("success"):
        raise HTTPException(status_code=403, detail=result.get("error", "访问失败"))
    
    return result


# ==================== 权限管理接口 ====================

@router.get("/permissions")
async def get_permissions():
    """获取当前权限配置"""
    executor = get_executor()
    config = get_config_manager()
    
    return {
        "root_mode": executor.permission_guard.root_mode,
        "allowed_paths": executor.permission_guard.allowed_paths,
        "dangerous_paths": executor.permission_guard.dangerous_paths
    }


@router.post("/permissions")
async def set_permissions(request: PermissionConfigRequest):
    """设置权限配置"""
    executor = get_executor()
    
    executor.permission_guard.set_root_mode(request.root_mode)
    executor.permission_guard.set_allowed_paths(request.allowed_paths)
    
    # 保存到配置
    config = get_config_manager()
    config.set("system.root_mode", request.root_mode)
    config.set("system.allowed_paths", request.allowed_paths)
    config.save()
    
    return {"success": True, "message": "权限配置已更新"}


# ==================== 工具管理接口 ====================

@router.get("/tools")
async def list_tools():
    """列出可用工具"""
    installer = get_auto_installer()
    tools = installer.get_available_tools()
    return {"tools": tools}


@router.post("/tools/install")
async def install_tool(request: ToolInstallRequest):
    """安装工具"""
    installer = get_auto_installer()
    result = installer.install_tool(request.tool_name)
    
    return result


@router.get("/tools/history")
async def get_install_history():
    """获取安装历史"""
    installer = get_auto_installer()
    return {"history": installer.get_install_history()}


@router.post("/tools/check")
async def check_and_install(command: str):
    """检查并自动安装缺失工具"""
    installer = get_auto_installer()
    config = get_config_manager()
    
    if not config.get("system.auto_install", True):
        return {"success": False, "error": "自动安装已禁用"}
    
    # 检测缺失工具
    tool_name = installer.detect_missing_tool(command)
    
    if tool_name:
        # 自动安装
        result = installer.install_tool(tool_name)
        return result
    else:
        return {"success": False, "error": "未检测到缺失工具"}
