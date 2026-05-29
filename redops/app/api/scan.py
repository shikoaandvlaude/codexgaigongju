"""
RedOps Web - 扫描API
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.core.manager import ScanManager

router = APIRouter()
scan_manager = ScanManager()


class ScanRequest(BaseModel):
    targets: List[str]
    scan_type: str
    options: Optional[Dict[str, Any]] = {}


@router.post("/start")
async def start_scan(request: ScanRequest):
    if not request.targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    
    task_ids = []
    for target in request.targets:
        task_id = scan_manager.create_task(target, request.scan_type, request.options)
        task_ids.append(task_id)
    
    return {"task_ids": task_ids, "status": "started", "message": f"Created {len(task_ids)} scan tasks"}


@router.get("/tasks")
async def list_tasks(status: Optional[str] = None):
    tasks = scan_manager.get_all_tasks()
    if status:
        tasks = [t for t in tasks if t["status"] == status]
    return tasks


@router.get("/task/{task_id}")
async def get_task_result(task_id: str):
    task = scan_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task.task_id, "status": task.status, "results": task.results, "logs": task.logs}


@router.delete("/task/{task_id}")
async def delete_task(task_id: str):
    if scan_manager.delete_task(task_id):
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Task not found")


@router.get("/active")
async def get_active_scans():
    return {"active_count": scan_manager.get_active_count(), "targets": scan_manager.targets}
