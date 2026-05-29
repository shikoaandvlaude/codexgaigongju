"""
RedOps Web - 目标管理API
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid
import re

router = APIRouter()

targets_db = {}
target_groups_db = {}


class Target(BaseModel):
    id: Optional[str] = None
    url: str
    name: Optional[str] = None
    tags: List[str] = []
    status: str = "active"


def validate_target(url: str) -> bool:
    url_pattern = r'^https?://[^\s]+$'
    domain_pattern = r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(url_pattern, url) or re.match(domain_pattern, url) or re.match(ip_pattern, url))


@router.post("/targets")
async def create_target(target: Target):
    if not validate_target(target.url):
        raise HTTPException(status_code=400, detail="Invalid target format")
    target.id = str(uuid.uuid4())
    target.created_at = datetime.now().isoformat()
    targets_db[target.id] = target
    return target


@router.get("/targets")
async def list_targets():
    return list(targets_db.values())


@router.get("/targets/{target_id}")
async def get_target(target_id: str):
    if target_id not in targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    return targets_db[target_id]


@router.delete("/targets/{target_id}")
async def delete_target(target_id: str):
    if target_id not in targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    del targets_db[target_id]
    return {"status": "deleted"}


@router.post("/targets/batch")
async def create_targets_batch(targets: List[Target]):
    created = []
    errors = []
    for target in targets:
        if not validate_target(target.url):
            errors.append({"url": target.url, "error": "Invalid format"})
            continue
        target.id = str(uuid.uuid4())
        target.created_at = datetime.now().isoformat()
        targets_db[target.id] = target
        created.append(target)
    return {"created": len(created), "errors": errors}


@router.post("/targets/import")
async def import_targets(content: str, tags: List[str] = []):
    lines = content.replace(',', '\n').replace(' ', '\n').split('\n')
    lines = [line.strip() for line in lines if line.strip()]
    created = []
    for line in lines:
        target_url = line
        if not target_url.startswith(('http://', 'https://')):
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_url):
                target_url = 'http://' + target_url
            else:
                target_url = 'https://' + target_url
        if validate_target(target_url):
            target = Target(url=target_url, tags=tags)
            target.id = str(uuid.uuid4())
            target.created_at = datetime.now().isoformat()
            targets_db[target.id] = target
            created.append(target)
    return {"total": len(lines), "created": len(created)}


@router.get("/tags")
async def list_tags():
    tags = set()
    for target in targets_db.values():
        tags.update(target.tags)
    return {"tags": sorted(list(tags))}
