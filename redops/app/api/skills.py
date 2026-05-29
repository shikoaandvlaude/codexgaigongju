"""
RedOps Web - Skill API
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

from app.core.skill_registry import get_skill_registry

router = APIRouter()


class SkillExecuteRequest(BaseModel):
    skill_name: str
    params: Dict[str, Any] = {}


@router.get("/")
async def list_all_skills():
    registry = get_skill_registry()
    return {"categories": registry.list_categories(), "skills": registry.list_skills()}


@router.get("/categories")
async def list_categories():
    registry = get_skill_registry()
    return {"categories": registry.list_categories()}


@router.get("/{skill_name}")
async def get_skill_info(skill_name: str):
    registry = get_skill_registry()
    skill = registry.get_skill(skill_name)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    return {"name": skill.name, "description": skill.description, "category": skill.category, "schema": skill.get_schema()}


@router.post("/execute")
async def execute_skill(request: SkillExecuteRequest):
    registry = get_skill_registry()
    result = registry.execute_skill(request.skill_name, request.params)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/{skill_name}/execute")
async def execute_skill_by_name(skill_name: str, params: Dict[str, Any] = {}):
    registry = get_skill_registry()
    result = registry.execute_skill(skill_name, params)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result
