"""
RedOps Web - Skill系统
可动态加载的技能模块
"""

from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod


class BaseSkill(ABC):
    name: str = "base_skill"
    description: str = "基础技能"
    category: str = "general"
    
    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def get_schema(self) -> Dict[str, Any]:
        pass


class SkillRegistry:
    def __init__(self):
        self.skills: Dict[str, BaseSkill] = {}
        self.categories: Dict[str, List[str]] = {}
        self._load_builtin_skills()
    
    def _load_builtin_skills(self):
        self.register(PortScanSkill())
        self.register(VulnScanSkill())
        self.register(FOFASkill())
        self.register(POCVerifySkill())
        self.register(JSAnalysisSkill())
        self.register(SubdomainEnumSkill())
        self.register(CMSIdentifySkill())
        self.register(ReportGenSkill())
    
    def register(self, skill: BaseSkill):
        self.skills[skill.name] = skill
        if skill.category not in self.categories:
            self.categories[skill.category] = []
        self.categories[skill.category].append(skill.name)
    
    def get_skill(self, name: str):
        return self.skills.get(name)
    
    def list_skills(self, category: str = None) -> List[Dict[str, Any]]:
        result = []
        skill_names = self.categories.get(category, []) if category else list(self.skills.keys())
        for name in skill_names:
            skill = self.skills.get(name)
            if skill:
                result.append({"name": skill.name, "description": skill.description, "category": skill.category, "schema": skill.get_schema()})
        return result
    
    def list_categories(self) -> List[str]:
        return list(self.categories.keys())
    
    def execute_skill(self, name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        skill = self.get_skill(name)
        if not skill:
            return {"error": f"Skill '{name}' not found"}
        try:
            return skill.execute(params)
        except Exception as e:
            return {"error": str(e)}


class PortScanSkill(BaseSkill):
    name = "port_scan"
    description = "端口扫描技能"
    category = "scan"
    def get_schema(self): return {"target": {"type": "string", "description": "目标IP或域名"}}
    def execute(self, params): return {"skill": self.name, "status": "ready", "target": params.get("target")}


class VulnScanSkill(BaseSkill):
    name = "vuln_scan"
    description = "漏洞扫描技能"
    category = "scan"
    def get_schema(self): return {"target": {"type": "string", "description": "目标URL"}}
    def execute(self, params): return {"skill": self.name, "status": "ready", "target": params.get("target")}


class FOFASkill(BaseSkill):
    name = "fofa_search"
    description = "FOFA资产搜索"
    category = "recon"
    def get_schema(self): return {"query": {"type": "string"}}
    def execute(self, params): return {"skill": self.name, "status": "ready"}


class POCVerifySkill(BaseSkill):
    name = "poc_verify"
    description = "POC验证"
    category = "exploit"
    def get_schema(self): return {"target": {"type": "string"}, "poc_name": {"type": "string"}}
    def execute(self, params): return {"skill": self.name, "status": "ready"}


class JSAnalysisSkill(BaseSkill):
    name = "js_analyze"
    description = "JS分析"
    category = "analyze"
    def get_schema(self): return {"target": {"type": "string"}}
    def execute(self, params): return {"skill": self.name, "status": "ready"}


class SubdomainEnumSkill(BaseSkill):
    name = "subdomain_enum"
    description = "子域名枚举"
    category = "recon"
    def get_schema(self): return {"domain": {"type": "string"}}
    def execute(self, params): return {"skill": self.name, "status": "ready"}


class CMSIdentifySkill(BaseSkill):
    name = "cms_identify"
    description = "CMS识别"
    category = "identify"
    def get_schema(self): return {"target": {"type": "string"}}
    def execute(self, params): return {"skill": self.name, "status": "ready"}


class ReportGenSkill(BaseSkill):
    name = "report_gen"
    description = "报告生成"
    category = "util"
    def get_schema(self): return {"format": {"type": "string", "default": "html"}}
    def execute(self, params): return {"skill": self.name, "status": "ready"}


_skill_registry: Optional[SkillRegistry] = None


def get_skill_registry() -> SkillRegistry:
    global _skill_registry
    if _skill_registry is None:
        _skill_registry = SkillRegistry()
    return _skill_registry
