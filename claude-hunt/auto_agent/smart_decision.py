#!/usr/bin/env python3
"""
Smart Decision Engine — 智能决策引擎
参考 HexStrike AI 的 IntelligentDecisionEngine 设计
根据目标画像自动选择最优工具链和攻击路径

核心能力：
1. 目标类型识别（Web/API/Network/Cloud/Binary/IoT）
2. 技术栈指纹检测（从响应头/内容推断）
3. 攻击面评分（量化风险等级）
4. 工具链自动编排（根据目标画像选择最优工具组合）
5. 攻击模式推荐（预置的攻击序列）

来源: 参考 hexstrike-ai IntelligentDecisionEngine 架构
"""

import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# 目标类型枚举
# ═══════════════════════════════════════════════════════════════

class TargetType(Enum):
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    NETWORK_HOST = "network_host"
    CLOUD_SERVICE = "cloud_service"
    IOT_DEVICE = "iot_device"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"


class TechnologyStack(Enum):
    PHP = "php"
    NODEJS = "nodejs"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    RUBY = "ruby"
    GO = "go"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    LARAVEL = "laravel"
    DJANGO = "django"
    FLASK = "flask"
    SPRING = "spring"
    EXPRESS = "express"
    NEXTJS = "nextjs"
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    GRAPHQL = "graphql"
    UNKNOWN = "unknown"


# ═══════════════════════════════════════════════════════════════
# 目标画像
# ═══════════════════════════════════════════════════════════════

@dataclass
class TargetProfile:
    """目标画像 — 包含所有已知信息"""
    target: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    technologies: list = field(default_factory=list)
    cms_type: str = ""
    open_ports: list = field(default_factory=list)
    has_waf: bool = False
    waf_type: str = ""
    attack_surface_score: float = 0.0
    risk_level: str = "medium"
    confidence_score: float = 0.0


# ═══════════════════════════════════════════════════════════════
# 预置攻击模式（参考 HexStrike 攻击链）
# ═══════════════════════════════════════════════════════════════

ATTACK_PATTERNS = {
    "web_reconnaissance": [
        {"tool": "subfinder", "priority": 1, "params": "-silent"},
        {"tool": "httpx", "priority": 2, "params": "-silent -tech-detect -status-code"},
        {"tool": "katana", "priority": 3, "params": "-d 3 -silent"},
        {"tool": "gau", "priority": 4, "params": ""},
        {"tool": "nuclei", "priority": 5, "params": "-severity critical,high -rate-limit 5"},
    ],
    "api_testing": [
        {"tool": "httpx", "priority": 1, "params": "-silent -tech-detect"},
        {"tool": "arjun", "priority": 2, "params": "--stable"},
        {"tool": "paramspider", "priority": 3, "params": ""},
        {"tool": "nuclei", "priority": 4, "params": "-tags api,graphql,jwt -severity high,critical"},
        {"tool": "ffuf", "priority": 5, "params": "-ac -t 3 -rate 5"},
    ],
    "bug_bounty_recon": [
        {"tool": "subfinder", "priority": 1, "params": "-silent -all"},
        {"tool": "httpx", "priority": 2, "params": "-silent -tech-detect -status-code"},
        {"tool": "katana", "priority": 3, "params": "-d 3 -js-crawl -silent"},
        {"tool": "gau", "priority": 4, "params": ""},
        {"tool": "waybackurls", "priority": 5, "params": ""},
        {"tool": "paramspider", "priority": 6, "params": ""},
        {"tool": "arjun", "priority": 7, "params": "--stable"},
    ],
    "bug_bounty_hunting": [
        {"tool": "nuclei", "priority": 1, "params": "-severity critical,high -tags rce,sqli,xss,ssrf"},
        {"tool": "dalfox", "priority": 2, "params": "pipe --worker 2 --delay 300"},
        {"tool": "ffuf", "priority": 3, "params": "-ac -t 3 -rate 5 -mc 200,301,302,403"},
    ],
    "iot_device_testing": [
        {"tool": "nmap", "priority": 1, "params": "-sV -sC -p 80,443,1883,8883,5683,8080"},
        {"tool": "httpx", "priority": 2, "params": "-silent"},
        {"tool": "nuclei", "priority": 3, "params": "-tags iot,default-login,firmware"},
    ],
    "cloud_assessment": [
        {"tool": "subfinder", "priority": 1, "params": "-silent"},
        {"tool": "httpx", "priority": 2, "params": "-silent -tech-detect"},
        {"tool": "nuclei", "priority": 3, "params": "-tags cloud,aws,azure,gcp,s3 -severity high,critical"},
    ],
}

# 技术栈 → 漏洞类型 优先级映射
TECH_VULN_PRIORITY = {
    "php": ["sqli", "lfi", "rce", "file_upload", "deserialization"],
    "nodejs": ["prototype_pollution", "ssrf", "path_traversal", "ssti"],
    "python": ["ssti", "ssrf", "deserialization", "command_injection"],
    "java": ["deserialization", "xxe", "ssti", "rce", "log4j"],
    "wordpress": ["plugin_vuln", "sqli", "xss", "file_upload", "auth_bypass"],
    "laravel": ["mass_assignment", "idor", "ssti", "debug_mode"],
    "spring": ["actuator_exposure", "rce", "ssrf", "deserialization"],
    "graphql": ["introspection", "idor", "injection", "dos"],
    "nextjs": ["ssrf", "open_redirect", "path_traversal"],
    "django": ["idor", "ssti", "mass_assignment", "debug_mode"],
}


# ═══════════════════════════════════════════════════════════════
# 智能决策引擎
# ═══════════════════════════════════════════════════════════════

class SmartDecisionEngine:
    """
    智能决策引擎 — 根据目标画像自动选择攻击策略

    用法:
        engine = SmartDecisionEngine()
        profile = engine.analyze_target("https://target.com")
        tools = engine.select_tools(profile)
        pattern = engine.recommend_attack_pattern(profile)
    """

    def __init__(self, config: dict = None):
        self.config = config or {}

    def analyze_target(self, target: str, extra_info: dict = None) -> TargetProfile:
        """分析目标，生成目标画像"""
        profile = TargetProfile(target=target)
        extra_info = extra_info or {}

        # 1. 确定目标类型
        profile.target_type = self._determine_target_type(target)

        # 2. 技术栈检测（从已有信息推断）
        if extra_info.get("headers"):
            profile.technologies = self._detect_tech_from_headers(extra_info["headers"])
        if extra_info.get("body"):
            profile.technologies.extend(self._detect_tech_from_content(extra_info["body"]))

        # 3. WAF 信息
        if extra_info.get("waf_type"):
            profile.has_waf = True
            profile.waf_type = extra_info["waf_type"]

        # 4. 开放端口
        if extra_info.get("ports"):
            profile.open_ports = extra_info["ports"]

        # 5. 攻击面评分
        profile.attack_surface_score = self._calculate_attack_surface(profile)
        profile.risk_level = self._determine_risk_level(profile)

        return profile

    def select_tools(self, profile: TargetProfile) -> list[dict]:
        """根据目标画像选择最优工具组合"""
        tools = []

        if profile.target_type == TargetType.WEB_APPLICATION:
            tools = ATTACK_PATTERNS.get("bug_bounty_recon", [])
        elif profile.target_type == TargetType.API_ENDPOINT:
            tools = ATTACK_PATTERNS.get("api_testing", [])
        elif profile.target_type == TargetType.IOT_DEVICE:
            tools = ATTACK_PATTERNS.get("iot_device_testing", [])
        elif profile.target_type == TargetType.CLOUD_SERVICE:
            tools = ATTACK_PATTERNS.get("cloud_assessment", [])
        elif profile.target_type == TargetType.MOBILE_APP:
            # APP 目标不走传统工具链，走 app_recon
            tools = []
        else:
            tools = ATTACK_PATTERNS.get("web_reconnaissance", [])

        # 根据 WAF 调整参数
        if profile.has_waf:
            tools = self._adjust_for_waf(tools, profile.waf_type)

        return sorted(tools, key=lambda t: t.get("priority", 99))

    def recommend_attack_pattern(self, profile: TargetProfile) -> dict:
        """推荐攻击模式"""
        pattern_name = "web_reconnaissance"

        if profile.target_type == TargetType.API_ENDPOINT:
            pattern_name = "api_testing"
        elif profile.target_type == TargetType.IOT_DEVICE:
            pattern_name = "iot_device_testing"
        elif profile.target_type == TargetType.CLOUD_SERVICE:
            pattern_name = "cloud_assessment"
        elif profile.attack_surface_score > 7:
            pattern_name = "bug_bounty_hunting"

        return {
            "pattern_name": pattern_name,
            "tools": ATTACK_PATTERNS.get(pattern_name, []),
            "vuln_priorities": self._get_vuln_priorities(profile),
            "estimated_time": self._estimate_time(pattern_name),
        }

    def get_vuln_priorities(self, profile: TargetProfile) -> list[str]:
        """根据技术栈返回漏洞优先级列表"""
        return self._get_vuln_priorities(profile)

    # ─── 内部方法 ──────────────────────────────────────────────

    def _determine_target_type(self, target: str) -> TargetType:
        """确定目标类型"""
        target_lower = target.lower()

        # APP 包名
        if re.match(r'^com\.[a-z]', target_lower):
            return TargetType.MOBILE_APP

        # URL
        if target_lower.startswith(('http://', 'https://')):
            if '/api/' in target_lower or target_lower.endswith('/api'):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION

        # IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return TargetType.NETWORK_HOST

        # 云服务
        cloud_indicators = ['amazonaws.com', 'azure', 'googleapis.com', 'cloudflare']
        if any(c in target_lower for c in cloud_indicators):
            return TargetType.CLOUD_SERVICE

        # IoT 特征
        iot_indicators = ['iot', 'device', 'mqtt', 'smart', 'hub']
        if any(i in target_lower for i in iot_indicators):
            return TargetType.IOT_DEVICE

        # 域名
        if '.' in target:
            return TargetType.WEB_APPLICATION

        return TargetType.UNKNOWN

    def _detect_tech_from_headers(self, headers: dict) -> list[str]:
        """从 HTTP 响应头检测技术栈"""
        techs = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        tech_headers = {
            "x-powered-by": {
                "express": "nodejs", "php": "php", "asp.net": "dotnet",
                "next.js": "nextjs",
            },
            "server": {
                "apache": "php", "nginx": "unknown", "gunicorn": "python",
                "werkzeug": "python", "tomcat": "java",
            },
        }

        for header, mapping in tech_headers.items():
            value = headers_lower.get(header, "")
            for keyword, tech in mapping.items():
                if keyword in value:
                    techs.append(tech)

        return techs

    def _detect_tech_from_content(self, body: str) -> list[str]:
        """从页面内容检测技术栈"""
        techs = []
        body_lower = body.lower()

        content_patterns = {
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "drupal": ["drupal", "/sites/default"],
            "laravel": ["laravel", "csrf-token"],
            "react": ["__react", "react-root", "data-reactroot"],
            "vue": ["__vue__", "v-cloak", "vue-router"],
            "angular": ["ng-version", "angular"],
            "nextjs": ["__next", "_next/static"],
            "graphql": ["graphql", "__schema"],
            "spring": ["actuator", "spring"],
        }

        for tech, patterns in content_patterns.items():
            if any(p in body_lower for p in patterns):
                techs.append(tech)

        return techs

    def _calculate_attack_surface(self, profile: TargetProfile) -> float:
        """计算攻击面评分 (0-10)"""
        score = 5.0  # 基础分

        # 技术栈加分
        high_risk_techs = ["php", "wordpress", "spring", "java"]
        for tech in profile.technologies:
            if tech in high_risk_techs:
                score += 1.0

        # 多端口加分
        if len(profile.open_ports) > 5:
            score += 1.5
        elif len(profile.open_ports) > 2:
            score += 0.5

        # WAF 减分（更难利用）
        if profile.has_waf:
            score -= 1.0

        # API 类型加分（通常有更多逻辑漏洞）
        if profile.target_type == TargetType.API_ENDPOINT:
            score += 1.0

        # IoT 加分（通常安全性较差）
        if profile.target_type == TargetType.IOT_DEVICE:
            score += 2.0

        return min(10.0, max(0.0, score))

    def _determine_risk_level(self, profile: TargetProfile) -> str:
        """确定风险等级"""
        if profile.attack_surface_score >= 8:
            return "critical"
        elif profile.attack_surface_score >= 6:
            return "high"
        elif profile.attack_surface_score >= 4:
            return "medium"
        return "low"

    def _get_vuln_priorities(self, profile: TargetProfile) -> list[str]:
        """根据技术栈获取漏洞优先级"""
        priorities = []
        for tech in profile.technologies:
            if tech in TECH_VULN_PRIORITY:
                priorities.extend(TECH_VULN_PRIORITY[tech])

        # 去重保持顺序
        seen = set()
        unique = []
        for p in priorities:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        # 如果没有检测到技术栈，返回通用优先级
        if not unique:
            unique = ["idor", "auth_bypass", "ssrf", "xss", "sqli", "business_logic"]

        return unique

    def _adjust_for_waf(self, tools: list[dict], waf_type: str) -> list[dict]:
        """根据 WAF 类型调整工具参数"""
        adjusted = []
        for tool in tools:
            t = dict(tool)
            # 所有工具加限速
            if "rate" not in t.get("params", ""):
                t["params"] = t.get("params", "") + " -rate-limit 2"
            adjusted.append(t)
        return adjusted

    def _estimate_time(self, pattern_name: str) -> str:
        """估算攻击模式的执行时间"""
        time_estimates = {
            "web_reconnaissance": "10-20 min",
            "api_testing": "15-30 min",
            "bug_bounty_recon": "20-40 min",
            "bug_bounty_hunting": "30-60 min",
            "iot_device_testing": "10-20 min",
            "cloud_assessment": "15-30 min",
        }
        return time_estimates.get(pattern_name, "15-30 min")
