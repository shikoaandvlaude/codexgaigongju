#!/usr/bin/env python3
"""
Skill Dispatcher — 技能调度系统
参考 VulnClaw 的 skills/dispatcher.py 设计
根据用户输入/目标特征自动匹配最合适的攻击技能

来源: 参考 VulnClaw skill dispatch + intent matching
"""

import re
from typing import Optional

# 意图 → 技能映射（中英文关键词匹配）
SKILL_INTENT_MAP = {
    # 信息搜集
    "信息收集|侦察|recon|端口扫描|子域名|指纹": "recon",
    "全面侦察|深度收集|资产发现": "deep_recon",
    # 漏洞类型
    "sql注入|sqli|注入|union select|盲注": "sqli_hunt",
    "xss|跨站脚本|反射|存储型xss|dom xss": "xss_hunt",
    "ssrf|内网|服务端请求|metadata": "ssrf_hunt",
    "idor|越权|水平越权|垂直越权|未授权": "idor_hunt",
    "rce|命令执行|代码执行|远程执行": "rce_hunt",
    "ssti|模板注入|jinja|twig|freemarker": "ssti_hunt",
    "文件上传|upload|webshell|绕过": "upload_hunt",
    "竞态|race|并发|重复领取": "race_hunt",
    "业务逻辑|支付|金额|价格|订单": "bizlogic_hunt",
    "jwt|token|认证|auth bypass|登录绕过": "auth_hunt",
    # 高级场景
    "graphql|introspection|mutation": "graphql_hunt",
    "api|接口|swagger|openapi": "api_hunt",
    "waf绕过|bypass|编码绕过": "waf_bypass",
    # CTF
    "ctf|夺旗|flag|解题": "ctf_mode",
    # IoT/APP
    "iot|设备|mqtt|固件|app|apk": "iot_hunt",
}

# 技能详情
SKILL_DETAILS = {
    "recon": {
        "name": "信息搜集",
        "description": "子域名枚举+端口扫描+URL收集+技术栈识别",
        "tools": ["subfinder", "httpx", "gau", "katana", "nmap"],
        "priority_vulns": [],
    },
    "deep_recon": {
        "name": "深度侦察",
        "description": "OSINT+证书关联+FOFA+GitHub泄露",
        "tools": ["subfinder", "uncover", "trufflehog", "alterx"],
        "priority_vulns": [],
    },
    "sqli_hunt": {
        "name": "SQL注入挖掘",
        "description": "手工构造payload,布尔/时间/报错/Union盲注",
        "tools": ["http_engine", "payload_generator"],
        "priority_vulns": ["sqli"],
        "payloads": ["'", "' OR '1'='1", "' AND SLEEP(3)--"],
    },
    "xss_hunt": {
        "name": "XSS挖掘",
        "description": "反射/存储/DOM XSS,反射上下文分析",
        "tools": ["dalfox", "http_engine", "active_fuzzer"],
        "priority_vulns": ["xss"],
    },
    "ssrf_hunt": {
        "name": "SSRF挖掘",
        "description": "内网探测/云元数据/协议绕过",
        "tools": ["http_engine", "interactsh"],
        "priority_vulns": ["ssrf"],
    },
    "idor_hunt": {
        "name": "越权挖掘",
        "description": "水平/垂直越权,ID枚举,方法变换,API版本降级",
        "tools": ["idor_tester", "http_engine"],
        "priority_vulns": ["idor"],
    },
    "rce_hunt": {
        "name": "RCE挖掘",
        "description": "命令注入/代码注入/反序列化",
        "tools": ["http_engine", "payload_generator"],
        "priority_vulns": ["rce", "command_injection"],
    },
    "ssti_hunt": {
        "name": "SSTI挖掘",
        "description": "模板注入(Jinja2/Twig/Freemarker/Thymeleaf)",
        "tools": ["http_engine", "active_fuzzer"],
        "priority_vulns": ["ssti"],
    },
    "race_hunt": {
        "name": "竞态条件挖掘",
        "description": "并发领券/提现/签到,带状态验证",
        "tools": ["business_logic_tester", "http_engine"],
        "priority_vulns": ["race_condition"],
    },
    "bizlogic_hunt": {
        "name": "业务逻辑挖掘",
        "description": "金额篡改/流程跳跃/权限提升/优惠滥用",
        "tools": ["business_logic_tester", "http_engine"],
        "priority_vulns": ["business_logic", "price_manipulation"],
    },
    "auth_hunt": {
        "name": "认证绕过挖掘",
        "description": "JWT攻击/OAuth/Token泄露/默认口令",
        "tools": ["http_engine", "active_fuzzer"],
        "priority_vulns": ["auth_bypass"],
    },
    "graphql_hunt": {
        "name": "GraphQL挖掘",
        "description": "Introspection/IDOR/注入/DoS",
        "tools": ["api_discovery", "http_engine"],
        "priority_vulns": ["graphql_idor", "injection"],
    },
    "api_hunt": {
        "name": "API安全测试",
        "description": "Swagger发现/未授权/IDOR/参数篡改",
        "tools": ["api_discovery", "idor_tester", "active_fuzzer"],
        "priority_vulns": ["api_misconfig", "idor"],
    },
    "waf_bypass": {
        "name": "WAF绕过",
        "description": "编码变异/注释插入/HPP/Unicode/分块传输",
        "tools": ["waf_bypass", "payload_generator"],
        "priority_vulns": [],
    },
    "ctf_mode": {
        "name": "CTF模式",
        "description": "夺旗赛专用,自动检测flag格式",
        "tools": ["http_engine", "active_fuzzer", "payload_generator"],
        "priority_vulns": [],
    },
    "iot_hunt": {
        "name": "IoT设备挖掘",
        "description": "设备IDOR/固件泄露/MQTT越权/ID枚举",
        "tools": ["iot_hunter", "app_recon", "http_engine"],
        "priority_vulns": ["device_idor", "firmware_leak"],
    },
}


class SkillDispatcher:
    """
    技能调度器 — 根据输入自动匹配最佳攻击技能
    
    用法:
        dispatcher = SkillDispatcher()
        skill = dispatcher.dispatch("帮我测试这个接口的SQL注入")
        print(skill["name"])  # "SQL注入挖掘"
        print(skill["tools"])  # ["http_engine", "payload_generator"]
    """

    def dispatch(self, user_input: str) -> dict:
        """根据用户输入匹配技能"""
        input_lower = user_input.lower()
        scores = {}

        for pattern, skill_name in SKILL_INTENT_MAP.items():
            keywords = pattern.split("|")
            match_count = sum(1 for kw in keywords if kw in input_lower)
            if match_count > 0:
                score = match_count / len(keywords)
                scores[skill_name] = scores.get(skill_name, 0) + score

        if not scores:
            # 默认返回综合 Recon
            return SKILL_DETAILS.get("recon", {})

        best_skill = max(scores, key=scores.get)
        return SKILL_DETAILS.get(best_skill, SKILL_DETAILS["recon"])

    def dispatch_by_findings(self, findings: dict) -> list[dict]:
        """根据已有发现推荐下一步技能"""
        recommendations = []

        urls_with_params = [u for u in findings.get("params", []) if "?" in u]
        alive_hosts = findings.get("alive_hosts", [])

        # 有参数的 URL → 推荐注入测试
        if urls_with_params:
            recommendations.append(SKILL_DETAILS["sqli_hunt"])
            recommendations.append(SKILL_DETAILS["xss_hunt"])

        # 有存活主机 → 推荐 IDOR 和 API 测试
        if alive_hosts:
            recommendations.append(SKILL_DETAILS["idor_hunt"])
            recommendations.append(SKILL_DETAILS["api_hunt"])

        # 有业务相关 URL → 推荐业务逻辑
        biz_keywords = ["pay", "order", "coupon", "wallet", "sign"]
        biz_urls = [u for u in findings.get("urls", [])
                   if any(kw in u.lower() for kw in biz_keywords)]
        if biz_urls:
            recommendations.append(SKILL_DETAILS["bizlogic_hunt"])
            recommendations.append(SKILL_DETAILS["race_hunt"])

        return recommendations[:5]

    def list_all_skills(self) -> list[dict]:
        """列出所有可用技能"""
        return [
            {"name": v["name"], "key": k, "description": v["description"]}
            for k, v in SKILL_DETAILS.items()
        ]
