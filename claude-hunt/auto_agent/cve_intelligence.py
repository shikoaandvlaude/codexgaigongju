#!/usr/bin/env python3
"""
CVE Intelligence — CVE/ExploitDB 情报自动关联
扫描结果自动匹配已知漏洞库，提供利用参考

功能：
1. NVD/CVE 查询（通过 API 或本地缓存）
2. ExploitDB 关联（搜索可用 exploit）
3. 扫描结果自动匹配 CVE
4. 漏洞严重性评分（CVSS）
5. 已知 PoC/Exploit 链接
6. 与 nuclei 模板关联

用法：
    from cve_intelligence import CVEIntelligence

    intel = CVEIntelligence()

    # 查询单个 CVE
    info = await intel.lookup_cve("CVE-2021-44228")

    # 根据技术栈批量匹配
    cves = await intel.match_tech_stack(["apache 2.4.49", "openssl 1.1.1"])

    # 为 findings 补充 CVE 情报
    enriched = await intel.enrich_findings(findings)
"""

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class CVEInfo:
    """CVE 详细信息"""
    cve_id: str = ""
    description: str = ""
    severity: str = ""  # CRITICAL/HIGH/MEDIUM/LOW
    cvss_score: float = 0.0
    cvss_vector: str = ""
    # 影响
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    # 利用信息
    exploit_available: bool = False
    exploit_links: List[str] = field(default_factory=list)
    nuclei_template: str = ""
    metasploit_module: str = ""
    # 修复
    patch_available: bool = False
    patch_links: List[str] = field(default_factory=list)
    # 元数据
    published_date: str = ""
    last_modified: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ExploitInfo:
    """Exploit 信息"""
    edb_id: str = ""  # ExploitDB ID
    title: str = ""
    platform: str = ""  # linux/windows/multiple
    exploit_type: str = ""  # local/remote/webapps/dos
    url: str = ""
    verified: bool = False
    author: str = ""
    date: str = ""


# ═══════════════════════════════════════════════════════════════
# 本地高频 CVE 知识库（离线可用）
# ═══════════════════════════════════════════════════════════════

# 高频被利用的 CVE（SRC/Bug Bounty 常见）
HIGH_FREQ_CVES = {
    # Log4j
    "CVE-2021-44228": {
        "description": "Apache Log4j2 远程代码执行 (Log4Shell)",
        "severity": "CRITICAL", "cvss": 10.0,
        "products": ["log4j 2.x < 2.15.0"],
        "exploit": True,
        "nuclei": "CVE-2021-44228",
        "msf": "exploit/multi/http/log4shell_header_injection",
        "check": "jndi:ldap://",
    },
    # Spring4Shell
    "CVE-2022-22965": {
        "description": "Spring Framework RCE (Spring4Shell)",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["spring-framework < 5.3.18", "spring-boot < 2.6.6"],
        "exploit": True,
        "nuclei": "CVE-2022-22965",
        "msf": "exploit/multi/http/spring_framework_rce_spring4shell",
    },
    # Apache Struts
    "CVE-2017-5638": {
        "description": "Apache Struts2 S2-045 RCE",
        "severity": "CRITICAL", "cvss": 10.0,
        "products": ["struts 2.3.x", "struts 2.5.x < 2.5.10.1"],
        "exploit": True,
        "nuclei": "CVE-2017-5638",
        "msf": "exploit/multi/http/struts2_content_type_ognl",
    },
    # ProxyShell
    "CVE-2021-34473": {
        "description": "Microsoft Exchange ProxyShell RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["exchange server 2013/2016/2019"],
        "exploit": True,
    },
    # Apache Path Traversal
    "CVE-2021-41773": {
        "description": "Apache HTTP Server 路径遍历 + RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["apache httpd 2.4.49", "apache httpd 2.4.50"],
        "exploit": True,
        "nuclei": "CVE-2021-41773",
        "check": "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
    },
    # Confluence
    "CVE-2022-26134": {
        "description": "Atlassian Confluence OGNL 注入 RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["confluence < 7.4.17", "confluence 7.13.x < 7.13.7"],
        "exploit": True,
        "nuclei": "CVE-2022-26134",
    },
    # ThinkPHP
    "CVE-2018-20062": {
        "description": "ThinkPHP 5.x RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["thinkphp 5.0.x", "thinkphp 5.1.x"],
        "exploit": True,
        "nuclei": "thinkphp-5023-rce",
    },
    # Shiro
    "CVE-2016-4437": {
        "description": "Apache Shiro 默认密钥反序列化 RCE",
        "severity": "HIGH", "cvss": 8.1,
        "products": ["shiro < 1.2.5"],
        "exploit": True,
        "nuclei": "CVE-2016-4437",
        "check": "rememberMe=deleteMe",
    },
    # Fastjson
    "CVE-2022-25845": {
        "description": "Fastjson 反序列化 RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["fastjson < 1.2.83"],
        "exploit": True,
    },
    # Redis
    "CVE-2022-0543": {
        "description": "Redis Lua 沙箱逃逸 RCE",
        "severity": "CRITICAL", "cvss": 10.0,
        "products": ["redis (debian packaged)"],
        "exploit": True,
        "msf": "exploit/linux/redis/redis_replication_cmd_exec",
    },
    # GitLab
    "CVE-2021-22205": {
        "description": "GitLab CE/EE 未授权 RCE",
        "severity": "CRITICAL", "cvss": 10.0,
        "products": ["gitlab < 13.10.3"],
        "exploit": True,
    },
    # Nacos
    "CVE-2021-29441": {
        "description": "Nacos 未授权访问",
        "severity": "HIGH", "cvss": 8.8,
        "products": ["nacos < 1.4.2"],
        "exploit": True,
        "nuclei": "nacos-unauth",
    },
    # JWT
    "CVE-2018-0114": {
        "description": "JWT 算法混淆攻击",
        "severity": "HIGH", "cvss": 7.5,
        "products": ["various jwt libraries"],
        "exploit": True,
        "check": "alg: none",
    },
    # SSRF
    "CVE-2019-17558": {
        "description": "Apache Solr SSRF + RCE",
        "severity": "HIGH", "cvss": 8.8,
        "products": ["solr < 8.3.1"],
        "exploit": True,
    },
    # WebLogic
    "CVE-2020-14882": {
        "description": "Oracle WebLogic 未授权 RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["weblogic 10.3.6", "weblogic 12.x", "weblogic 14.x"],
        "exploit": True,
        "nuclei": "CVE-2020-14882",
        "msf": "exploit/multi/misc/weblogic_deserialize",
    },
    # 用友
    "CVE-2023-2523": {
        "description": "用友 NC Cloud 远程代码执行",
        "severity": "CRITICAL", "cvss": 9.8,
        "products": ["yongyou nc cloud"],
        "exploit": True,
    },
    # 泛微
    "CVE-2023-43955": {
        "description": "泛微 E-Office SQL 注入",
        "severity": "HIGH", "cvss": 8.8,
        "products": ["weaver e-office"],
        "exploit": True,
    },
}

# 技术栈 → CVE 映射（用于自动关联）
TECH_CVE_MAP = {
    "apache": ["CVE-2021-41773", "CVE-2021-42013"],
    "nginx": ["CVE-2021-23017"],
    "tomcat": ["CVE-2020-1938", "CVE-2019-0232"],
    "spring": ["CVE-2022-22965", "CVE-2022-22963"],
    "struts": ["CVE-2017-5638", "CVE-2018-11776"],
    "log4j": ["CVE-2021-44228", "CVE-2021-45046"],
    "shiro": ["CVE-2016-4437", "CVE-2020-1957"],
    "fastjson": ["CVE-2022-25845", "CVE-2020-8840"],
    "thinkphp": ["CVE-2018-20062", "CVE-2019-9082"],
    "weblogic": ["CVE-2020-14882", "CVE-2021-2109"],
    "confluence": ["CVE-2022-26134", "CVE-2023-22515"],
    "gitlab": ["CVE-2021-22205", "CVE-2023-7028"],
    "jenkins": ["CVE-2024-23897", "CVE-2019-1003000"],
    "redis": ["CVE-2022-0543", "CVE-2015-4335"],
    "elasticsearch": ["CVE-2015-1427", "CVE-2014-3120"],
    "nacos": ["CVE-2021-29441"],
    "wordpress": ["CVE-2022-21661", "CVE-2019-8942"],
    "drupal": ["CVE-2018-7600", "CVE-2019-6340"],
    "exchange": ["CVE-2021-34473", "CVE-2021-26855"],
    "openssl": ["CVE-2014-0160", "CVE-2022-3602"],
    "docker": ["CVE-2019-5736", "CVE-2020-15257"],
    "kubernetes": ["CVE-2018-1002105", "CVE-2020-8554"],
}


# ═══════════════════════════════════════════════════════════════
# CVE Intelligence 主类
# ═══════════════════════════════════════════════════════════════

class CVEIntelligence:
    """
    CVE 情报引擎

    工作模式：
    1. 优先查本地知识库（秒级响应）
    2. 本地无结果时查在线 API（NVD/Sploitus）
    3. 结果自动缓存
    """

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    SPLOITUS_API = "https://sploitus.com/search"
    EXPLOITDB_SEARCH = "https://www.exploit-db.com/search"

    def __init__(self, cache_dir: str = "~/.bai-agent/cve_cache"):
        self.cache_dir = os.path.expanduser(cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)
        self._cache: Dict[str, CVEInfo] = {}

    async def lookup_cve(self, cve_id: str) -> CVEInfo:
        """
        查询单个 CVE 详细信息

        优先级：内存缓存 → 本地知识库 → 文件缓存 → NVD API
        """
        cve_id = cve_id.upper().strip()

        # 1. 内存缓存
        if cve_id in self._cache:
            return self._cache[cve_id]

        # 2. 本地高频知识库
        if cve_id in HIGH_FREQ_CVES:
            info = self._from_local_kb(cve_id)
            self._cache[cve_id] = info
            return info

        # 3. 文件缓存
        cached = self._read_file_cache(cve_id)
        if cached:
            self._cache[cve_id] = cached
            return cached

        # 4. 在线查询
        info = await self._query_nvd(cve_id)
        if info.cve_id:
            self._cache[cve_id] = info
            self._write_file_cache(cve_id, info)

        return info

    async def match_tech_stack(self, technologies: List[str]) -> List[CVEInfo]:
        """
        根据技术栈匹配已知 CVE

        Args:
            technologies: 技术列表（如 ["apache 2.4.49", "spring-boot 2.5.0"]）

        Returns:
            匹配的 CVE 列表
        """
        matched_cves = set()

        for tech in technologies:
            tech_lower = tech.lower()
            # 在 TECH_CVE_MAP 中匹配
            for key, cve_ids in TECH_CVE_MAP.items():
                if key in tech_lower:
                    matched_cves.update(cve_ids)

        # 查询每个匹配的 CVE
        results = []
        for cve_id in matched_cves:
            info = await self.lookup_cve(cve_id)
            if info.cve_id:
                results.append(info)

        # 按 CVSS 排序
        results.sort(key=lambda x: x.cvss_score, reverse=True)
        return results

    async def search_exploits(self, query: str) -> List[ExploitInfo]:
        """
        搜索可用的 exploit

        查询 Sploitus API（聚合 ExploitDB/PacketStorm/GitHub）
        """
        exploits = []

        try:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    self.SPLOITUS_API,
                    params={"query": query, "type": "exploits"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("exploits", [])[:10]:
                        exploits.append(ExploitInfo(
                            edb_id=item.get("id", ""),
                            title=item.get("title", ""),
                            platform=item.get("platform", ""),
                            exploit_type=item.get("type", ""),
                            url=item.get("href", ""),
                            verified=item.get("verified", False),
                            author=item.get("author", ""),
                            date=item.get("published", ""),
                        ))
        except Exception:
            pass

        return exploits

    async def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        为 auto_hunt findings 补充 CVE 情报

        对每个 finding 检查是否关联已知 CVE，补充：
        - CVE ID
        - CVSS 评分
        - 已知 exploit 链接
        - Nuclei 模板
        - Metasploit 模块
        """
        enriched = []

        for finding in findings:
            enriched_finding = dict(finding)

            # 提取技术线索
            title = (finding.get("title", "") + finding.get("description", "")).lower()
            url = finding.get("url", "").lower()
            evidence = finding.get("evidence", "").lower()

            # 匹配 CVE
            matched_cve = None

            # 1. finding 本身带 CVE
            existing_cve = finding.get("cve", "")
            if existing_cve:
                matched_cve = await self.lookup_cve(existing_cve)

            # 2. 从描述中提取 CVE
            if not matched_cve:
                cve_pattern = re.findall(r'CVE-\d{4}-\d{4,}', title + evidence, re.IGNORECASE)
                if cve_pattern:
                    matched_cve = await self.lookup_cve(cve_pattern[0])

            # 3. 从技术特征匹配
            if not matched_cve:
                for tech_key, cve_ids in TECH_CVE_MAP.items():
                    if tech_key in title or tech_key in url:
                        for cve_id in cve_ids[:2]:
                            info = await self.lookup_cve(cve_id)
                            if info.exploit_available:
                                matched_cve = info
                                break
                        if matched_cve:
                            break

            # 4. 从本地高频库特征匹配
            if not matched_cve:
                for cve_id, data in HIGH_FREQ_CVES.items():
                    check = data.get("check", "")
                    if check and check.lower() in (title + evidence):
                        matched_cve = self._from_local_kb(cve_id)
                        break

            # 补充情报
            if matched_cve and matched_cve.cve_id:
                enriched_finding["cve"] = matched_cve.cve_id
                enriched_finding["cvss_score"] = matched_cve.cvss_score
                enriched_finding["cve_description"] = matched_cve.description
                enriched_finding["exploit_available"] = matched_cve.exploit_available
                if matched_cve.exploit_links:
                    enriched_finding["exploit_links"] = matched_cve.exploit_links
                if matched_cve.nuclei_template:
                    enriched_finding["nuclei_template"] = matched_cve.nuclei_template
                if matched_cve.metasploit_module:
                    enriched_finding["metasploit_module"] = matched_cve.metasploit_module
                # 用 CVSS 更新 severity
                if matched_cve.cvss_score >= 9.0:
                    enriched_finding["severity"] = "critical"
                elif matched_cve.cvss_score >= 7.0:
                    enriched_finding["severity"] = "high"

            enriched.append(enriched_finding)

        return enriched

    async def get_trending_cves(self, days: int = 7) -> List[CVEInfo]:
        """获取近期热门 CVE（从本地知识库）"""
        # 返回本地高频库中的高危 CVE
        results = []
        for cve_id in list(HIGH_FREQ_CVES.keys())[:20]:
            info = self._from_local_kb(cve_id)
            results.append(info)
        results.sort(key=lambda x: x.cvss_score, reverse=True)
        return results

    # ─── 内部方法 ──────────────────────────────────────────

    def _from_local_kb(self, cve_id: str) -> CVEInfo:
        """从本地知识库构建 CVEInfo"""
        data = HIGH_FREQ_CVES.get(cve_id, {})
        if not data:
            return CVEInfo(cve_id=cve_id)

        return CVEInfo(
            cve_id=cve_id,
            description=data.get("description", ""),
            severity=data.get("severity", ""),
            cvss_score=data.get("cvss", 0.0),
            affected_products=data.get("products", []),
            exploit_available=data.get("exploit", False),
            nuclei_template=data.get("nuclei", ""),
            metasploit_module=data.get("msf", ""),
        )

    async def _query_nvd(self, cve_id: str) -> CVEInfo:
        """查询 NVD API"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    self.NVD_API,
                    params={"cveId": cve_id},
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        cve_data = vulns[0].get("cve", {})
                        return self._parse_nvd_response(cve_data)
        except Exception:
            pass
        return CVEInfo(cve_id=cve_id)

    def _parse_nvd_response(self, cve_data: Dict) -> CVEInfo:
        """解析 NVD API 响应"""
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        severity = ""
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "")
                break

        # References
        refs = [r.get("url", "") for r in cve_data.get("references", [])[:10]]
        exploit_links = [r for r in refs if "exploit" in r.lower() or "github.com" in r.lower()]

        return CVEInfo(
            cve_id=cve_id,
            description=desc[:500],
            severity=severity,
            cvss_score=cvss_score,
            exploit_available=bool(exploit_links),
            exploit_links=exploit_links[:5],
            references=refs,
            published_date=cve_data.get("published", ""),
            last_modified=cve_data.get("lastModified", ""),
        )

    def _read_file_cache(self, cve_id: str) -> Optional[CVEInfo]:
        """读文件缓存"""
        path = os.path.join(self.cache_dir, f"{cve_id}.json")
        if not os.path.exists(path):
            return None
        # 超过 7 天的缓存失效
        if time.time() - os.path.getmtime(path) > 7 * 86400:
            return None
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return CVEInfo(**data)
        except Exception:
            return None

    def _write_file_cache(self, cve_id: str, info: CVEInfo):
        """写文件缓存"""
        path = os.path.join(self.cache_dir, f"{cve_id}.json")
        try:
            from dataclasses import asdict
            with open(path, 'w') as f:
                json.dump(asdict(info), f, ensure_ascii=False)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

_intel_instance: Optional[CVEIntelligence] = None

def get_cve_intel() -> CVEIntelligence:
    global _intel_instance
    if _intel_instance is None:
        _intel_instance = CVEIntelligence()
    return _intel_instance

async def cve_lookup(cve_id: str) -> Dict:
    """快捷 CVE 查询"""
    intel = get_cve_intel()
    info = await intel.lookup_cve(cve_id)
    from dataclasses import asdict
    return asdict(info)

async def enrich_with_cve(findings: List[Dict]) -> List[Dict]:
    """快捷 findings 情报补充"""
    intel = get_cve_intel()
    return await intel.enrich_findings(findings)
