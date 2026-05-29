#!/usr/bin/env python3
"""
AI Attack Surface Mapper — 智能攻击面分析与可视化
基于 AI 的攻击面自动发现、分类、优先级排序

功能：
1. 多源数据聚合（子域名、端口、服务、路径）
2. AI 驱动的风险评估与优先级排序
3. 攻击路径自动建模
4. 技术栈指纹识别与漏洞关联
5. 变更监控（与历史对比）
6. 攻击面可视化输出（JSON/Mermaid/ASCII）

用法：
    from ai_attack_surface import AttackSurfaceMapper
    
    mapper = AttackSurfaceMapper(config)
    surface = await mapper.map_target("example.com")
    mapper.visualize(surface, format="mermaid")
"""

import asyncio
import json
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path



# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class AssetNode:
    """资产节点"""
    id: str = ""
    asset_type: str = ""  # domain/subdomain/ip/port/service/endpoint/param
    value: str = ""
    # 属性
    tech_stack: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    # 风险评估
    risk_score: float = 0.0  # 0-10
    risk_factors: List[str] = field(default_factory=list)
    known_vulns: List[str] = field(default_factory=list)
    # 关系
    parent: str = ""
    children: List[str] = field(default_factory=list)
    # 元数据
    first_seen: str = ""
    last_seen: str = ""
    status: str = "active"  # active/inactive/new/changed


@dataclass
class AttackVector:
    """攻击向量"""
    id: str = ""
    name: str = ""
    target_asset: str = ""
    vector_type: str = ""  # rce/sqli/ssrf/idor/auth_bypass/xss/upload
    # 评估
    likelihood: float = 0.0  # 成功可能性 0-1
    impact: float = 0.0  # 影响程度 0-1
    complexity: str = "medium"  # low/medium/high
    # 详情
    entry_point: str = ""
    payload_hint: str = ""
    prerequisites: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)



@dataclass
class AttackSurface:
    """完整攻击面"""
    target: str = ""
    scan_time: str = ""
    # 资产图
    assets: List[AssetNode] = field(default_factory=list)
    vectors: List[AttackVector] = field(default_factory=list)
    # 统计
    total_subdomains: int = 0
    total_endpoints: int = 0
    total_params: int = 0
    high_risk_count: int = 0
    # 历史对比
    new_assets: List[str] = field(default_factory=list)
    removed_assets: List[str] = field(default_factory=list)
    changed_assets: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# 技术栈指纹库
# ═══════════════════════════════════════════════════════════════

TECH_VULN_MAP = {
    "apache": ["CVE-2021-41773", "CVE-2021-42013", "path-traversal"],
    "nginx": ["CVE-2021-23017", "off-by-slash", "alias-traversal"],
    "tomcat": ["CVE-2020-1938", "ghostcat", "put-upload", "manager-default-creds"],
    "jboss": ["CVE-2017-12149", "deserialization", "jmx-console"],
    "wordpress": ["xmlrpc-dos", "user-enum", "plugin-vulns", "wp-cron-abuse"],
    "drupal": ["CVE-2018-7600", "CVE-2014-3704", "drupalgeddon"],
    "spring": ["CVE-2022-22965", "spring4shell", "actuator-exposure"],
    "struts": ["CVE-2017-5638", "CVE-2018-11776", "ognl-injection"],
    "laravel": ["CVE-2021-3129", "debug-mode", "env-exposure"],
    "express": ["prototype-pollution", "path-traversal", "ssrf"],
    "django": ["CVE-2022-34265", "debug-mode", "admin-exposure"],
    "flask": ["ssti-jinja2", "debug-pin", "secret-key-weak"],
    "graphql": ["introspection", "batching-dos", "idor", "injection"],
    "elasticsearch": ["unauthenticated-access", "script-injection", "data-exposure"],
    "redis": ["unauthenticated-access", "lua-injection", "rce-via-replication"],
    "mongodb": ["unauthenticated-access", "nosql-injection", "data-exposure"],
    "kubernetes": ["api-exposure", "etcd-unauthenticated", "privilege-escalation"],
    "docker": ["api-exposure", "container-escape", "privileged-mode"],
}



# 端口风险评分
PORT_RISK = {
    21: ("ftp", 6), 22: ("ssh", 3), 23: ("telnet", 8),
    25: ("smtp", 5), 53: ("dns", 4), 80: ("http", 3),
    110: ("pop3", 5), 143: ("imap", 5), 443: ("https", 2),
    445: ("smb", 8), 1433: ("mssql", 7), 1521: ("oracle", 7),
    2049: ("nfs", 7), 3306: ("mysql", 7), 3389: ("rdp", 8),
    5432: ("postgresql", 6), 5900: ("vnc", 8), 6379: ("redis", 9),
    8080: ("http-alt", 4), 8443: ("https-alt", 3), 9200: ("elasticsearch", 8),
    11211: ("memcached", 8), 27017: ("mongodb", 9),
}


# ═══════════════════════════════════════════════════════════════
# 攻击面映射器
# ═══════════════════════════════════════════════════════════════

class AttackSurfaceMapper:
    """AI 驱动的攻击面映射器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.history_dir = Path(self.config.get("history_dir", "./attack_surface_history"))
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self._llm = None

    def _init_llm(self):
        """延迟初始化 LLM"""
        if self._llm:
            return
        try:
            from agent_engine import AgentEngine
            self._llm = AgentEngine(self.config)
        except Exception:
            self._llm = None

    async def map_target(self, target: str, recon_dir: str = None) -> AttackSurface:
        """
        完整攻击面映射
        1. 收集资产数据
        2. 构建资产图
        3. AI 分析风险
        4. 生成攻击向量
        5. 历史对比
        """
        surface = AttackSurface(
            target=target,
            scan_time=datetime.now().isoformat()
        )

        # Step 1: 收集资产
        assets = await self._collect_assets(target, recon_dir)
        surface.assets = assets


        # Step 2: 风险评估
        self._assess_risks(surface)

        # Step 3: 生成攻击向量
        surface.vectors = self._generate_vectors(surface)

        # Step 4: 统计
        surface.total_subdomains = len([a for a in assets if a.asset_type == "subdomain"])
        surface.total_endpoints = len([a for a in assets if a.asset_type == "endpoint"])
        surface.total_params = len([a for a in assets if a.asset_type == "param"])
        surface.high_risk_count = len([a for a in assets if a.risk_score >= 7.0])

        # Step 5: 历史对比
        self._compare_history(target, surface)

        # 保存历史
        self._save_history(target, surface)

        return surface

    async def _collect_assets(self, target: str, recon_dir: str = None) -> List[AssetNode]:
        """从侦察数据收集资产"""
        assets = []
        now = datetime.now().isoformat()

        # 根域名
        root = AssetNode(
            id=f"root_{target}",
            asset_type="domain",
            value=target,
            first_seen=now,
            last_seen=now
        )
        assets.append(root)

        if not recon_dir:
            return assets

        recon_path = Path(recon_dir)

        # 加载子域名
        for subfile in ["resolved.txt", "all.txt", "subdomains.txt"]:
            fp = recon_path / subfile
            if fp.exists():
                for line in fp.read_text().splitlines():
                    sub = line.strip()
                    if sub and sub != target:
                        node = AssetNode(
                            id=f"sub_{hashlib.md5(sub.encode()).hexdigest()[:8]}",
                            asset_type="subdomain",
                            value=sub,
                            parent=root.id,
                            first_seen=now,
                            last_seen=now
                        )
                        assets.append(node)
                        root.children.append(node.id)
                break


        # 加载 httpx 数据（端口+技术栈）
        for httpx_file in ["live/httpx_full.txt", "httpx_full.txt", "httpx.json"]:
            fp = recon_path / httpx_file
            if fp.exists():
                self._parse_httpx(fp, assets, now)
                break

        # 加载端点
        for url_file in ["urls/all.txt", "urls/with_params.txt", "crawl.txt"]:
            fp = recon_path / url_file
            if fp.exists():
                for line in fp.read_text().splitlines()[:2000]:
                    url = line.strip()
                    if url.startswith("http"):
                        node = AssetNode(
                            id=f"ep_{hashlib.md5(url.encode()).hexdigest()[:8]}",
                            asset_type="endpoint",
                            value=url,
                            first_seen=now,
                            last_seen=now
                        )
                        # 检测参数
                        if "?" in url:
                            node.asset_type = "param"
                        assets.append(node)
                break

        # 加载技术栈
        for tech_file in ["tech_priority.txt", "tech.txt"]:
            fp = recon_path / tech_file
            if fp.exists():
                techs = [l.strip().lower() for l in fp.read_text().splitlines() if l.strip()]
                root.tech_stack = techs[:20]
                break

        return assets

    def _parse_httpx(self, filepath: Path, assets: List[AssetNode], now: str):
        """解析 httpx 输出获取服务信息"""
        content = filepath.read_text(errors="ignore")
        for line in content.splitlines()[:500]:
            line = line.strip()
            if not line:
                continue
            # httpx JSON 格式
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    port = data.get("port", 0)
                    tech = data.get("tech", [])
                    status = data.get("status_code", 0)
                    if host:
                        # 查找对应资产并更新
                        for asset in assets:
                            if asset.value == host:
                                if port:
                                    asset.ports.append(port)
                                if tech:
                                    asset.tech_stack.extend(tech)
                                break
                except json.JSONDecodeError:
                    pass


    def _assess_risks(self, surface: AttackSurface):
        """为每个资产评估风险"""
        for asset in surface.assets:
            score = 0.0
            factors = []

            # 基于端口评估
            for port in asset.ports:
                if port in PORT_RISK:
                    svc, risk = PORT_RISK[port]
                    score = max(score, risk)
                    if risk >= 7:
                        factors.append(f"高危端口 {port}/{svc}")

            # 基于技术栈评估
            for tech in asset.tech_stack:
                tech_lower = tech.lower()
                for known_tech, vulns in TECH_VULN_MAP.items():
                    if known_tech in tech_lower:
                        score = max(score, 6.0)
                        asset.known_vulns.extend(vulns[:3])
                        factors.append(f"已知漏洞技术: {known_tech}")

            # 基于资产类型
            if asset.asset_type == "param":
                score = max(score, 5.0)
                factors.append("参数化端点(可测试注入)")

            # 子域名特征
            if asset.asset_type == "subdomain":
                risky_patterns = [
                    ("dev", 7), ("staging", 7), ("test", 7), ("admin", 8),
                    ("api", 6), ("internal", 8), ("legacy", 7), ("old", 6),
                    ("backup", 7), ("jenkins", 8), ("git", 8), ("ci", 7),
                    ("jira", 6), ("vpn", 5), ("mail", 5), ("ftp", 7),
                ]
                for pattern, risk in risky_patterns:
                    if pattern in asset.value.lower():
                        score = max(score, risk)
                        factors.append(f"高价值子域名模式: {pattern}")

            asset.risk_score = min(score, 10.0)
            asset.risk_factors = factors

    def _generate_vectors(self, surface: AttackSurface) -> List[AttackVector]:
        """基于资产生成可能的攻击向量"""
        vectors = []
        vec_id = 0

        for asset in surface.assets:
            if asset.risk_score < 4.0:
                continue

            # 基于技术栈的攻击向量
            for tech in asset.tech_stack:
                tech_lower = tech.lower()
                if "spring" in tech_lower:
                    vec_id += 1
                    vectors.append(AttackVector(
                        id=f"vec_{vec_id}",
                        name="Spring Actuator/Spring4Shell",
                        target_asset=asset.id,
                        vector_type="rce",
                        likelihood=0.3,
                        impact=1.0,
                        complexity="medium",
                        entry_point=f"{asset.value}/actuator",
                        payload_hint="classLoader.resources.context exploit",
                    ))


                if "graphql" in tech_lower:
                    vec_id += 1
                    vectors.append(AttackVector(
                        id=f"vec_{vec_id}",
                        name="GraphQL Introspection + IDOR",
                        target_asset=asset.id,
                        vector_type="idor",
                        likelihood=0.6,
                        impact=0.7,
                        complexity="low",
                        entry_point=f"{asset.value}/graphql",
                        payload_hint='{"query":"{__schema{types{name,fields{name}}}}"}',
                    ))

            # 基于端口的攻击向量
            for port in asset.ports:
                if port == 6379:
                    vec_id += 1
                    vectors.append(AttackVector(
                        id=f"vec_{vec_id}",
                        name="Redis Unauthenticated RCE",
                        target_asset=asset.id,
                        vector_type="rce",
                        likelihood=0.4,
                        impact=1.0,
                        complexity="low",
                        entry_point=f"{asset.value}:{port}",
                        payload_hint="CONFIG SET dir /var/spool/cron/",
                    ))
                elif port == 27017:
                    vec_id += 1
                    vectors.append(AttackVector(
                        id=f"vec_{vec_id}",
                        name="MongoDB Unauthenticated Access",
                        target_asset=asset.id,
                        vector_type="auth_bypass",
                        likelihood=0.3,
                        impact=0.9,
                        complexity="low",
                        entry_point=f"{asset.value}:{port}",
                        payload_hint="mongo --host target --eval 'db.adminCommand(\"listDatabases\")'",
                    ))

            # 基于子域名模式
            if asset.asset_type == "subdomain":
                if any(p in asset.value for p in ["admin", "jenkins", "ci"]):
                    vec_id += 1
                    vectors.append(AttackVector(
                        id=f"vec_{vec_id}",
                        name="Admin Panel Default Credentials",
                        target_asset=asset.id,
                        vector_type="auth_bypass",
                        likelihood=0.2,
                        impact=0.9,
                        complexity="low",
                        entry_point=asset.value,
                        payload_hint="admin:admin, admin:password, root:toor",
                    ))

        # 按 likelihood * impact 排序
        vectors.sort(key=lambda v: v.likelihood * v.impact, reverse=True)
        return vectors[:50]


    def _compare_history(self, target: str, surface: AttackSurface):
        """与历史数据对比，找出变化"""
        history_file = self.history_dir / f"{target.replace('.', '_')}_latest.json"
        if not history_file.exists():
            surface.new_assets = [a.value for a in surface.assets]
            return

        try:
            old_data = json.loads(history_file.read_text())
            old_values = set(old_data.get("asset_values", []))
            current_values = set(a.value for a in surface.assets)

            surface.new_assets = list(current_values - old_values)
            surface.removed_assets = list(old_values - current_values)
            # 标记新资产
            for asset in surface.assets:
                if asset.value in surface.new_assets:
                    asset.status = "new"
        except Exception:
            pass

    def _save_history(self, target: str, surface: AttackSurface):
        """保存历史快照"""
        history_file = self.history_dir / f"{target.replace('.', '_')}_latest.json"
        data = {
            "target": target,
            "scan_time": surface.scan_time,
            "asset_values": [a.value for a in surface.assets],
            "total_assets": len(surface.assets),
            "high_risk_count": surface.high_risk_count,
        }
        history_file.write_text(json.dumps(data, indent=2))

    # ═══════════════════════════════════════════════════════════════
    # 可视化输出
    # ═══════════════════════════════════════════════════════════════

    def visualize(self, surface: AttackSurface, format: str = "ascii") -> str:
        """生成攻击面可视化"""
        if format == "mermaid":
            return self._to_mermaid(surface)
        elif format == "json":
            return self._to_json(surface)
        else:
            return self._to_ascii(surface)

    def _to_ascii(self, surface: AttackSurface) -> str:
        """ASCII 树形图"""
        lines = []
        lines.append(f"{'═'*60}")
        lines.append(f"  ATTACK SURFACE: {surface.target}")
        lines.append(f"  Scanned: {surface.scan_time}")
        lines.append(f"{'═'*60}")
        lines.append(f"  Subdomains: {surface.total_subdomains} | "
                     f"Endpoints: {surface.total_endpoints} | "
                     f"Params: {surface.total_params} | "
                     f"High Risk: {surface.high_risk_count}")
        lines.append(f"{'─'*60}")


        # 高风险资产
        high_risk = sorted([a for a in surface.assets if a.risk_score >= 7],
                          key=lambda x: x.risk_score, reverse=True)
        if high_risk:
            lines.append("\n  [!] HIGH RISK ASSETS:")
            for asset in high_risk[:15]:
                status_icon = "NEW" if asset.status == "new" else "   "
                lines.append(f"    [{status_icon}] {asset.value} "
                           f"(risk: {asset.risk_score:.1f}) "
                           f"{'|'.join(asset.risk_factors[:2])}")

        # 攻击向量
        if surface.vectors:
            lines.append(f"\n  [>] TOP ATTACK VECTORS:")
            for vec in surface.vectors[:10]:
                roi = vec.likelihood * vec.impact
                lines.append(f"    [{vec.vector_type.upper():12s}] {vec.name}")
                lines.append(f"      Target: {vec.entry_point}")
                lines.append(f"      P={vec.likelihood:.0%} Impact={vec.impact:.0%} ROI={roi:.2f}")

        # 变更摘要
        if surface.new_assets:
            lines.append(f"\n  [+] NEW ASSETS ({len(surface.new_assets)}):")
            for a in surface.new_assets[:10]:
                lines.append(f"    + {a}")
        if surface.removed_assets:
            lines.append(f"\n  [-] REMOVED ASSETS ({len(surface.removed_assets)}):")
            for a in surface.removed_assets[:10]:
                lines.append(f"    - {a}")

        lines.append(f"\n{'═'*60}")
        output = "\n".join(lines)
        print(output)
        return output

    def _to_mermaid(self, surface: AttackSurface) -> str:
        """生成 Mermaid 流程图"""
        lines = ["graph TD"]
        lines.append(f'    ROOT["{surface.target}"]')

        # 添加高风险资产
        high_risk = [a for a in surface.assets if a.risk_score >= 5][:20]
        for i, asset in enumerate(high_risk):
            node_id = f"N{i}"
            label = asset.value.replace('"', "'")[:40]
            if asset.risk_score >= 8:
                lines.append(f'    {node_id}["{label}"]:::danger')
            elif asset.risk_score >= 6:
                lines.append(f'    {node_id}["{label}"]:::warning')
            else:
                lines.append(f'    {node_id}["{label}"]')
            lines.append(f'    ROOT --> {node_id}')

        # 添加攻击向量连接
        for i, vec in enumerate(surface.vectors[:8]):
            vec_id = f"V{i}"
            lines.append(f'    {vec_id}{{{{{vec.name}}}}}:::attack')
            # 找到目标资产的索引
            for j, asset in enumerate(high_risk):
                if asset.id == vec.target_asset:
                    lines.append(f'    N{j} -.-> {vec_id}')
                    break

        lines.append('    classDef danger fill:#f66,stroke:#333')
        lines.append('    classDef warning fill:#fa0,stroke:#333')
        lines.append('    classDef attack fill:#f0f,stroke:#333')

        return "\n".join(lines)


    def _to_json(self, surface: AttackSurface) -> str:
        """JSON 导出"""
        data = {
            "target": surface.target,
            "scan_time": surface.scan_time,
            "summary": {
                "total_subdomains": surface.total_subdomains,
                "total_endpoints": surface.total_endpoints,
                "total_params": surface.total_params,
                "high_risk_count": surface.high_risk_count,
            },
            "high_risk_assets": [
                {
                    "value": a.value,
                    "type": a.asset_type,
                    "risk_score": a.risk_score,
                    "risk_factors": a.risk_factors,
                    "known_vulns": a.known_vulns,
                    "tech_stack": a.tech_stack,
                    "status": a.status,
                }
                for a in sorted(surface.assets, key=lambda x: x.risk_score, reverse=True)
                if a.risk_score >= 5
            ],
            "attack_vectors": [
                {
                    "name": v.name,
                    "type": v.vector_type,
                    "target": v.entry_point,
                    "likelihood": v.likelihood,
                    "impact": v.impact,
                    "payload_hint": v.payload_hint,
                }
                for v in surface.vectors[:20]
            ],
            "changes": {
                "new": surface.new_assets[:20],
                "removed": surface.removed_assets[:20],
            }
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def get_priority_targets(self, surface: AttackSurface, top_n: int = 10) -> List[Dict]:
        """获取优先测试目标列表"""
        targets = []
        for vec in surface.vectors[:top_n]:
            targets.append({
                "target": vec.entry_point,
                "attack": vec.name,
                "type": vec.vector_type,
                "priority_score": round(vec.likelihood * vec.impact, 3),
                "payload_hint": vec.payload_hint,
            })
        return targets
