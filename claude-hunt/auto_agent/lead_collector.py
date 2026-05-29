#!/usr/bin/env python3
"""
Lead Collector — 线索收集模块（explore/lead 模式核心）

设计思路：
- 扫描阶段要"贪"：所有可疑信号都保存为 lead，不急着过滤
- 报告阶段要"狠"：只有通过 report_gate 的才输出
- 中间层：lead_gate 只做最基本的去噪（明确的误报/噪音才丢弃）

Lead 分类：
- AUTH_BOUNDARY: 权限边界线索（401/403 的端点、需要不同角色的 API）
- BIZ_OBJECT: 业务对象线索（含 ID 的端点、用户/订单/团队等）
- PARAM_ANOMALY: 参数异常线索（响应差异、错误信息泄露）
- AUTH_INCONSISTENCY: 认证不一致（同组 API 部分有认证部分没有）
- INTERESTING_RESPONSE: 有趣的响应（非标准错误、调试信息、版本泄露）
- POTENTIAL_CHAIN: 潜在链式利用（单个低危但可能组合的信号）
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional



@dataclass
class Lead:
    """一条线索"""
    id: str = ""
    category: str = ""          # AUTH_BOUNDARY / BIZ_OBJECT / PARAM_ANOMALY / etc.
    url: str = ""
    method: str = "GET"
    summary: str = ""           # 一句话描述
    detail: str = ""            # 详细信息
    evidence: str = ""          # 原始证据（响应片段等）
    severity_hint: str = "unknown"  # 预估严重性
    confidence: float = 0.0     # 0-1，线索可信度
    source: str = ""            # 哪个模块产生的
    timestamp: str = ""
    # 待测信息
    test_suggestion: str = ""   # 建议的测试方法
    requires_auth: bool = False
    requires_dual_account: bool = False
    # 状态
    status: str = "pending"     # pending / testing / confirmed / rejected / reported
    test_result: str = ""



class LeadCollector:
    """
    线索收集器 — explore 模式核心

    在扫描阶段，所有模块发现的"可疑但未确认"的信号都汇集到这里。
    只做最基本的去噪（lead_gate），不做严格的 report_gate 过滤。
    最终输出一份"待测清单"供 deep_hunt 或人工跟进。
    """

    # 明确的噪音模式 — 只有这些才会在 lead_gate 被丢弃
    NOISE_PATTERNS = [
        "favicon",
        "google-analytics",
        "gtag",
        "facebook pixel",
        "hotjar",
        "cdn.jsdelivr",
        "fonts.googleapis",
        "wp-emoji",
    ]

    def __init__(self, config: dict = None, storage_dir: str = None):
        self.config = config or {}
        lead_config = self.config.get("lead_mode", {})
        self.enabled = lead_config.get("enabled", True)
        self.max_leads = lead_config.get("max_leads", 500)
        self.auto_classify = lead_config.get("auto_classify", True)

        # 存储目录
        if storage_dir:
            self.storage_dir = storage_dir
        else:
            self.storage_dir = os.path.expanduser(
                lead_config.get("storage_dir", "~/.bai-agent/leads")
            )
        Path(self.storage_dir).mkdir(parents=True, exist_ok=True)

        self.leads: list[Lead] = []
        self._lead_counter = 0


    def add_lead(
        self,
        category: str,
        url: str,
        summary: str,
        detail: str = "",
        evidence: str = "",
        method: str = "GET",
        severity_hint: str = "unknown",
        confidence: float = 0.5,
        source: str = "",
        test_suggestion: str = "",
        requires_auth: bool = False,
        requires_dual_account: bool = False,
    ) -> Optional[Lead]:
        """
        添加一条线索。只有明确噪音才被拒绝，其他全部保留。
        返回创建的 Lead 或 None（如果被 lead_gate 拒绝）。
        """
        if not self.enabled:
            return None

        # lead_gate: 只过滤明确噪音
        if self._is_noise(url, summary, detail):
            return None

        # 去重：同 URL + 同 category 不重复添加
        for existing in self.leads:
            if existing.url == url and existing.category == category:
                # 更新 confidence 如果新的更高
                if confidence > existing.confidence:
                    existing.confidence = confidence
                    existing.detail = detail or existing.detail
                return existing

        if len(self.leads) >= self.max_leads:
            # 淘汰最低 confidence 的线索
            self.leads.sort(key=lambda l: l.confidence, reverse=True)
            self.leads = self.leads[: self.max_leads - 1]

        self._lead_counter += 1
        lead = Lead(
            id=f"LEAD-{self._lead_counter:04d}",
            category=category,
            url=url,
            method=method,
            summary=summary,
            detail=detail,
            evidence=evidence[:2000],
            severity_hint=severity_hint,
            confidence=confidence,
            source=source,
            timestamp=datetime.now().isoformat(),
            test_suggestion=test_suggestion,
            requires_auth=requires_auth,
            requires_dual_account=requires_dual_account,
        )
        self.leads.append(lead)
        return lead


    def add_auth_boundary(self, url: str, method: str, status_code: int,
                          source: str = "") -> Optional[Lead]:
        """快捷方法：添加权限边界线索（401/403 端点）"""
        return self.add_lead(
            category="AUTH_BOUNDARY",
            url=url,
            method=method,
            summary=f"{method} {url} → {status_code}",
            detail=f"端点返回 {status_code}，可能有权限绕过机会",
            severity_hint="medium",
            confidence=0.4,
            source=source,
            test_suggestion=(
                "尝试: 1) 不同HTTP方法 2) 路径大小写/编码变异 "
                "3) X-Forwarded-For/X-Original-URL 头 "
                "4) API版本降级 5) 去掉路径末尾斜杠"
            ),
            requires_auth=True,
        )

    def add_biz_object(self, url: str, method: str, id_param: str,
                       id_value: str, source: str = "") -> Optional[Lead]:
        """快捷方法：添加业务对象线索（含 ID 的端点）"""
        obj_type = self._classify_biz_object(url, id_param)
        return self.add_lead(
            category="BIZ_OBJECT",
            url=url,
            method=method,
            summary=f"业务对象[{obj_type}]: {id_param}={id_value}",
            detail=f"端点包含可枚举的业务ID，对象类型: {obj_type}",
            severity_hint="high" if obj_type in (
                "user", "account", "payment", "order", "billing"
            ) else "medium",
            confidence=0.6,
            source=source,
            test_suggestion=(
                f"双账号 IDOR 测试: 用账号B的token访问账号A的{obj_type}资源，"
                f"对比响应体差异。也测试 PUT/PATCH/DELETE 方法。"
            ),
            requires_auth=True,
            requires_dual_account=True,
        )

    def add_param_anomaly(self, url: str, param: str, anomaly_type: str,
                          evidence: str = "", source: str = "") -> Optional[Lead]:
        """快捷方法：添加参数异常线索"""
        return self.add_lead(
            category="PARAM_ANOMALY",
            url=url,
            summary=f"参数异常[{anomaly_type}]: {param}",
            detail=f"参数 {param} 触发了异常响应: {anomaly_type}",
            evidence=evidence,
            severity_hint="medium",
            confidence=0.5,
            source=source,
            test_suggestion=f"对参数 {param} 做深度 fuzz，测试 SQLi/XSS/SSRF payload",
        )

    def add_auth_inconsistency(self, protected_url: str, unprotected_url: str,
                                source: str = "") -> Optional[Lead]:
        """快捷方法：添加认证不一致线索"""
        return self.add_lead(
            category="AUTH_INCONSISTENCY",
            url=unprotected_url,
            summary=f"认证不一致: {unprotected_url} 无需认证",
            detail=(
                f"同组API中 {protected_url} 需要认证，"
                f"但 {unprotected_url} 不需要。开发者可能遗漏了权限检查。"
            ),
            severity_hint="high",
            confidence=0.7,
            source=source,
            test_suggestion="确认无认证端点是否泄露敏感数据或允许越权操作",
        )


    def get_test_queue(self, min_confidence: float = 0.0,
                        categories: list = None) -> list[Lead]:
        """
        获取待测清单，按优先级排序。
        优先级 = severity_hint 权重 * confidence
        """
        severity_weight = {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1
        }
        filtered = [
            l for l in self.leads
            if l.status == "pending"
            and l.confidence >= min_confidence
            and (not categories or l.category in categories)
        ]
        filtered.sort(
            key=lambda l: severity_weight.get(l.severity_hint, 1) * l.confidence,
            reverse=True,
        )
        return filtered

    def get_summary(self) -> dict:
        """获取线索汇总统计"""
        by_category = {}
        by_status = {}
        by_severity = {}
        for lead in self.leads:
            by_category[lead.category] = by_category.get(lead.category, 0) + 1
            by_status[lead.status] = by_status.get(lead.status, 0) + 1
            by_severity[lead.severity_hint] = by_severity.get(lead.severity_hint, 0) + 1
        return {
            "total": len(self.leads),
            "by_category": by_category,
            "by_status": by_status,
            "by_severity": by_severity,
            "top_leads": [
                {"id": l.id, "category": l.category, "url": l.url[:80],
                 "summary": l.summary, "confidence": l.confidence}
                for l in self.get_test_queue()[:10]
            ],
        }

    def mark_lead(self, lead_id: str, status: str, result: str = ""):
        """更新线索状态"""
        for lead in self.leads:
            if lead.id == lead_id:
                lead.status = status
                lead.test_result = result
                break

    def save(self, target: str = "unknown"):
        """持久化线索到磁盘"""
        filename = f"leads_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.storage_dir, filename)
        data = {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "summary": self.get_summary(),
            "leads": [asdict(l) for l in self.leads],
        }
        Path(filepath).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return filepath

    def load(self, filepath: str):
        """从磁盘加载线索"""
        data = json.loads(Path(filepath).read_text())
        self.leads = [Lead(**item) for item in data.get("leads", [])]
        self._lead_counter = len(self.leads)


    def _is_noise(self, url: str, summary: str, detail: str) -> bool:
        """lead_gate: 只过滤明确的噪音"""
        combined = f"{url} {summary} {detail}".lower()
        for pattern in self.NOISE_PATTERNS:
            if pattern in combined:
                return True
        return False

    def _classify_biz_object(self, url: str, id_param: str) -> str:
        """根据 URL 和参数名推断业务对象类型"""
        combined = f"{url} {id_param}".lower()
        classifiers = {
            "user": ["user", "uid", "profile", "account", "member"],
            "order": ["order", "purchase", "buy", "checkout"],
            "payment": ["pay", "payment", "billing", "invoice", "charge", "transaction"],
            "team": ["team", "org", "organization", "group", "workspace"],
            "project": ["project", "repo", "repository"],
            "file": ["file", "doc", "document", "upload", "attachment"],
            "message": ["message", "msg", "chat", "notification", "comment"],
            "role": ["role", "permission", "privilege", "admin"],
            "invite": ["invite", "invitation", "join", "member"],
            "config": ["config", "setting", "preference"],
            "api_key": ["key", "token", "secret", "credential", "api_key"],
        }
        for obj_type, keywords in classifiers.items():
            if any(kw in combined for kw in keywords):
                return obj_type
        return "generic"

    def generate_test_plan_text(self) -> str:
        """生成人类可读的待测计划文本"""
        queue = self.get_test_queue()
        if not queue:
            return "暂无待测线索。"

        lines = [
            "# 待测线索清单",
            f"生成时间: {datetime.now().isoformat()}",
            f"总线索数: {len(self.leads)} | 待测: {len(queue)}",
            "",
            "---",
            "",
        ]

        # 按 category 分组
        by_cat = {}
        for lead in queue:
            by_cat.setdefault(lead.category, []).append(lead)

        priority_order = [
            "AUTH_INCONSISTENCY", "BIZ_OBJECT", "AUTH_BOUNDARY",
            "PARAM_ANOMALY", "POTENTIAL_CHAIN", "INTERESTING_RESPONSE",
        ]
        for cat in priority_order:
            if cat not in by_cat:
                continue
            leads = by_cat[cat]
            lines.append(f"## {cat} ({len(leads)} 条)")
            lines.append("")
            for lead in leads[:20]:
                auth_tag = " [需登录]" if lead.requires_auth else ""
                dual_tag = " [需双账号]" if lead.requires_dual_account else ""
                lines.append(
                    f"- [{lead.id}] [{lead.severity_hint.upper()}] "
                    f"{lead.summary}{auth_tag}{dual_tag}"
                )
                lines.append(f"  URL: {lead.url}")
                if lead.test_suggestion:
                    lines.append(f"  测试方法: {lead.test_suggestion}")
                lines.append("")
            lines.append("")

        return "\n".join(lines)
