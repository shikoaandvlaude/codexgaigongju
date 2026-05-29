#!/usr/bin/env python3
"""
Attack Chain — 攻击路径概率建模
移植自 HexStrike AI 的 Attack Chain Modeling

功能：
1. 攻击路径建模（多步骤链式攻击）
2. 成功概率计算（复合概率 + 前置条件）
3. 路径优先级排序（ROI 最高的路径先打）
4. 依赖关系追踪（步骤间的前置/后置）
5. 动态更新（执行结果反馈调整概率）

用法：
    from attack_chain import AttackChainModeler
    
    modeler = AttackChainModeler()
    
    # 添加攻击步骤
    modeler.add_step("recon_subdomains", probability=0.95, time_est=60)
    modeler.add_step("find_sqli", probability=0.3, requires=["recon_subdomains"])
    modeler.add_step("extract_data", probability=0.7, requires=["find_sqli"])
    
    # 计算最优路径
    chains = modeler.get_ranked_chains()
    for chain in chains:
        print(f"{chain.name}: P={chain.compound_probability:.2%}, ETA={chain.estimated_time}s")
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class AttackStep:
    """攻击步骤"""
    id: str = ""
    name: str = ""
    description: str = ""
    # 概率与时间
    probability: float = 0.5  # 成功概率 0-1
    time_estimate: int = 60  # 预计耗时（秒）
    impact_score: float = 0.5  # 影响分 0-1
    # 依赖
    requires: List[str] = field(default_factory=list)  # 前置步骤ID
    enables: List[str] = field(default_factory=list)  # 解锁的后续步骤
    # 分类
    phase: str = ""  # recon/weaponize/exploit/post_exploit
    vuln_type: str = ""
    tool: str = ""
    # 状态
    status: str = "pending"  # pending/running/success/failed/skipped
    actual_result: str = ""
    actual_time: float = 0


@dataclass
class AttackChain:
    """一条完整攻击链"""
    id: str = ""
    name: str = ""
    steps: List[AttackStep] = field(default_factory=list)
    # 计算结果
    compound_probability: float = 0.0  # 链式成功概率
    estimated_time: int = 0  # 总预计时间
    expected_impact: float = 0.0  # 期望影响 = P × Impact
    roi_score: float = 0.0  # ROI = 期望影响 / 时间
    # 目标
    target: str = ""
    goal: str = ""  # 最终目标描述


# ═══════════════════════════════════════════════════════════════
# 预定义攻击链模板
# ═══════════════════════════════════════════════════════════════

CHAIN_TEMPLATES = {
    "web_sqli_data_extraction": {
        "name": "Web SQLi 数据提取链",
        "goal": "通过 SQL 注入提取数据库敏感数据",
        "steps": [
            {"id": "recon", "name": "端点发现", "probability": 0.95, "time_estimate": 120, "phase": "recon"},
            {"id": "param_find", "name": "参数发现", "probability": 0.85, "time_estimate": 60, "requires": ["recon"]},
            {"id": "sqli_detect", "name": "SQL注入检测", "probability": 0.3, "time_estimate": 180, "requires": ["param_find"]},
            {"id": "waf_bypass", "name": "WAF绕过", "probability": 0.5, "time_estimate": 120, "requires": ["sqli_detect"]},
            {"id": "data_extract", "name": "数据提取", "probability": 0.8, "time_estimate": 60, "requires": ["waf_bypass"]},
        ],
    },
    "auth_bypass_chain": {
        "name": "认证绕过链",
        "goal": "绕过认证获取管理员访问",
        "steps": [
            {"id": "login_find", "name": "登录端点识别", "probability": 0.95, "time_estimate": 30},
            {"id": "default_cred", "name": "默认凭据测试", "probability": 0.15, "time_estimate": 30, "requires": ["login_find"]},
            {"id": "brute_force", "name": "弱密码爆破", "probability": 0.25, "time_estimate": 300, "requires": ["login_find"]},
            {"id": "jwt_attack", "name": "JWT攻击", "probability": 0.2, "time_estimate": 60, "requires": ["login_find"]},
            {"id": "session_fixation", "name": "会话固定", "probability": 0.1, "time_estimate": 90, "requires": ["login_find"]},
        ],
    },
    "idor_privilege_escalation": {
        "name": "IDOR 越权提升链",
        "goal": "通过 IDOR 访问其他用户/管理员数据",
        "steps": [
            {"id": "api_map", "name": "API映射", "probability": 0.9, "time_estimate": 120},
            {"id": "id_pattern", "name": "ID模式识别", "probability": 0.7, "time_estimate": 60, "requires": ["api_map"]},
            {"id": "horizontal_idor", "name": "水平越权", "probability": 0.4, "time_estimate": 120, "requires": ["id_pattern"]},
            {"id": "vertical_idor", "name": "垂直越权", "probability": 0.2, "time_estimate": 120, "requires": ["id_pattern"]},
        ],
    },
    "ssrf_to_rce": {
        "name": "SSRF → 内网 → RCE 链",
        "goal": "通过 SSRF 访问内部服务实现代码执行",
        "steps": [
            {"id": "ssrf_find", "name": "SSRF点发现", "probability": 0.2, "time_estimate": 180},
            {"id": "internal_scan", "name": "内网探测", "probability": 0.7, "time_estimate": 120, "requires": ["ssrf_find"]},
            {"id": "metadata", "name": "云元数据获取", "probability": 0.6, "time_estimate": 30, "requires": ["ssrf_find"]},
            {"id": "internal_exploit", "name": "内部服务利用", "probability": 0.3, "time_estimate": 300, "requires": ["internal_scan"]},
        ],
    },
    "xss_to_account_takeover": {
        "name": "XSS → 账户接管链",
        "goal": "通过 XSS 窃取会话实现账户接管",
        "steps": [
            {"id": "reflect_find", "name": "反射点发现", "probability": 0.6, "time_estimate": 120},
            {"id": "xss_confirm", "name": "XSS确认", "probability": 0.4, "time_estimate": 60, "requires": ["reflect_find"]},
            {"id": "bypass_csp", "name": "CSP绕过", "probability": 0.3, "time_estimate": 120, "requires": ["xss_confirm"]},
            {"id": "steal_session", "name": "会话窃取", "probability": 0.8, "time_estimate": 30, "requires": ["bypass_csp"]},
        ],
    },
}


# ═══════════════════════════════════════════════════════════════
# Attack Chain Modeler
# ═══════════════════════════════════════════════════════════════

class AttackChainModeler:
    """
    攻击链概率建模引擎
    
    核心算法：
    - 链式概率 = P(step1) × P(step2|step1) × P(step3|step2) × ...
    - ROI = (概率 × 影响分) / 时间
    - 动态调整：执行结果反馈更新概率
    """

    def __init__(self):
        self._steps: Dict[str, AttackStep] = {}
        self._chains: List[AttackChain] = []

    # ─── 步骤管理 ──────────────────────────────────────────

    def add_step(self, step_id: str, name: str = "", probability: float = 0.5,
                 time_estimate: int = 60, impact: float = 0.5,
                 requires: List[str] = None, phase: str = "", tool: str = ""):
        """添加攻击步骤"""
        step = AttackStep(
            id=step_id,
            name=name or step_id,
            probability=max(0.01, min(1.0, probability)),
            time_estimate=time_estimate,
            impact_score=impact,
            requires=requires or [],
            phase=phase,
            tool=tool,
        )
        self._steps[step_id] = step

    def update_step(self, step_id: str, success: bool, actual_time: float = 0):
        """根据执行结果更新步骤概率"""
        if step_id not in self._steps:
            return

        step = self._steps[step_id]
        step.status = "success" if success else "failed"
        step.actual_time = actual_time

        # 贝叶斯更新概率
        if success:
            step.probability = min(1.0, step.probability * 1.2 + 0.1)
        else:
            step.probability = max(0.01, step.probability * 0.6)

        # 重新计算所有链
        self._recalculate_chains()

    # ─── 链构建 ──────────────────────────────────────────

    def build_chain(self, step_ids: List[str], name: str = "", goal: str = "") -> AttackChain:
        """从步骤列表构建攻击链"""
        steps = [self._steps[sid] for sid in step_ids if sid in self._steps]
        chain = AttackChain(
            id=f"chain_{len(self._chains)}",
            name=name or f"Chain {len(self._chains) + 1}",
            steps=steps,
            goal=goal,
        )
        self._calculate_chain_metrics(chain)
        self._chains.append(chain)
        return chain

    def build_from_template(self, template_name: str, target: str = "") -> Optional[AttackChain]:
        """从预定义模板构建攻击链"""
        template = CHAIN_TEMPLATES.get(template_name)
        if not template:
            return None

        # 注册所有步骤
        for step_def in template["steps"]:
            self.add_step(
                step_id=step_def["id"],
                name=step_def["name"],
                probability=step_def.get("probability", 0.5),
                time_estimate=step_def.get("time_estimate", 60),
                requires=step_def.get("requires", []),
                phase=step_def.get("phase", ""),
            )

        # 构建链
        step_ids = [s["id"] for s in template["steps"]]
        chain = self.build_chain(step_ids, name=template["name"], goal=template["goal"])
        chain.target = target
        return chain

    def auto_build_chains(self, target_info: Dict = None) -> List[AttackChain]:
        """根据目标信息自动构建推荐攻击链"""
        chains = []

        # 根据目标类型选择模板
        target_type = (target_info or {}).get("type", "web")
        has_login = (target_info or {}).get("has_login", True)
        has_api = (target_info or {}).get("has_api", True)

        if target_type == "web":
            chains.append(self.build_from_template("web_sqli_data_extraction"))
            chains.append(self.build_from_template("xss_to_account_takeover"))
            if has_login:
                chains.append(self.build_from_template("auth_bypass_chain"))
            if has_api:
                chains.append(self.build_from_template("idor_privilege_escalation"))

        chains.append(self.build_from_template("ssrf_to_rce"))

        return [c for c in chains if c]

    # ─── 排序与推荐 ──────────────────────────────────────

    def get_ranked_chains(self) -> List[AttackChain]:
        """获取按 ROI 排序的攻击链"""
        self._recalculate_chains()
        return sorted(self._chains, key=lambda c: c.roi_score, reverse=True)

    def get_next_best_step(self) -> Optional[AttackStep]:
        """获取下一个最优步骤（全局最优）"""
        # 找出所有前置条件已满足的步骤
        completed_ids = {sid for sid, s in self._steps.items() if s.status == "success"}
        available = []

        for sid, step in self._steps.items():
            if step.status != "pending":
                continue
            if all(req in completed_ids for req in step.requires):
                # 计算该步骤的期望值
                ev = step.probability * step.impact_score / max(step.time_estimate, 1)
                available.append((ev, step))

        if available:
            available.sort(key=lambda x: x[0], reverse=True)
            return available[0][1]
        return None

    def get_chain_summary(self) -> List[Dict]:
        """获取所有链的摘要"""
        self._recalculate_chains()
        return [
            {
                "name": c.name,
                "goal": c.goal,
                "steps": len(c.steps),
                "probability": f"{c.compound_probability:.1%}",
                "estimated_time": f"{c.estimated_time}s",
                "roi_score": f"{c.roi_score:.3f}",
                "impact": f"{c.expected_impact:.2f}",
            }
            for c in sorted(self._chains, key=lambda c: c.roi_score, reverse=True)
        ]

    # ─── 内部方法 ──────────────────────────────────────────

    def _calculate_chain_metrics(self, chain: AttackChain):
        """计算链的各项指标"""
        if not chain.steps:
            return

        # 链式概率（各步骤概率相乘）
        prob = 1.0
        for step in chain.steps:
            prob *= step.probability
        chain.compound_probability = prob

        # 总时间
        chain.estimated_time = sum(s.time_estimate for s in chain.steps)

        # 最终影响（取最后一步的影响 × 链概率）
        final_impact = chain.steps[-1].impact_score if chain.steps else 0
        chain.expected_impact = chain.compound_probability * final_impact

        # ROI = 期望影响 / 时间（归一化）
        chain.roi_score = chain.expected_impact / max(chain.estimated_time / 60, 0.1)

    def _recalculate_chains(self):
        """重新计算所有链的指标"""
        for chain in self._chains:
            # 更新链中步骤的引用
            chain.steps = [self._steps[s.id] for s in chain.steps if s.id in self._steps]
            self._calculate_chain_metrics(chain)


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

def recommend_attack_chains(target: str, target_info: Dict = None) -> List[Dict]:
    """
    为目标推荐攻击链（一键使用）
    
    Args:
        target: 目标 URL/域名
        target_info: {"type": "web", "has_login": True, "has_api": True, ...}
    
    Returns:
        排序后的攻击链摘要列表
    """
    modeler = AttackChainModeler()
    modeler.auto_build_chains(target_info)
    return modeler.get_chain_summary()
