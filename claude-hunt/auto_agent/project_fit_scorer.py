#!/usr/bin/env python3
"""
Project Fit Scorer — 自动判断赏金项目值不值得打

评分维度（满分100）：
1. 注册难度（能不能注册/需不需要KYC）
2. 攻击面大小（有API/GraphQL/移动端/多子域吗）
3. 排除项严格度（排除了多少常见洞）
4. 赏金活跃度（最近有没有人拿过bounty）
5. 竞争度（参与人数 vs 解决报告数）
6. 技术栈适配（是不是你工具擅长打的）

用法：
    from project_fit_scorer import ProjectFitScorer
    scorer = ProjectFitScorer()

    # 从 H1 API 自动评分
    score = scorer.score_h1_program("shopify")

    # 手动评分
    score = scorer.score({
        "can_register": True,
        "has_api": True,
        "exclusions_count": 5,
        "recent_bounty": True,
    })
"""

import json, os, re
from datetime import datetime
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ProjectFitScorer:
    def __init__(self, config=None):
        self.config = config or {}
        self.output_dir = os.path.expanduser('~/.bai-agent/project-scores')
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def score_h1_program(self, handle):
        """从 HackerOne GraphQL API 自动拉信息并评分"""
        if not HAS_REQUESTS:
            return {"error": "requests not installed", "score": 0}

        info = self._fetch_h1_info(handle)
        if not info:
            return {"error": f"无法获取 {handle} 信息", "score": 0}

        return self._calculate_score(info, handle)

    def score(self, info):
        """手动传入信息评分"""
        return self._calculate_score(info, info.get("name", "manual"))

    def _fetch_h1_info(self, handle):
        """从 H1 GraphQL 拉项目信息"""
        query = """
        { team(handle: "%s") {
            name
            offers_bounties
            resolved_report_count
            allows_bounty_splitting
            policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty instruction } } }
            structured_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty } } }
        } }
        """ % handle

        try:
            r = requests.post("https://hackerone.com/graphql",
                            json={"query": query},
                            headers={"Content-Type": "application/json"},
                            timeout=15)
            data = r.json().get("data", {}).get("team", {})
            if not data:
                return None

            # 解析 scope
            scopes = []
            for edge in data.get("policy_scopes", {}).get("edges", []):
                scopes.append(edge["node"])

            # 统计
            info = {
                "name": data.get("name", handle),
                "offers_bounties": data.get("offers_bounties", False),
                "resolved_reports": data.get("resolved_report_count", 0),
                "allows_splitting": data.get("allows_bounty_splitting", False),
                "total_scope_assets": len(scopes),
                "eligible_assets": sum(1 for s in scopes if s.get("eligible_for_bounty")),
                "has_api": any("api" in (s.get("asset_identifier", "") + s.get("asset_type", "")).lower() for s in scopes),
                "has_wildcard": any("*" in s.get("asset_identifier", "") for s in scopes),
                "has_mobile": any(s.get("asset_type", "") in ("GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK") for s in scopes),
                "has_source_code": any(s.get("asset_type", "") == "SOURCE_CODE" for s in scopes),
                "scope_types": list(set(s.get("asset_type", "") for s in scopes)),
            }

            return info

        except Exception as e:
            return None

    def _calculate_score(self, info, handle):
        """计算评分"""
        score = 0
        breakdown = {}

        # 1. 赏金活跃度（0-25分）
        resolved = info.get("resolved_reports", 0)
        if resolved > 100:
            breakdown["bounty_active"] = 25
        elif resolved > 50:
            breakdown["bounty_active"] = 20
        elif resolved > 20:
            breakdown["bounty_active"] = 15
        elif resolved > 5:
            breakdown["bounty_active"] = 10
        else:
            breakdown["bounty_active"] = 5
        # 最近有人拿过 = 项目还活着
        if info.get("recent_bounty", True) and info.get("offers_bounties", True):
            breakdown["bounty_active"] += 5

        # 2. 攻击面大小（0-30分）
        scope_size = info.get("total_scope_assets", 0)
        if scope_size >= 20:
            breakdown["attack_surface"] = 20
        elif scope_size >= 10:
            breakdown["attack_surface"] = 15
        elif scope_size >= 5:
            breakdown["attack_surface"] = 10
        else:
            breakdown["attack_surface"] = 5

        if info.get("has_api"):
            breakdown["attack_surface"] += 5
        if info.get("has_wildcard"):
            breakdown["attack_surface"] += 3
        if info.get("has_mobile"):
            breakdown["attack_surface"] += 2

        # 3. 注册/准入难度（0-20分）
        # 有 wildcard/API = 容易注册
        if info.get("can_register", True):
            breakdown["access"] = 15
        else:
            breakdown["access"] = 5
        if not info.get("requires_kyc", False):
            breakdown["access"] += 5

        # 4. 工具适配度（0-15分）
        breakdown["tool_fit"] = 5
        if info.get("has_api"):
            breakdown["tool_fit"] += 5  # 你的工具擅长 API 测试
        if info.get("has_wildcard"):
            breakdown["tool_fit"] += 3  # 子域名枚举能力强
        if info.get("has_source_code"):
            breakdown["tool_fit"] += 2  # Shannon 白盒

        # 5. 排除项（0-10分）
        exclusions = info.get("exclusions_count", 0)
        if exclusions <= 5:
            breakdown["exclusions"] = 10
        elif exclusions <= 10:
            breakdown["exclusions"] = 7
        elif exclusions <= 20:
            breakdown["exclusions"] = 4
        else:
            breakdown["exclusions"] = 2

        # 汇总
        total = sum(breakdown.values())
        total = min(total, 100)

        verdict = "SKIP"
        if total >= 70:
            verdict = "GO — 高价值目标"
        elif total >= 50:
            verdict = "MAYBE — 值得花 2 小时试试"
        elif total >= 30:
            verdict = "LOW — 只在没别的可打时考虑"
        else:
            verdict = "SKIP — 不值得花时间"

        result = {
            "program": handle,
            "score": total,
            "verdict": verdict,
            "breakdown": breakdown,
            "info": info,
            "timestamp": datetime.now().isoformat(),
        }

        # 保存
        out = os.path.join(self.output_dir, f"{handle}_score.json")
        Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')

        return result
