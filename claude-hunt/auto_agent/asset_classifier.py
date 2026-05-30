#!/usr/bin/env python3
"""
Asset Classifier — 资产分类管理

解决问题：
- 资产只是列表不够细，需要区分 Web/API/UAT/生产/移动/第三方
- 不同资产有不同测试权限（只读、登录后、禁止自动化）
- 避免测试 out-of-scope 或第三方资产

功能：
1. 资产自动分类（基于 URL 模式、响应特征、header 分析）
2. 手动标注资产类型和可测权限
3. 与 ComplianceMode 联动
4. 资产状态跟踪（未测/测试中/已完成/跳过）

用法：
    from asset_classifier import AssetClassifier

    ac = AssetClassifier()
    ac.add_asset("https://api.syfe.com", type="api", env="production")
    ac.add_asset("https://uat.syfe.com", type="web", env="uat", actions=["read_only"])

    # 自动分类一批 URL
    ac.auto_classify(["https://app.syfe.com", "https://api-staging.syfe.com", ...])

    # 获取可测资产
    testable = ac.get_testable_assets()
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class Asset:
    """资产"""
    url: str = ""
    host: str = ""
    # 分类
    asset_type: str = ""       # web/api/mobile_api/graphql/websocket/grpc
    environment: str = ""      # production/uat/staging/dev/unknown
    category: str = ""         # frontend/backend/admin/docs/third_party/cdn/not_test
    # 权限
    allowed_actions: List[str] = field(default_factory=list)
    # ["read_only", "authenticated", "full_test", "no_automation", "no_write"]
    # 状态
    status: str = "untested"   # untested/testing/done/skipped/blocked
    # 信息
    tech_stack: List[str] = field(default_factory=list)
    title: str = ""
    notes: str = ""
    # 来源
    discovered_by: str = ""    # recon/manual/har/scope
    added_at: str = ""


# 环境识别关键词
ENV_PATTERNS = {
    "uat": [r"uat\.", r"uat-", r"-uat", r"\.uat\b"],
    "staging": [r"staging\.", r"stage\.", r"stg\.", r"-staging", r"-stg"],
    "dev": [r"dev\.", r"develop\.", r"-dev\b", r"\.dev\b", r"localhost"],
    "test": [r"test\.", r"testing\.", r"-test\b", r"qa\."],
    "production": [],  # 默认
}

# 类型识别关键词
TYPE_PATTERNS = {
    "api": [r"api\.", r"api-", r"/api/", r"-api\.", r"\.api\."],
    "mobile_api": [r"mobile\.", r"m-api\.", r"app-api\.", r"mobile-api\."],
    "graphql": [r"graphql\.", r"/graphql"],
    "admin": [r"admin\.", r"backoffice\.", r"manage\.", r"internal\."],
    "docs": [r"docs\.", r"doc\.", r"help\.", r"support\."],
    "cdn": [r"cdn\.", r"static\.", r"assets\.", r"media\."],
}

# 第三方服务识别
THIRD_PARTY_DOMAINS = [
    "amazonaws.com", "cloudfront.net", "cloudflare.com",
    "google.com", "googleapis.com", "gstatic.com",
    "facebook.com", "twitter.com", "linkedin.com",
    "stripe.com", "paypal.com", "braintree.com",
    "intercom.io", "zendesk.com", "freshdesk.com",
    "segment.io", "mixpanel.com", "amplitude.com",
    "sentry.io", "bugsnag.com", "datadog.com",
    "auth0.com", "okta.com", "cognito",
    "sendgrid.net", "mailgun.org", "mailchimp.com",
    "twilio.com", "nexmo.com",
    "github.com", "gitlab.com", "bitbucket.org",
]


class AssetClassifier:
    """资产分类管理器"""

    def __init__(self, config: dict = None, program_name: str = ""):
        self.config = config or {}
        self.program_name = program_name
        self.assets: List[Asset] = []
        self.assets_dir = os.path.expanduser("~/.bai-agent/assets")
        Path(self.assets_dir).mkdir(parents=True, exist_ok=True)

    def add_asset(self, url: str, asset_type: str = "", env: str = "",
                  category: str = "", actions: List[str] = None,
                  notes: str = "") -> Asset:
        """手动添加资产"""
        parsed = urlparse(url)
        host = parsed.netloc or url

        asset = Asset(
            url=url,
            host=host,
            asset_type=asset_type or self._detect_type(url),
            environment=env or self._detect_env(url),
            category=category or self._detect_category(url),
            allowed_actions=actions or ["full_test"],
            discovered_by="manual",
            added_at=datetime.now().isoformat(),
            notes=notes,
        )

        # 去重
        if not any(a.url == url for a in self.assets):
            self.assets.append(asset)

        return asset

    def auto_classify(self, urls: List[str]) -> List[Asset]:
        """自动分类一批 URL"""
        classified = []
        for url in urls:
            asset = self.add_asset(url)
            classified.append(asset)

        # 打印分类结果
        self._print_classification_summary(classified)
        return classified

    def get_testable_assets(self, env: str = None, asset_type: str = None) -> List[Asset]:
        """获取可测试的资产（排除第三方和跳过的）"""
        result = []
        for a in self.assets:
            if a.status == "skipped" or a.category == "not_test":
                continue
            if a.category == "third_party":
                continue
            if env and a.environment != env:
                continue
            if asset_type and a.asset_type != asset_type:
                continue
            result.append(a)
        return result

    def get_by_env(self, env: str) -> List[Asset]:
        """按环境获取"""
        return [a for a in self.assets if a.environment == env]

    def get_by_type(self, asset_type: str) -> List[Asset]:
        """按类型获取"""
        return [a for a in self.assets if a.asset_type == asset_type]

    def mark_status(self, url: str, status: str):
        """标记资产状态"""
        for a in self.assets:
            if a.url == url or a.host == url:
                a.status = status
                return

    def get_summary(self) -> str:
        """获取资产分类摘要"""
        lines = [f"\n资产分类摘要 ({len(self.assets)} 个):\n"]

        # 按环境分组
        by_env = {}
        for a in self.assets:
            by_env.setdefault(a.environment or "unknown", []).append(a)

        for env, assets in sorted(by_env.items()):
            emoji = {"production": "🟢", "uat": "🟡", "staging": "🟠",
                     "dev": "🔵", "unknown": "⚪"}.get(env, "⚪")
            lines.append(f"  {emoji} {env.upper()} ({len(assets)})")
            for a in assets[:10]:
                type_tag = f"[{a.asset_type}]" if a.asset_type else ""
                action_tag = f"({','.join(a.allowed_actions[:2])})" if a.allowed_actions != ["full_test"] else ""
                lines.append(f"      {a.host:40s} {type_tag:12s} {action_tag}")

        # 第三方
        third_party = [a for a in self.assets if a.category == "third_party"]
        if third_party:
            lines.append(f"\n  ⛔ 第三方/不测 ({len(third_party)})")
            for a in third_party[:5]:
                lines.append(f"      {a.host}")

        return "\n".join(lines)

    def save(self, name: str = None):
        """保存资产分类"""
        name = name or self.program_name or "default"
        path = os.path.join(self.assets_dir, f"{name}_assets.json")
        from dataclasses import asdict
        data = [asdict(a) for a in self.assets]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] 资产已保存: {path}")

    def load(self, name: str = None) -> List[Asset]:
        """加载资产分类"""
        name = name or self.program_name or "default"
        path = os.path.join(self.assets_dir, f"{name}_assets.json")
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assets = [Asset(**item) for item in data]
        print(f"[+] 已加载 {len(self.assets)} 个资产")
        return self.assets

    # ═══════════════════════════════════════════════════════════
    # 自动检测
    # ═══════════════════════════════════════════════════════════

    def _detect_env(self, url: str) -> str:
        """检测环境"""
        url_lower = url.lower()
        for env, patterns in ENV_PATTERNS.items():
            for p in patterns:
                if re.search(p, url_lower):
                    return env
        return "production"

    def _detect_type(self, url: str) -> str:
        """检测资产类型"""
        url_lower = url.lower()
        for atype, patterns in TYPE_PATTERNS.items():
            for p in patterns:
                if re.search(p, url_lower):
                    return atype
        return "web"

    def _detect_category(self, url: str) -> str:
        """检测资产类别"""
        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # 第三方检测
        for domain in THIRD_PARTY_DOMAINS:
            if domain in host:
                return "third_party"

        # 管理后台
        if any(kw in host for kw in ["admin", "backoffice", "internal", "manage"]):
            return "admin"

        # 文档
        if any(kw in host for kw in ["docs", "doc", "help", "support", "wiki"]):
            return "docs"

        return "frontend" if self._detect_type(url) == "web" else "backend"

    def _print_classification_summary(self, assets: List[Asset]):
        """打印分类结果"""
        print(f"\n[+] 自动分类 {len(assets)} 个资产:")
        for a in assets[:20]:
            env_emoji = {"production": "🟢", "uat": "🟡", "staging": "🟠",
                         "dev": "🔵"}.get(a.environment, "⚪")
            cat_emoji = {"third_party": "⛔", "admin": "🔑", "docs": "📄"}.get(a.category, "")
            print(f"  {env_emoji} {a.host:35s} [{a.asset_type:8s}] [{a.environment:10s}] {cat_emoji}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="资产分类管理器")
    parser.add_argument("--classify", nargs="+", help="自动分类 URL 列表")
    parser.add_argument("--file", help="从文件导入 URL（每行一个）")
    parser.add_argument("--program", default="", help="项目名称")
    parser.add_argument("--show", action="store_true", help="显示当前资产")
    args = parser.parse_args()

    ac = AssetClassifier(program_name=args.program)

    if args.classify:
        ac.auto_classify(args.classify)
        print(ac.get_summary())
    elif args.file:
        with open(args.file) as f:
            urls = [l.strip() for l in f if l.strip()]
        ac.auto_classify(urls)
        print(ac.get_summary())
        if args.program:
            ac.save()
    elif args.show:
        ac.load()
        print(ac.get_summary())
    else:
        parser.print_help()
