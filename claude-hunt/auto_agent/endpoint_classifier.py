#!/usr/bin/env python3
"""
Endpoint Classifier — API 端点语义分类 + ID 枚举候选生成

将发现的 API 端点按业务功能分类，识别高价值攻击面。
同时从响应中提取 ID 模式，生成枚举候选列表。

分类维度：
- 业务功能：auth/user/team/billing/role/invite/file/config
- 权限级别：public/user/admin/internal
- 数据敏感度：high/medium/low
- 测试优先级：基于分类自动计算
"""

import re
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs



@dataclass
class ClassifiedEndpoint:
    """分类后的端点"""
    url: str = ""
    method: str = "GET"
    # 分类结果
    business_function: str = "unknown"  # auth/user/team/billing/role/invite/file/config/...
    permission_level: str = "unknown"   # public/user/admin/internal
    data_sensitivity: str = "unknown"   # high/medium/low
    # ID 信息
    id_params: list = field(default_factory=list)   # [{"name": "user_id", "value": "123", "location": "path"}]
    id_pattern: str = ""                # sequential/uuid/timestamp/custom
    # 优先级
    test_priority: float = 0.0          # 0-10，越高越值得测
    test_suggestions: list = field(default_factory=list)


@dataclass
class IDCandidate:
    """ID 枚举候选"""
    url_template: str = ""       # /api/user/{id}/profile
    id_param: str = ""           # 参数名
    id_location: str = "path"    # path/query/body
    observed_values: list = field(default_factory=list)  # 已观察到的 ID 值
    pattern: str = "sequential"  # sequential/uuid/timestamp/short_hash
    enum_range: tuple = (1, 100) # 建议枚举范围
    priority: float = 0.0



class EndpointClassifier:
    """
    API 端点语义分类器

    输入：URL 列表（来自 recon/api_discovery）
    输出：分类后的端点 + 测试优先级 + ID 枚举候选
    """

    # 业务功能关键词映射
    FUNCTION_KEYWORDS = {
        "auth": [
            "login", "logout", "signin", "signup", "register",
            "password", "reset", "forgot", "verify", "otp",
            "mfa", "2fa", "totp", "sso", "oauth", "token",
            "session", "refresh", "authorize", "callback",
        ],
        "user": [
            "user", "profile", "account", "me", "self",
            "avatar", "preferences", "settings",
        ],
        "team": [
            "team", "org", "organization", "workspace",
            "group", "company", "tenant", "department",
        ],
        "billing": [
            "billing", "payment", "invoice", "subscription",
            "plan", "pricing", "charge", "credit", "balance",
            "wallet", "topup", "recharge", "refund", "payout",
            "transaction", "transfer", "withdraw",
        ],
        "role": [
            "role", "permission", "privilege", "access",
            "admin", "moderator", "member", "owner",
            "grant", "revoke", "policy",
        ],
        "invite": [
            "invite", "invitation", "join", "onboard",
            "share", "collaborate", "link",
        ],
        "file": [
            "file", "upload", "download", "attachment",
            "document", "media", "image", "asset", "export",
            "import", "storage", "bucket",
        ],
        "config": [
            "config", "setting", "option", "feature",
            "flag", "toggle", "environment", "variable",
            "webhook", "integration", "api_key", "secret",
        ],
        "data": [
            "report", "analytics", "dashboard", "metric",
            "log", "audit", "history", "activity", "event",
        ],
        "messaging": [
            "message", "chat", "notification", "email",
            "sms", "push", "comment", "thread", "reply",
        ],
        "order": [
            "order", "cart", "checkout", "purchase",
            "product", "item", "catalog", "inventory",
            "coupon", "discount", "promo",
        ],
    }

    # 权限级别关键词
    PERMISSION_KEYWORDS = {
        "admin": ["admin", "internal", "manage", "system", "debug", "actuator"],
        "internal": ["internal", "private", "debug", "health", "status", "metrics"],
        "public": ["public", "open", "anonymous", "guest", "static"],
    }

    # 高敏感度端点模式
    HIGH_SENSITIVITY_PATTERNS = [
        r"/api/.*/(payment|billing|transaction|transfer|withdraw)",
        r"/api/.*/(password|secret|key|token|credential)",
        r"/api/.*/(admin|manage|internal)",
        r"/api/.*/user.*/\d+",
        r"/api/.*/(export|download|dump|backup)",
    ]

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.classified: list[ClassifiedEndpoint] = []
        self.id_candidates: list[IDCandidate] = []


    def classify_urls(self, urls: list[str]) -> list[ClassifiedEndpoint]:
        """批量分类 URL 列表"""
        self.classified = []
        for url in urls:
            endpoint = self._classify_single(url)
            self.classified.append(endpoint)

        # 检测认证不一致（同组 API 部分需要认证部分不需要）
        self._detect_auth_inconsistency()

        # 生成 ID 枚举候选
        self._generate_id_candidates()

        return self.classified

    def _classify_single(self, url: str, method: str = "GET") -> ClassifiedEndpoint:
        """分类单个端点"""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        url_lower = url.lower()

        endpoint = ClassifiedEndpoint(url=url, method=method)

        # 1. 业务功能分类
        endpoint.business_function = self._detect_function(path_lower)

        # 2. 权限级别
        endpoint.permission_level = self._detect_permission(path_lower)

        # 3. 数据敏感度
        endpoint.data_sensitivity = self._detect_sensitivity(url_lower)

        # 4. 提取 ID 参数
        endpoint.id_params = self._extract_ids(url)

        # 5. 计算测试优先级
        endpoint.test_priority = self._calculate_priority(endpoint)

        # 6. 生成测试建议
        endpoint.test_suggestions = self._suggest_tests(endpoint)

        return endpoint

    def _detect_function(self, path: str) -> str:
        """检测业务功能"""
        best_match = "unknown"
        best_score = 0
        for function, keywords in self.FUNCTION_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in path)
            if score > best_score:
                best_score = score
                best_match = function
        return best_match

    def _detect_permission(self, path: str) -> str:
        """检测权限级别"""
        for level, keywords in self.PERMISSION_KEYWORDS.items():
            if any(kw in path for kw in keywords):
                return level
        return "user"  # 默认假设需要用户级权限

    def _detect_sensitivity(self, url: str) -> str:
        """检测数据敏感度"""
        for pattern in self.HIGH_SENSITIVITY_PATTERNS:
            if re.search(pattern, url, re.I):
                return "high"
        if any(kw in url for kw in ["user", "account", "profile", "email", "phone"]):
            return "medium"
        return "low"

    def _extract_ids(self, url: str) -> list[dict]:
        """从 URL 中提取所有 ID 参数"""
        ids = []
        parsed = urlparse(url)

        # 路径中的数字 ID
        parts = parsed.path.split("/")
        for i, part in enumerate(parts):
            if re.match(r"^\d+$", part) and int(part) < 10000000:
                # 推断参数名（基于前一段路径）
                param_name = parts[i - 1] if i > 0 else "id"
                param_name = param_name.rstrip("s")  # users -> user
                ids.append({
                    "name": f"{param_name}_id",
                    "value": part,
                    "location": "path",
                    "index": i,
                })
            elif re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                part, re.I
            ):
                param_name = parts[i - 1] if i > 0 else "id"
                ids.append({
                    "name": f"{param_name}_uuid",
                    "value": part,
                    "location": "path",
                    "index": i,
                })

        # 查询参数中的 ID
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in qs.items():
            if values and re.match(r"^\d+$", values[0]):
                ids.append({
                    "name": param,
                    "value": values[0],
                    "location": "query",
                })

        return ids


    def _calculate_priority(self, endpoint: ClassifiedEndpoint) -> float:
        """计算测试优先级 (0-10)"""
        score = 0.0

        # 业务功能权重
        function_weights = {
            "billing": 3.0, "auth": 2.5, "role": 2.5,
            "invite": 2.0, "user": 2.0, "team": 1.8,
            "config": 1.5, "file": 1.5, "order": 2.0,
            "messaging": 1.2, "data": 1.0, "unknown": 0.5,
        }
        score += function_weights.get(endpoint.business_function, 0.5)

        # 敏感度加权
        sensitivity_weights = {"high": 2.5, "medium": 1.5, "low": 0.5}
        score += sensitivity_weights.get(endpoint.data_sensitivity, 0.5)

        # 有 ID 参数加分（IDOR 机会）
        if endpoint.id_params:
            score += 2.0
            # 数字 ID 比 UUID 更容易枚举
            if any(re.match(r"^\d+$", p["value"]) for p in endpoint.id_params):
                score += 1.0

        # admin/internal 端点加分
        if endpoint.permission_level in ("admin", "internal"):
            score += 1.5

        return min(10.0, score)

    def _suggest_tests(self, endpoint: ClassifiedEndpoint) -> list[str]:
        """基于分类生成测试建议"""
        suggestions = []

        if endpoint.id_params:
            suggestions.append("IDOR: 替换ID为其他用户的资源ID，对比响应")
            suggestions.append("ID枚举: 遍历相邻数字ID，检查是否可访问")

        func = endpoint.business_function
        if func == "auth":
            suggestions.extend([
                "测试: OTP 限速绕过（并发请求）",
                "测试: 密码重置令牌可预测性",
                "测试: OAuth redirect_uri 限制绕过",
            ])
        elif func == "billing":
            suggestions.extend([
                "测试: 负数金额/数量",
                "测试: 竞态条件（重复提交支付）",
                "测试: 价格参数篡改",
                "测试: 优惠券重复使用",
            ])
        elif func == "role":
            suggestions.extend([
                "测试: 垂直越权（普通用户调用admin接口）",
                "测试: 参数注入 role=admin",
                "测试: 批量操作权限",
            ])
        elif func == "invite":
            suggestions.extend([
                "测试: 邀请链接可枚举",
                "测试: 已过期邀请仍可使用",
                "测试: 邀请权限提升",
            ])
        elif func == "file":
            suggestions.extend([
                "测试: 路径穿越 (../../etc/passwd)",
                "测试: 文件类型绕过上传",
                "测试: 通过文件ID访问他人文件",
            ])
        elif func == "config":
            suggestions.extend([
                "测试: 未授权读取配置",
                "测试: Webhook URL SSRF",
                "测试: API Key 泄露",
            ])

        if endpoint.permission_level in ("admin", "internal"):
            suggestions.append("测试: 403绕过（方法/头/路径变异）")

        return suggestions

    def _detect_auth_inconsistency(self):
        """检测同组 API 中的认证不一致"""
        # 按 API 前缀分组
        groups = {}
        for ep in self.classified:
            parsed = urlparse(ep.url)
            parts = parsed.path.strip("/").split("/")
            if len(parts) >= 2:
                prefix = "/".join(parts[:2])
                groups.setdefault(prefix, []).append(ep)

        for prefix, endpoints in groups.items():
            perm_levels = set(ep.permission_level for ep in endpoints)
            if "public" in perm_levels and ("user" in perm_levels or "admin" in perm_levels):
                # 同组中有 public 也有需要认证的 → 可能不一致
                for ep in endpoints:
                    if ep.permission_level == "public":
                        ep.test_priority += 2.0
                        ep.test_suggestions.insert(
                            0, "认证不一致: 同API组有受保护端点，此端点可能遗漏了权限检查"
                        )


    def _generate_id_candidates(self):
        """从分类结果中生成 ID 枚举候选"""
        self.id_candidates = []
        seen_templates = set()

        for ep in self.classified:
            if not ep.id_params:
                continue

            for id_info in ep.id_params:
                # 生成 URL 模板
                template = self._make_url_template(ep.url, id_info)
                if template in seen_templates:
                    continue
                seen_templates.add(template)

                # 判断 ID 模式
                value = id_info["value"]
                if re.match(r"^\d+$", value):
                    pattern = "sequential"
                    num_val = int(value)
                    # 枚举范围：以观察值为中心 ±50
                    enum_range = (max(1, num_val - 50), num_val + 50)
                elif re.match(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}",
                    value, re.I
                ):
                    pattern = "uuid"
                    enum_range = (0, 0)  # UUID 不可枚举
                else:
                    pattern = "custom"
                    enum_range = (0, 0)

                priority = ep.test_priority
                if pattern == "sequential":
                    priority += 2.0  # 可枚举的加分

                self.id_candidates.append(IDCandidate(
                    url_template=template,
                    id_param=id_info["name"],
                    id_location=id_info["location"],
                    observed_values=[value],
                    pattern=pattern,
                    enum_range=enum_range,
                    priority=min(10.0, priority),
                ))

        # 按优先级排序
        self.id_candidates.sort(key=lambda c: c.priority, reverse=True)

    def _make_url_template(self, url: str, id_info: dict) -> str:
        """将 URL 中的 ID 替换为模板占位符"""
        if id_info["location"] == "path":
            parsed = urlparse(url)
            parts = parsed.path.split("/")
            idx = id_info.get("index", -1)
            if 0 <= idx < len(parts):
                parts[idx] = "{" + id_info["name"] + "}"
            return parsed._replace(path="/".join(parts)).geturl()
        elif id_info["location"] == "query":
            return re.sub(
                rf"([?&]){re.escape(id_info['name'])}=[^&]*",
                rf"\1{id_info['name']}={{id}}",
                url,
            )
        return url

    def get_high_priority_endpoints(self, top_n: int = 20) -> list[ClassifiedEndpoint]:
        """获取最高优先级端点"""
        sorted_eps = sorted(self.classified, key=lambda e: e.test_priority, reverse=True)
        return sorted_eps[:top_n]

    def get_idor_candidates(self) -> list[IDCandidate]:
        """获取可枚举的 ID 候选列表"""
        return [c for c in self.id_candidates if c.pattern == "sequential"]
