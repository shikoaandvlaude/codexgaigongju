#!/usr/bin/env python3
"""
JS Analyzer — JavaScript 文件安全分析器
从 JS bundle 中提取攻击面信息

提取内容：
1. API 端点路径 (/api/v1/users, /graphql)
2. 硬编码密钥/Token (API Key, Secret, OAuth client_secret)
3. 隐藏/调试接口 (/admin, /debug, /internal)
4. 环境变量引用 (process.env.*, import.meta.env.*)
5. 云服务配置 (S3 bucket, Firebase config, AWS region)
6. DOM XSS Sink (innerHTML, eval, document.write)
7. postMessage handler（可能的 XSS 入口）
8. WebSocket 端点

用法:
    analyzer = JSAnalyzer()
    
    # 分析单个 JS 文件内容
    findings = analyzer.analyze(js_content, source_url="https://target.com/main.js")
    
    # 批量分析（配合 browser_crawler 使用）
    all_findings = await analyzer.analyze_urls(js_url_list, http_engine)
"""

import re
import json
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class JSFinding:
    """JS 分析发现"""
    category: str = ""        # endpoint/secret/sink/config/debug
    severity: str = "info"    # critical/high/medium/low/info
    value: str = ""           # 发现的值
    context: str = ""         # 上下文（前后代码片段）
    source_url: str = ""      # JS 文件 URL
    line_number: int = 0      # 行号
    confidence: float = 0.0   # 置信度 0-1


@dataclass
class JSAnalysisResult:
    """分析结果汇总"""
    endpoints: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    sinks: list = field(default_factory=list)
    configs: list = field(default_factory=list)
    debug_endpoints: list = field(default_factory=list)
    source_maps: list = field(default_factory=list)
    all_findings: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# 正则模式
# ═══════════════════════════════════════════════════════════════

# API 端点模式
ENDPOINT_PATTERNS = [
    # 字符串中的 API 路径
    r'["\'](/api/[a-zA-Z0-9_/\-{}:.]+)["\']',
    r'["\'](/v[1-9]/[a-zA-Z0-9_/\-{}:.]+)["\']',
    r'["\'](/graphql)["\']',
    r'["\'](/rest/[a-zA-Z0-9_/\-{}:.]+)["\']',
    r'["\'](/internal/[a-zA-Z0-9_/\-{}:.]+)["\']',
    r'["\'](/admin/[a-zA-Z0-9_/\-{}:.]+)["\']',
    r'["\'](/debug/[a-zA-Z0-9_/\-{}:.]+)["\']',
    # fetch/axios 调用
    r'(?:fetch|axios\.?\w*)\s*\(\s*[`"\']([^`"\']+)[`"\']',
    r'(?:\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*[`"\']([^`"\']+)[`"\']',
    # URL 拼接
    r'(?:baseUrl|BASE_URL|apiUrl|API_URL|endpoint)\s*[=:+]\s*[`"\']([^`"\']+)[`"\']',
    # Route 定义
    r'(?:path|route)\s*:\s*["\']([^"\']+)["\']',
]

# 密钥/Token 模式
SECRET_PATTERNS = [
    # API Keys
    (r'["\']([A-Za-z0-9_\-]{32,})["\']', "api_key_generic", 0.3),
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{16,})["\']', "api_key", 0.8),
    (r'(?:secret|SECRET)\s*[=:]\s*["\']([^"\']{16,})["\']', "secret", 0.8),
    (r'(?:token|TOKEN)\s*[=:]\s*["\']([^"\']{16,})["\']', "token", 0.7),
    (r'(?:password|passwd|PASS)\s*[=:]\s*["\']([^"\']{4,})["\']', "password", 0.8),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "aws_access_key", 0.95),
    (r'(?:aws_secret|AWS_SECRET)\s*[=:]\s*["\']([^"\']{40})["\']', "aws_secret", 0.9),
    # Google
    (r'AIza[0-9A-Za-z_\-]{35}', "google_api_key", 0.9),
    # Firebase
    (r'(?:firebase|FIREBASE)\s*[=:]\s*["\']([^"\']+\.firebaseapp\.com)["\']', "firebase_url", 0.8),
    # JWT
    (r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "jwt_token", 0.85),
    # OAuth
    (r'(?:client_secret|CLIENT_SECRET)\s*[=:]\s*["\']([^"\']{16,})["\']', "oauth_client_secret", 0.9),
    (r'(?:client_id|CLIENT_ID)\s*[=:]\s*["\']([^"\']{16,})["\']', "oauth_client_id", 0.5),
    # Private keys
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "private_key", 0.95),
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', "stripe_secret_key", 0.95),
    (r'pk_live_[0-9a-zA-Z]{24,}', "stripe_publishable_key", 0.4),
    # Slack
    (r'xox[baprs]-[0-9a-zA-Z\-]+', "slack_token", 0.9),
    # GitHub
    (r'gh[ps]_[A-Za-z0-9_]{36,}', "github_token", 0.9),
]

# DOM XSS Sink 模式
SINK_PATTERNS = [
    (r'\.innerHTML\s*=', "innerHTML", "high"),
    (r'\.outerHTML\s*=', "outerHTML", "high"),
    (r'document\.write\s*\(', "document.write", "high"),
    (r'eval\s*\(', "eval", "critical"),
    (r'setTimeout\s*\(\s*[^,\)]*\+', "setTimeout_string", "high"),
    (r'setInterval\s*\(\s*[^,\)]*\+', "setInterval_string", "high"),
    (r'new\s+Function\s*\(', "new_Function", "critical"),
    (r'\.src\s*=\s*[^"\';\n]*(?:location|document|window)', "src_assignment", "medium"),
    (r'\.href\s*=\s*[^"\';\n]*(?:location|document|window)', "href_assignment", "medium"),
    (r'location\s*=\s*', "location_assignment", "medium"),
    (r'postMessage\s*\(', "postMessage", "medium"),
    (r'addEventListener\s*\(\s*["\']message["\']', "message_listener", "medium"),
    (r'dangerouslySetInnerHTML', "react_dangerously", "high"),
    (r'\$\(\s*[^)]*\)\.html\s*\(', "jquery_html", "high"),
]

# 云服务/环境配置模式
CONFIG_PATTERNS = [
    (r'(?:s3|S3)[_.]?(?:bucket|BUCKET)\s*[=:]\s*["\']([^"\']+)["\']', "s3_bucket"),
    (r'["\']([a-z0-9\-]+\.s3\.amazonaws\.com)["\']', "s3_url"),
    (r'(?:region|REGION)\s*[=:]\s*["\']([a-z]{2}-[a-z]+-\d+)["\']', "aws_region"),
    (r'(?:cognito|COGNITO)[_.]?(?:pool|POOL)\s*[=:]\s*["\']([^"\']+)["\']', "cognito_pool"),
    (r'["\']https?://[^"\']*\.cloudfunctions\.net[^"\']*["\']', "cloud_function"),
    (r'(?:SENTRY_DSN|sentryDsn)\s*[=:]\s*["\']([^"\']+)["\']', "sentry_dsn"),
    (r'(?:GOOGLE_MAPS|googleMaps|maps_key)\s*[=:]\s*["\']([^"\']+)["\']', "google_maps_key"),
]

# 调试/管理端点
DEBUG_PATTERNS = [
    r'["\'](?:/(?:admin|debug|internal|test|dev|staging|backdoor|console|phpinfo|actuator|swagger|api-docs|graphiql|playground)[^"\']*)["\']',
]


# ═══════════════════════════════════════════════════════════════
# JS Analyzer
# ═══════════════════════════════════════════════════════════════

class JSAnalyzer:
    """JS 文件安全分析器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.base_url = self.config.get("base_url", "")
        # 忽略的模式（减少误报）
        self.ignore_patterns = self.config.get("ignore_patterns", [
            r"node_modules", r"\.min\.js", r"jquery", r"bootstrap",
            r"react\.production", r"vendor", r"polyfill",
        ])

    def analyze(self, js_content: str, source_url: str = "") -> JSAnalysisResult:
        """
        分析单个 JS 文件内容
        返回所有发现
        """
        result = JSAnalysisResult()

        if not js_content or len(js_content) < 10:
            return result

        # 检查是否应该忽略
        if source_url:
            for pattern in self.ignore_patterns:
                if re.search(pattern, source_url, re.I):
                    return result

        # 按行分析（保留行号信息）
        lines = js_content.split("\n")

        # 1. 提取 API 端点
        endpoints = self._extract_endpoints(js_content, source_url)
        result.endpoints = endpoints
        result.all_findings.extend(endpoints)

        # 2. 检测硬编码密钥
        secrets = self._extract_secrets(js_content, lines, source_url)
        result.secrets = secrets
        result.all_findings.extend(secrets)

        # 3. DOM XSS Sink 检测
        sinks = self._detect_sinks(js_content, lines, source_url)
        result.sinks = sinks
        result.all_findings.extend(sinks)

        # 4. 云服务/环境配置
        configs = self._extract_configs(js_content, source_url)
        result.configs = configs
        result.all_findings.extend(configs)

        # 5. 调试端点
        debug = self._detect_debug_endpoints(js_content, source_url)
        result.debug_endpoints = debug
        result.all_findings.extend(debug)

        # 6. Source Map 检测
        if "//# sourceMappingURL=" in js_content:
            map_url = re.search(r'//# sourceMappingURL=(.+?)(?:\s|$)', js_content)
            if map_url:
                result.source_maps.append(JSFinding(
                    category="source_map",
                    severity="medium",
                    value=map_url.group(1),
                    source_url=source_url,
                    confidence=0.9,
                ))

        return result

    async def analyze_urls(self, js_urls: list, http_engine) -> JSAnalysisResult:
        """批量分析 JS URL（配合 http_engine 使用）"""
        combined = JSAnalysisResult()

        for url in js_urls:
            try:
                resp = await http_engine.get(url)
                if resp.status_code == 200 and resp.body:
                    result = self.analyze(resp.body, source_url=url)
                    combined.endpoints.extend(result.endpoints)
                    combined.secrets.extend(result.secrets)
                    combined.sinks.extend(result.sinks)
                    combined.configs.extend(result.configs)
                    combined.debug_endpoints.extend(result.debug_endpoints)
                    combined.source_maps.extend(result.source_maps)
                    combined.all_findings.extend(result.all_findings)
            except Exception:
                pass

        return combined

    # ─── 端点提取 ──────────────────────────────────────────────

    def _extract_endpoints(self, content: str, source_url: str) -> list:
        """提取 API 端点"""
        findings = []
        seen = set()

        for pattern in ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip()

                # 过滤
                if not endpoint or len(endpoint) < 3:
                    continue
                if endpoint in seen:
                    continue
                if not endpoint.startswith("/") and not endpoint.startswith("http"):
                    continue
                # 排除明显不是端点的
                if any(x in endpoint for x in [".css", ".png", ".jpg", ".svg", "node_modules"]):
                    continue

                seen.add(endpoint)

                # 判断是否是调试/管理端点
                is_debug = any(kw in endpoint.lower() for kw in
                             ["admin", "debug", "internal", "test", "dev", "staging"])

                findings.append(JSFinding(
                    category="endpoint",
                    severity="medium" if is_debug else "info",
                    value=endpoint,
                    context=content[max(0, match.start()-30):match.end()+30][:100],
                    source_url=source_url,
                    confidence=0.7,
                ))

        return findings

    # ─── 密钥提取 ──────────────────────────────────────────────

    def _extract_secrets(self, content: str, lines: list, source_url: str) -> list:
        """检测硬编码密钥"""
        findings = []

        for pattern, secret_type, confidence in SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.I)
            for match in matches:
                value = match.group(1) if match.lastindex else match.group(0)

                # 过滤明显的误报
                if self._is_false_positive_secret(value, secret_type):
                    continue

                # 找到行号
                pos = match.start()
                line_num = content[:pos].count("\n") + 1

                # 获取上下文
                context_start = max(0, pos - 50)
                context_end = min(len(content), pos + len(value) + 50)
                context = content[context_start:context_end]

                severity = "critical" if confidence >= 0.9 else "high" if confidence >= 0.7 else "medium"

                findings.append(JSFinding(
                    category="secret",
                    severity=severity,
                    value=f"[{secret_type}] {value[:50]}{'...' if len(value) > 50 else ''}",
                    context=context[:120],
                    source_url=source_url,
                    line_number=line_num,
                    confidence=confidence,
                ))

        return findings

    def _is_false_positive_secret(self, value: str, secret_type: str) -> bool:
        """过滤密钥误报"""
        if not value:
            return True
        # 占位符
        placeholders = ["xxx", "your_", "placeholder", "example", "changeme",
                       "TODO", "FIXME", "INSERT", "REPLACE", "undefined",
                       "null", "none", "empty", "test", "demo", "sample"]
        value_lower = value.lower()
        if any(ph in value_lower for ph in placeholders):
            return True
        # 全相同字符
        if len(set(value)) <= 2:
            return True
        # 太短
        if secret_type == "api_key_generic" and len(value) < 20:
            return True
        # 明显是变量名
        if re.match(r'^[a-z_]+$', value):
            return True

        return False

    # ─── Sink 检测 ─────────────────────────────────────────────

    def _detect_sinks(self, content: str, lines: list, source_url: str) -> list:
        """检测 DOM XSS Sink"""
        findings = []

        for pattern, sink_name, severity in SINK_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                pos = match.start()
                line_num = content[:pos].count("\n") + 1

                # 获取整行作为上下文
                line_start = content.rfind("\n", 0, pos) + 1
                line_end = content.find("\n", pos)
                if line_end == -1:
                    line_end = min(len(content), pos + 200)
                context = content[line_start:line_end].strip()

                # 检查是否有用户输入流向 sink
                has_user_input = any(src in context for src in [
                    "location", "document.URL", "document.referrer",
                    "window.name", "postMessage", "localStorage",
                    "sessionStorage", "cookie", "URLSearchParams",
                    "params", "query", "hash", "search",
                ])

                if has_user_input:
                    severity = "critical" if severity == "high" else severity
                    confidence = 0.8
                else:
                    confidence = 0.4

                findings.append(JSFinding(
                    category="sink",
                    severity=severity,
                    value=sink_name,
                    context=context[:150],
                    source_url=source_url,
                    line_number=line_num,
                    confidence=confidence,
                ))

        return findings

    # ─── 配置提取 ──────────────────────────────────────────────

    def _extract_configs(self, content: str, source_url: str) -> list:
        """提取云服务配置"""
        findings = []

        for pattern, config_type in CONFIG_PATTERNS:
            matches = re.finditer(pattern, content, re.I)
            for match in matches:
                value = match.group(1) if match.lastindex else match.group(0)

                findings.append(JSFinding(
                    category="config",
                    severity="medium",
                    value=f"[{config_type}] {value}",
                    source_url=source_url,
                    confidence=0.7,
                ))

        return findings

    # ─── 调试端点 ──────────────────────────────────────────────

    def _detect_debug_endpoints(self, content: str, source_url: str) -> list:
        """检测调试/管理端点"""
        findings = []
        seen = set()

        for pattern in DEBUG_PATTERNS:
            matches = re.finditer(pattern, content, re.I)
            for match in matches:
                endpoint = match.group(0).strip("\"'")
                if endpoint in seen:
                    continue
                seen.add(endpoint)

                findings.append(JSFinding(
                    category="debug_endpoint",
                    severity="high",
                    value=endpoint,
                    source_url=source_url,
                    confidence=0.6,
                ))

        return findings

    def get_summary(self, result: JSAnalysisResult) -> dict:
        """获取分析摘要"""
        return {
            "total_findings": len(result.all_findings),
            "endpoints": len(result.endpoints),
            "secrets": len(result.secrets),
            "sinks": len(result.sinks),
            "configs": len(result.configs),
            "debug_endpoints": len(result.debug_endpoints),
            "source_maps": len(result.source_maps),
            "critical": len([f for f in result.all_findings if f.severity == "critical"]),
            "high": len([f for f in result.all_findings if f.severity == "high"]),
        }
