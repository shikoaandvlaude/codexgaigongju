#!/usr/bin/env python3
"""
JS 敏感信息提取工具

用途：从目标网站的 JavaScript 文件中自动提取 API 端点、密钥、Token、内部URL等敏感信息。

使用方式：
  # 扫描单个JS文件URL
  python3 js_extractor.py --url "https://target.com/static/app.js"

  # 扫描多个JS URL（从文件加载）
  python3 js_extractor.py --url-file js_urls.txt

  # 扫描本地JS文件
  python3 js_extractor.py --file ./downloaded_app.js

  # 从网站首页自动发现并扫描所有JS
  python3 js_extractor.py --crawl "https://target.com"

  # 只提取API端点
  python3 js_extractor.py --url "https://target.com/app.js" --only endpoints

  # 只提取密钥/凭证
  python3 js_extractor.py --url "https://target.com/app.js" --only secrets

注意事项：
  - 不需要发攻击请求，只是分析JS内容
  - 属于被动信息搜集，风险低
  - 发现的API端点可以作为后续测试的目标
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime
from urllib.parse import urlparse, urljoin


# ── 正则模式定义 ──────────────────────────────────────────────────────────

# API 端点
ENDPOINT_PATTERNS = [
    # 绝对路径API
    re.compile(r'["\'](/api/[a-zA-Z0-9_/\-{}.]+)["\']'),
    re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-{}.]+)["\']'),
    re.compile(r'["\'](/rest/[a-zA-Z0-9_/\-{}.]+)["\']'),
    re.compile(r'["\'](/graphql[a-zA-Z0-9_/\-]*)["\']'),
    # 相对路径
    re.compile(r'["\']([a-zA-Z0-9_]+/[a-zA-Z0-9_/\-{}.]+)["\']'),
    # 完整URL
    re.compile(r'["\'](https?://[a-zA-Z0-9.\-]+/[a-zA-Z0-9_/\-{}.?&=]+)["\']'),
    # fetch/axios 调用
    re.compile(r'(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']'),
    # 模板字符串
    re.compile(r'`((?:https?://|/)[^`]*\$\{[^}]+\}[^`]*)`'),
]

# 密钥和敏感信息
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    "AWS Secret Key": re.compile(r'(?:aws_secret|AWS_SECRET)[_a-zA-Z]*[\s:="\']+([a-zA-Z0-9/+=]{40})'),
    "API Key (generic)": re.compile(r'(?:api[_-]?key|apikey|API_KEY)[\s:="\']+["\']?([a-zA-Z0-9_\-]{16,64})["\']?'),
    "Secret Key (generic)": re.compile(r'(?:secret[_-]?key|SECRET_KEY|client_secret)[\s:="\']+["\']?([a-zA-Z0-9_\-]{16,64})["\']?'),
    "Access Token": re.compile(r'(?:access[_-]?token|ACCESS_TOKEN)[\s:="\']+["\']?([a-zA-Z0-9_\-\.]{16,200})["\']?'),
    "Bearer Token": re.compile(r'Bearer\s+([a-zA-Z0-9_\-\.]{20,})'),
    "JWT Token": re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
    "Private Key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "Google API Key": re.compile(r'AIza[a-zA-Z0-9_\-]{35}'),
    "Google OAuth": re.compile(r'[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com'),
    "GitHub Token": re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}'),
    "Slack Token": re.compile(r'xox[baprs]-[a-zA-Z0-9\-]+'),
    "Stripe Key": re.compile(r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}'),
    "Twilio": re.compile(r'SK[a-f0-9]{32}'),
    "SendGrid": re.compile(r'SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,}'),
    "Mailgun": re.compile(r'key-[a-f0-9]{32}'),
    "Heroku API Key": re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    "Password in Code": re.compile(r'(?:password|passwd|pwd)[\s]*[=:]\s*["\']([^"\']{4,30})["\']', re.IGNORECASE),
    "Database URL": re.compile(r'(?:mysql|postgres|mongodb|redis)://[^\s"\'<>]+'),
    "Internal IP": re.compile(r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'),
    "WeChat AppID": re.compile(r'wx[a-f0-9]{16}'),
    "Aliyun AccessKey": re.compile(r'LTAI[a-zA-Z0-9]{12,20}'),
    "Phone Number (CN)": re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)'),
    "Email": re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}'),
    "ID Card (CN)": re.compile(r'(?<!\d)\d{17}[\dXx](?!\d)'),
}

# 敏感路径/配置
SENSITIVE_PATH_PATTERNS = [
    re.compile(r'["\'](/admin[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\'](/debug[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\'](/test[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\'](/backup[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\'](/config[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\'](/internal[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\'](/swagger[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\'](/actuator[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'["\']([a-zA-Z0-9_/\-]*\.(?:env|config|yml|yaml|xml|sql|bak|log|tmp))["\']'),
]


class JSExtractor:
    """JS 敏感信息提取器"""

    def __init__(self):
        self.findings = {
            "endpoints": [],
            "secrets": [],
            "sensitive_paths": [],
            "domains": [],
        }

    def fetch_js(self, url, timeout=15):
        """获取JS文件内容"""
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            print(f"  [!] 获取失败: {url} ({e})")
            return None

    def crawl_js_urls(self, base_url, timeout=15):
        """从网页中发现所有JS文件URL"""
        content = self.fetch_js(base_url, timeout)
        if not content:
            return []

        js_urls = set()
        # 匹配 <script src="...">
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', content, re.IGNORECASE):
            src = match.group(1)
            full_url = urljoin(base_url, src)
            js_urls.add(full_url)

        # 匹配 JS import
        for match in re.finditer(r'(?:import|from)\s+["\']([^"\']+\.js)["\']', content):
            src = match.group(1)
            full_url = urljoin(base_url, src)
            js_urls.add(full_url)

        return list(js_urls)

    def extract_from_content(self, content, source="unknown"):
        """从JS内容中提取敏感信息"""
        results = {
            "source": source,
            "endpoints": [],
            "secrets": [],
            "sensitive_paths": [],
            "domains": []
        }

        # 提取 API 端点
        seen_endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip("\"' ")
                # 过滤噪音
                if len(endpoint) < 4 or len(endpoint) > 200:
                    continue
                if endpoint in seen_endpoints:
                    continue
                if any(skip in endpoint.lower() for skip in [
                    ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff",
                    "node_modules", "webpack", "chunk", ".map"
                ]):
                    continue
                seen_endpoints.add(endpoint)
                results["endpoints"].append(endpoint)

        # 提取密钥/敏感信息
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                # 过滤明显的占位符
                if value in ("your-api-key", "xxx", "placeholder", "example"):
                    continue
                if len(value) < 6:
                    continue
                results["secrets"].append({
                    "type": secret_type,
                    "value": value[:80] + ("..." if len(value) > 80 else ""),
                    "context": content[max(0, match.start()-30):match.end()+30].strip()[:120]
                })

        # 提取敏感路径
        seen_paths = set()
        for pattern in SENSITIVE_PATH_PATTERNS:
            for match in pattern.finditer(content):
                path = match.group(1)
                if path not in seen_paths and len(path) > 3:
                    seen_paths.add(path)
                    results["sensitive_paths"].append(path)

        # 提取域名
        domain_pattern = re.compile(r'https?://([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})')
        seen_domains = set()
        for match in domain_pattern.finditer(content):
            domain = match.group(1)
            if domain not in seen_domains and not any(skip in domain for skip in [
                "googleapis.com", "gstatic.com", "cloudflare.com",
                "jsdelivr.net", "unpkg.com", "cdnjs.com", "w3.org"
            ]):
                seen_domains.add(domain)
                results["domains"].append(domain)

        return results

    def analyze_url(self, url):
        """分析单个JS URL"""
        print(f"  [*] 分析: {url}")
        content = self.fetch_js(url)
        if not content:
            return None

        result = self.extract_from_content(content, source=url)

        # 汇总
        self.findings["endpoints"].extend(result["endpoints"])
        self.findings["secrets"].extend(result["secrets"])
        self.findings["sensitive_paths"].extend(result["sensitive_paths"])
        self.findings["domains"].extend(result["domains"])

        # 打印摘要
        counts = f"端点:{len(result['endpoints'])} 密钥:{len(result['secrets'])} 路径:{len(result['sensitive_paths'])} 域名:{len(result['domains'])}"
        if result["secrets"]:
            print(f"  [!] {counts} ← 发现敏感信息!")
        else:
            print(f"  [+] {counts}")

        return result

    def analyze_file(self, filepath):
        """分析本地JS文件"""
        print(f"  [*] 分析本地文件: {filepath}")
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            print(f"  [!] 读取失败: {e}")
            return None

        return self.extract_from_content(content, source=filepath)

    def print_summary(self):
        """打印总结"""
        # 去重
        endpoints = sorted(set(self.findings["endpoints"]))
        secrets = self.findings["secrets"]
        paths = sorted(set(self.findings["sensitive_paths"]))
        domains = sorted(set(self.findings["domains"]))

        print(f"\n{'='*60}")
        print(f"  JS 分析总结")
        print(f"{'='*60}\n")

        if endpoints:
            print(f"  [API 端点] ({len(endpoints)} 个)")
            for ep in endpoints[:30]:
                print(f"    {ep}")
            if len(endpoints) > 30:
                print(f"    ... 还有 {len(endpoints)-30} 个")
            print()

        if secrets:
            print(f"  [敏感信息] ({len(secrets)} 个) ← 重点关注!")
            for s in secrets[:20]:
                print(f"    [{s['type']}] {s['value']}")
            if len(secrets) > 20:
                print(f"    ... 还有 {len(secrets)-20} 个")
            print()

        if paths:
            print(f"  [敏感路径] ({len(paths)} 个)")
            for p in paths[:20]:
                print(f"    {p}")
            print()

        if domains:
            print(f"  [关联域名] ({len(domains)} 个)")
            for d in domains[:20]:
                print(f"    {d}")
            print()

        total = len(endpoints) + len(secrets) + len(paths) + len(domains)
        if total == 0:
            print("  [✓] 未发现敏感信息")
        else:
            print(f"  共发现: {len(endpoints)} 端点, {len(secrets)} 密钥, {len(paths)} 敏感路径, {len(domains)} 域名")

        print(f"\n{'='*60}\n")

        return {
            "endpoints": endpoints,
            "secrets": secrets,
            "sensitive_paths": paths,
            "domains": domains
        }


def main():
    parser = argparse.ArgumentParser(description="JS 敏感信息提取工具")
    parser.add_argument("--url", help="JS文件URL")
    parser.add_argument("--url-file", help="JS URL列表文件（每行一个）")
    parser.add_argument("--file", help="本地JS文件路径")
    parser.add_argument("--crawl", help="从网页自动发现并分析所有JS")
    parser.add_argument("--only", choices=["endpoints", "secrets", "paths", "domains"], help="只提取指定类型")
    parser.add_argument("--output", help="输出JSON文件")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时秒数")

    args = parser.parse_args()

    if not any([args.url, args.url_file, args.file, args.crawl]):
        parser.error("需要 --url, --url-file, --file 或 --crawl")

    extractor = JSExtractor()

    print(f"\n{'='*60}")
    print(f"  JS Extractor — 敏感信息提取")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    # 获取要分析的 JS 列表
    js_targets = []

    if args.crawl:
        print(f"[*] 从 {args.crawl} 爬取JS文件...")
        js_targets = extractor.crawl_js_urls(args.crawl, args.timeout)
        print(f"[+] 发现 {len(js_targets)} 个JS文件")

    if args.url:
        js_targets.append(args.url)

    if args.url_file:
        with open(args.url_file, "r") as f:
            js_targets.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])

    # 分析远程JS
    for url in js_targets:
        extractor.analyze_url(url)

    # 分析本地文件
    if args.file:
        extractor.analyze_file(args.file)

    # 总结
    summary = extractor.print_summary()

    # 过滤输出
    if args.only:
        summary = {args.only: summary.get(args.only, [])}

    # 保存
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(f"[+] 结果已保存: {args.output}")

    # 如果发现密钥，退出码1
    has_secrets = len(extractor.findings["secrets"]) > 0
    sys.exit(1 if has_secrets else 0)


if __name__ == "__main__":
    main()
