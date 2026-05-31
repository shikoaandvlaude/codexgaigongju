#!/usr/bin/env python3
"""
AuthZ Matrix — 权限矩阵自动生成器

核心思路（顶级猎人工作流）：
  1. 无账号视角：哪些端点公开可访问
  2. 单账号视角：登录后能访问什么
  3. 双账号视角（可选）：A 能不能访问 B 的资源

不需要双账号也能跑（对比登录/未登录的差异就能找到越权）。
有双账号时自动做 IDOR 水平越权检测。

参考项目：AuthMatrix (Burp Extension) / Autorize

用法：
    from authz_matrix import AuthZMatrix
    am = AuthZMatrix(config)

    # 自动生成权限矩阵
    matrix = am.build(target_url, endpoints, cookie_a, cookie_b)

    # 只有单账号
    matrix = am.build_single(target_url, endpoints, cookie)

    # 无账号基线
    baseline = am.build_unauthenticated(target_url, endpoints)
"""

import json, os, re, time, random
from pathlib import Path
from datetime import datetime

try:
    import requests as _req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class AuthZMatrix:
    def __init__(self, config=None):
        self.config = config or {}
        self.output_dir = os.path.expanduser('~/.bai-agent/authz-matrix')
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        self.rate_limit = self.config.get('rate_limit', {}).get('requests_per_second', 2)

    def build(self, base_url, endpoints, cookie_a="", cookie_b=""):
        """完整权限矩阵（三视角）"""
        matrix = []

        for ep in endpoints[:100]:
            url = self._full_url(base_url, ep)
            row = {"endpoint": ep, "url": url, "method": "GET"}

            # 无认证
            row["no_auth"] = self._probe(url, cookie=None)
            self._sleep()

            # 账号 A
            if cookie_a:
                row["auth_a"] = self._probe(url, cookie=cookie_a)
                self._sleep()

            # 账号 B
            if cookie_b:
                row["auth_b"] = self._probe(url, cookie=cookie_b)
                self._sleep()

            # 分析
            row["analysis"] = self._analyze_row(row)
            matrix.append(row)

        result = {
            "target": base_url,
            "endpoints_tested": len(matrix),
            "timestamp": datetime.now().isoformat(),
            "matrix": matrix,
            "findings": self._extract_findings(matrix),
        }

        self._save(base_url, result)
        return result

    def build_single(self, base_url, endpoints, cookie):
        """单账号模式：登录 vs 未登录"""
        return self.build(base_url, endpoints, cookie_a=cookie, cookie_b="")

    def build_unauthenticated(self, base_url, endpoints):
        """无账号基线：哪些端点裸奔"""
        matrix = []
        for ep in endpoints[:100]:
            url = self._full_url(base_url, ep)
            result = self._probe(url, cookie=None)
            if result["status"] == 200 and result["size"] > 50:
                matrix.append({"endpoint": ep, "url": url, "status": result["status"],
                             "size": result["size"], "has_data": result["has_json_data"]})
            self._sleep()

        findings = [row for row in matrix if row.get("has_data")]
        return {
            "target": base_url,
            "total_accessible": len(matrix),
            "with_data": len(findings),
            "endpoints": matrix,
            "unauthenticated_data_endpoints": findings,
        }

    def auto_discover_and_test(self, base_url, cookie_a="", cookie_b=""):
        """全自动：发现端点 → 建矩阵 → 找越权"""
        # 先从常见路径探测
        common_paths = [
            "/api/user", "/api/users", "/api/me", "/api/profile",
            "/api/account", "/api/settings", "/api/config",
            "/api/orders", "/api/billing", "/api/payments",
            "/api/teams", "/api/organizations", "/api/members",
            "/api/files", "/api/uploads", "/api/documents",
            "/api/notifications", "/api/messages", "/api/inbox",
            "/api/keys", "/api/tokens", "/api/webhooks",
            "/api/admin", "/api/admin/users", "/api/admin/config",
            "/api/v1/users", "/api/v2/users", "/api/v3/users",
            "/graphql", "/api/graphql",
            "/user/settings", "/account/billing", "/admin/dashboard",
        ]

        # 探测哪些存在
        alive_endpoints = []
        for path in common_paths:
            url = self._full_url(base_url, path)
            result = self._probe(url, cookie=cookie_a or None)
            if result["status"] not in (404, 000):
                alive_endpoints.append(path)
            self._sleep()

        if not alive_endpoints:
            return {"target": base_url, "message": "未发现活跃API端点", "endpoints": []}

        # 建矩阵
        return self.build(base_url, alive_endpoints, cookie_a, cookie_b)

    def _probe(self, url, cookie=None):
        """发一个请求看状态"""
        if not HAS_REQUESTS:
            return {"status": 0, "size": 0, "has_json_data": False, "error": "no requests"}
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        if cookie:
            headers["Cookie"] = cookie

        try:
            r = _req.get(url, headers=headers, timeout=10, allow_redirects=False, verify=False)
            body = r.text[:2000]
            has_json = False
            try:
                data = r.json()
                # 有实际数据字段 = 有业务数据
                if isinstance(data, dict) and len(data) > 1:
                    has_json = True
                elif isinstance(data, list) and len(data) > 0:
                    has_json = True
            except Exception:
                pass

            return {
                "status": r.status_code,
                "size": len(r.content),
                "has_json_data": has_json,
                "content_type": r.headers.get("Content-Type", ""),
                "sample": body[:200] if r.status_code == 200 else "",
            }
        except Exception as e:
            return {"status": 0, "size": 0, "has_json_data": False, "error": str(e)[:100]}

    def _analyze_row(self, row):
        """分析单行权限差异"""
        no_auth = row.get("no_auth", {})
        auth_a = row.get("auth_a", {})
        auth_b = row.get("auth_b", {})

        issues = []

        # 未登录就能拿到数据 = 信息泄露
        if no_auth.get("status") == 200 and no_auth.get("has_json_data"):
            issues.append({"type": "UNAUTHENTICATED_ACCESS", "severity": "high",
                         "detail": "未登录可访问且有业务数据"})

        # A 登录后能访问，未登录不能 = 正常鉴权
        # A 能访问，B 也能访问且数据相同 = 可能公开
        # A 能访问，B 也能访问但数据不同 = IDOR
        if auth_a.get("status") == 200 and auth_b.get("status") == 200:
            if auth_a.get("size") != auth_b.get("size"):
                issues.append({"type": "POTENTIAL_IDOR", "severity": "high",
                             "detail": "双账号返回不同数据量（B可能看到了A的数据）"})

        # 登录后能访问 admin 路径 = 垂直越权
        ep = row.get("endpoint", "")
        if "admin" in ep.lower() and auth_a.get("status") == 200 and auth_a.get("has_json_data"):
            issues.append({"type": "VERTICAL_PRIVESC", "severity": "critical",
                         "detail": f"普通账号可访问 admin 接口: {ep}"})

        return issues

    def _extract_findings(self, matrix):
        """从矩阵中提取所有安全发现"""
        findings = []
        for row in matrix:
            for issue in row.get("analysis", []):
                findings.append({**issue, "endpoint": row.get("endpoint", ""), "url": row.get("url", "")})
        return findings

    def _full_url(self, base, path):
        base = base.rstrip('/')
        if path.startswith('http'):
            return path
        return f"{base}{path}"

    def _sleep(self):
        interval = 1.0 / self.rate_limit
        jitter = random.uniform(0.3, 1.0)
        time.sleep(interval + jitter)

    def _save(self, target, result):
        domain = re.sub(r'https?://', '', target).replace('/', '_').replace(':', '_')[:40]
        out = os.path.join(self.output_dir, f"{domain}_matrix.json")
        Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
