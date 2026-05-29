#!/usr/bin/env python3
"""
Bounty Rejection Filter — 赏金平台不收的漏洞类型自动标注

核心目的：防止工具在"不收的方向"上浪费 token 和时间。
在扫描阶段就标注"这个发现大概率不会被接受"，避免跑邪路。
"""

ALWAYS_REJECTED = {
    "missing_security_headers": "缺少安全响应头 — 所有平台都不收",
    "missing_cookie_flags": "Cookie 缺少 HttpOnly/Secure/SameSite — 不收",
    "version_disclosure": "服务器/框架版本泄露 — 不收",
    "banner_disclosure": "Banner 信息泄露 — 不收",
    "server_header": "Server 响应头泄露版本 — 不收",
    "x_powered_by": "X-Powered-By 泄露技术栈 — 不收",
    "directory_listing": "目录列表（除非含密钥文件）— 通常不收",
    "source_map": "Source Map 暴露（除非含硬编码密钥）— 不收",
    "clickjacking": "Clickjacking — 通常不收",
    "tabnabbing": "Tabnabbing — 不收",
    "open_redirect_standalone": "开放重定向单独不收，需链式利用",
    "self_xss": "Self-XSS — 不收",
    "logout_csrf": "注销 CSRF — 不收",
    "login_csrf": "登录 CSRF — 大多不收",
    "rate_limit_noncritical": "非关键接口限速缺失 — 不收",
    "email_enumeration": "用户名/邮箱枚举 — 大多不收",
    "cors_null_origin": "CORS 只接受 null origin — 不收",
    "cors_no_credentials": "CORS 错配但无 credentials — 不收",
    "ssl_weak_cipher": "弱 SSL 密码套件 — 不收",
    "graphql_introspection": "GraphQL Introspection 单独不收",
    "swagger_exposed": "Swagger/API 文档暴露单独不收",
    "robots_txt": "robots.txt 泄露路径 — 不收",
    "dns_misconfiguration": "DNS 记录配置问题 — 不收",
    "spf_dmarc_missing": "缺少 SPF/DMARC — 不收",
    "autocomplete_on": "表单 autocomplete 未关闭 — 不收",
    "http_method_enabled": "OPTIONS/TRACE 方法开启 — 不收",
}

CONDITIONAL_REJECTED = {
    "open_redirect": {"reason": "单独不收", "valid_when": "链接到 OAuth token 窃取"},
    "ssrf_dns_only": {"reason": "仅 DNS 回调不收", "valid_when": "能读内网响应或云 metadata"},
    "idor_public_data": {"reason": "公开数据不算 IDOR", "valid_when": "能访问私人数据"},
    "xss_non_sensitive": {"reason": "无敏感页面的 XSS 降级", "valid_when": "能窃取 cookie 或在管理面板触发"},
    "race_condition": {"reason": "需要实际重复效果", "valid_when": "证明资金/积分重复领取"},
}


# ═══════════════════════════════════════════════════════════
# 国内 SRC 平台规则（补天/漏洞盒子/厂商 SRC）
# 比 H1 宽松很多，但也有自己的不收清单
# ═══════════════════════════════════════════════════════════

CN_SRC_ALWAYS_REJECTED = {
    "self_xss": "Self-XSS — 国内也不收",
    "logout_csrf": "注销 CSRF — 不收",
    "autocomplete_on": "表单 autocomplete — 不收",
    "http_method_enabled": "OPTIONS/TRACE — 不收",
    "dns_misconfiguration": "DNS 配置问题 — 不收",
    "robots_txt": "robots.txt — 不收",
    "spf_dmarc_missing": "SPF/DMARC — 不收",
    "tabnabbing": "Tabnabbing — 不收",
    "ssl_weak_cipher": "弱 SSL — 大多不收",
}

CN_SRC_ACCEPTED = {
    # 这些在 HackerOne 不收但国内收！
    "information_disclosure": "✓ 国内收！敏感信息泄露（手机号/身份证/内部数据）= 中高危",
    "weak_password": "✓ 国内收！后台弱口令 = 高危",
    "default_credentials": "✓ 国内收！默认密码 = 高危",
    "directory_listing": "✓ 国内收（如含敏感文件）= 低中危",
    "swagger_exposed": "✓ 国内可收！API 文档暴露 = 低危",
    "graphql_introspection": "✓ 国内可收！= 低危",
    "sms_bombing": "✓ 国内收！短信轰炸/验证码绕过 = 中危",
    "captcha_bypass": "✓ 国内收！验证码绕过 = 中危",
    "unauthorized_access": "✓ 国内重点！未授权访问 = 高危",
    "user_enumeration": "✓ 国内可收！用户枚举 = 低危",
    "open_redirect": "✓ 国内单独可收 = 低危",
    "cors_misconfiguration": "✓ 国内可收（有证据）= 低中危",
    "ssrf_dns_only": "✓ 国内 DNS 回调也可收 = 低危",
    "rate_limit": "✓ 国内可收！限速缺失 = 低中危（特别是登录/支付）",
    "version_disclosure": "⚠ 看厂商，部分收低危",
    "backup_file": "✓ 国内收！备份文件暴露 = 中高危",
}

# 国内 SRC 特有的高价值漏洞方向
CN_SRC_HIGH_VALUE = [
    "未授权访问后台",
    "越权（水平/垂直）",
    "SQL 注入",
    "任意文件读取/下载",
    "命令执行/代码执行",
    "后台弱口令（admin/admin123/123456）",
    "敏感信息泄露（手机号/身份证/密码明文）",
    "支付金额篡改/0元购",
    "短信验证码绕过（万能码/爆破/重放）",
    "任意密码重置",
    "SSRF（能打内网或读文件）",
    "文件上传 getshell",
    "批量数据泄露（翻页/导出无限制）",
]


class BountyRejectionFilter:
    def __init__(self, platform="hackerone"):
        """
        platform: "hackerone" | "cn_src" | "bugcrowd"
        国内 SRC 用 "cn_src"，会使用更宽松的过滤规则。
        """
        self.platform = platform

    def check(self, finding: dict) -> dict:
        vuln_type = self._normalize_type(finding)
        detail = (finding.get("detail", "") + " " + finding.get("type", "")).lower()

        # 国内 SRC 用不同规则
        if self.platform == "cn_src":
            return self._check_cn_src(finding, vuln_type, detail)

        # HackerOne / Bugcrowd 标准
        for key, reason in ALWAYS_REJECTED.items():
            if key in vuln_type or self._kw_match(key, detail):
                return {"rejected": True, "reason": reason, "category": "always_rejected", "advice": "不要提交，换方向。"}

        for key, info in CONDITIONAL_REJECTED.items():
            if key in vuln_type or self._kw_match(key, detail):
                return {"rejected": False, "reason": info["reason"], "category": "conditional",
                        "advice": f"需满足: {info['valid_when']}"}

        info_kw = ["information disclosure", "信息泄露", "版本", "version", "banner", "fingerprint", "header missing"]
        if any(kw in detail for kw in info_kw):
            secret_kw = ["api_key", "secret", "private_key", "password", "token", "credential", "aws_"]
            if not any(sk in detail for sk in secret_kw):
                return {"rejected": True, "reason": "纯信息泄露（非密钥）不收", "category": "always_rejected", "advice": "除非是可验证的密钥/密码。"}

        return {"rejected": False, "reason": "", "category": "acceptable", "advice": ""}

    def _check_cn_src(self, finding: dict, vuln_type: str, detail: str) -> dict:
        """国内 SRC 过滤规则 — 比 H1 宽松得多"""
        # 国内也不收的
        for key, reason in CN_SRC_ALWAYS_REJECTED.items():
            if key in vuln_type or self._kw_match(key, detail):
                return {"rejected": True, "reason": reason, "category": "always_rejected", "advice": "国内也不收。"}

        # 国内明确收的（在 H1 会被过滤但国内不过滤）
        for key, note in CN_SRC_ACCEPTED.items():
            if key in vuln_type or self._kw_match(key, detail):
                return {"rejected": False, "reason": note, "category": "cn_src_accepted",
                        "advice": "国内可提交，注意提供证据截图。"}

        return {"rejected": False, "reason": "", "category": "acceptable", "advice": ""}

    def filter_findings(self, findings: list) -> tuple:
        kept, rejected = [], []
        for f in findings:
            r = self.check(f)
            f["bounty_rejection"] = r
            if r["rejected"]:
                rejected.append(f)
            else:
                if r["category"] == "conditional":
                    f["bounty_warning"] = r["advice"]
                kept.append(f)
        return kept, rejected

    def get_focus_guide(self) -> str:
        if self.platform == "cn_src":
            return """=== 国内 SRC 赏金指南 ===
【不收的（国内也不收）】
✗ Self-XSS / 注销CSRF / autocomplete / OPTIONS暴露

【国内特色（H1不收但国内收）】
✓ 后台弱口令（admin/123456）→ 高危！
✓ 短信轰炸/验证码绕过 → 中危
✓ 敏感信息泄露（手机号/身份证/密码明文）→ 中高危
✓ 未授权访问任何后台 → 高危！
✓ Swagger/API 文档暴露 → 低危
✓ 目录遍历+敏感文件 → 中危
✓ 任意用户注册/枚举 → 低危
✓ 开放重定向（单独）→ 低危
✓ CORS 错配 → 低危
✓ SSRF DNS 回调 → 低危

【出赏金最高的方向（国内SRC）】
★ 越权（最值钱）：水平/垂直越权，改ID看别人数据
★ SQL 注入：证明可以拖库
★ 未授权后台：找到管理后台+弱口令
★ 任意文件读取/下载
★ 命令执行/RCE
★ 支付逻辑：0元购/金额篡改
★ 短信验证码绕过
★ 批量数据泄露：翻页无限制/导出全表
★ 任意密码重置
=== 指南结束 ==="""
        else:
            return """=== 赏金收/不收指南 (HackerOne) ===
【不要浪费时间】
✗ 缺安全头/版本泄露/目录列表/Source Map/Clickjacking/Self-XSS
✗ 注销CSRF/登录CSRF/限速缺失/用户名枚举/CORS无credentials
✗ SSL弱配置/GraphQL introspection单独/Swagger暴露/robots.txt

【条件性（需额外证明）】
⚠ SSRF → 必须读到内网响应或 metadata
⚠ IDOR → 必须是私人数据
⚠ XSS → 最好敏感页面+窃取cookie
⚠ 开放重定向 → 链接到OAuth窃取
⚠ 竞态 → 证明重复执行了

【优先挖这些（出赏金率最高）】
✓ IDOR（30% H1 赏金）  ✓ SQLi  ✓ SSRF+metadata
✓ RCE  ✓ 认证绕过  ✓ 硬编码可验证密钥
✓ JWT alg:none  ✓ 支付竞态  ✓ 子域名接管
=== 指南结束 ==="""

    def _normalize_type(self, f):
        return (f.get("type", "") + " " + f.get("vuln_type", "") + " " + f.get("title", "")).lower().replace("-", "_").replace(" ", "_")

    def _kw_match(self, key, text):
        return all(p in text for p in key.replace("_", " ").split())
