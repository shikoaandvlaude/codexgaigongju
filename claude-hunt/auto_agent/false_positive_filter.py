"""
False Positive Filter - 误报自动过滤模块
在验证阶段后对漏洞进行二次筛选，自动识别常见误报模式
"""

import hashlib
import json
import re


class FalsePositiveFilter:
    """误报自动过滤器"""
    
    def __init__(self, engine, logger, config: dict):
        self.engine = engine
        self.logger = logger
        self.config = config
        self.fp_config = config.get('false_positive_filter', {})
        self.enabled = self.fp_config.get('enabled', True)
        self.auto_threshold = self.fp_config.get('auto_threshold', 55)
        self.enabled_patterns = self.fp_config.get('patterns', 
            ['idor', 'cors', 'race_condition', 'xss', 'generic',
             'waf_detection', 'baseline_compare', 'public_data_check'])
    
    def filter_vulnerabilities(self, vulns: list) -> list:
        """对每个漏洞应用误报检测规则，添加 confidence 和 fp_reason 字段"""
        if not self.enabled:
            return vulns
        
        for vuln in vulns:
            # Default confidence: 80 (assume likely real)
            vuln.setdefault('confidence', 80)
            vuln['fp_reasons'] = []
            
            vuln_type = vuln.get('type', '').lower()
            detail = vuln.get('detail', '').lower()
            
            # Apply each check
            if 'idor' in self.enabled_patterns:
                self._check_idor_fp(vuln, vuln_type, detail)
            if 'cors' in self.enabled_patterns:
                self._check_cors_fp(vuln, vuln_type, detail)
            if 'race_condition' in self.enabled_patterns:
                self._check_race_condition_fp(vuln, vuln_type, detail)
            if 'xss' in self.enabled_patterns:
                self._check_xss_fp(vuln, vuln_type, detail)
            if 'generic' in self.enabled_patterns:
                self._check_generic_patterns(vuln, vuln_type, detail)
            if 'baseline_compare' in self.enabled_patterns:
                self._check_baseline_compare(vuln, vuln_type, detail)
            if 'waf_detection' in self.enabled_patterns:
                self._check_waf_detection(vuln, vuln_type, detail)
            if 'public_data_check' in self.enabled_patterns:
                self._check_public_data(vuln, vuln_type, detail)
            if 'idor' in self.enabled_patterns:
                self._check_self_idor(vuln, vuln_type, detail)
            self._check_time_delay_stability(vuln, vuln_type, detail)
            
            # Clamp confidence to [0, 100]
            vuln['confidence'] = max(0, min(100, vuln.get('confidence', 80)))

            # Compile fp_reason summary
            if vuln['fp_reasons']:
                vuln['fp_reason'] = '; '.join(vuln['fp_reasons'])
            # Always remove the working list
            vuln.pop('fp_reasons', None)
        
        return vulns
    
    def _check_idor_fp(self, vuln: dict, vuln_type: str, detail: str):
        """IDOR false positive: identical responses from different accounts"""
        if 'idor' not in vuln_type and '越权' not in vuln_type:
            return
        
        # Check for indicators of identical responses
        fp_indicators = [
            '相同', 'identical', 'same response', 'same hash',
            '响应相同', '一致', '都能访问同一资源'
        ]
        
        for indicator in fp_indicators:
            if indicator in detail:
                vuln['confidence'] -= 40
                vuln['fp_reasons'].append(
                    '两账号响应体相同 - 可能是公开接口非个人数据'
                )
                break
    
    def _check_cors_fp(self, vuln: dict, vuln_type: str, detail: str):
        """CORS false positive: only reflects null/specific origins, not arbitrary"""
        if 'cors' not in vuln_type:
            return
        
        # Check if it only reflects specific safe origins
        safe_indicators = [
            'null', 'only reflects null', '只反射null',
            'specific allowed', '特定域名',
            'not arbitrary', '非任意'
        ]
        
        fp_indicators_negative = [
            '任意来源', 'evil.com', 'arbitrary', 'any origin',
            'access-control-allow-origin: *'
        ]
        
        # If detail mentions arbitrary origins, it's likely real
        for real_indicator in fp_indicators_negative:
            if real_indicator in detail:
                return  # Likely real CORS issue
        
        # If none of the "real" indicators found, might be FP
        # Check for safe indicators
        for indicator in safe_indicators:
            if indicator in detail:
                vuln['confidence'] -= 50
                vuln['fp_reasons'].append(
                    'CORS 只反射 null 或特定域名，非任意来源'
                )
                return
        
        # Generic CORS with no detail about reflection - reduce confidence slightly
        if '接受任意来源' not in detail and 'evil.com' not in detail:
            vuln['confidence'] -= 20
            vuln['fp_reasons'].append(
                'CORS 未确认反射任意 Origin，需手动验证'
            )
    
    def _check_race_condition_fp(self, vuln: dict, vuln_type: str, detail: str):
        """Race condition FP: server handled requests correctly with unique IDs"""
        if 'race' not in vuln_type and '竞态' not in vuln_type and '并发' not in vuln_type:
            return
        
        # Check for indicators that server handled correctly
        fp_indicators = [
            '不同的事务id', 'different transaction', 'unique id',
            '唯一编号', '各自独立', 'properly handled',
            '正确处理', '服务端已去重'
        ]
        
        for indicator in fp_indicators:
            if indicator in detail:
                vuln['confidence'] -= 40
                vuln['fp_reasons'].append(
                    '服务端生成了不同事务ID - 正确处理并发'
                )
                return
        
        # If only based on "multiple 200 responses", lower confidence
        if '200' in detail and ('次成功' in detail or 'success' in detail):
            # Multiple 200s alone doesn't confirm race condition
            vuln['confidence'] -= 15
            vuln['fp_reasons'].append(
                '仅基于多个200响应判断，需确认是否真正产生重复效果'
            )
    
    def _check_xss_fp(self, vuln: dict, vuln_type: str, detail: str):
        """XSS false positive: payload in non-executable context"""
        if 'xss' not in vuln_type:
            return
        
        # Non-executable context indicators
        fp_indicators = [
            'html comment', '注释', '<!-- ',
            'properly encoded', '已编码', 'html entity',
            'attribute value', '属性值中',
            'textarea', 'input value',
            'json response', 'content-type: application/json',
            '404 page', '错误页面', 'error page',
            'non-executable', '不可执行'
        ]
        
        for indicator in fp_indicators:
            if indicator in detail:
                vuln['confidence'] -= 50
                vuln['fp_reasons'].append(
                    'Payload 在不可执行上下文中（注释/编码/JSON/错误页）'
                )
                return
    
    def _check_generic_patterns(self, vuln: dict, vuln_type: str, detail: str):
        """Generic FP patterns applicable to any vuln type"""
        generic_fp_indicators = {
            'custom 404': '自定义404页面反射，非真实漏洞',
            '自定义404': '自定义404页面反射，非真实漏洞',
            'error page reflection': '错误页面反射内容，非XSS',
            '错误页面': '错误页面反射内容，非真实漏洞',
            'waf block': 'WAF拦截页面，非真实漏洞',
            'waf拦截': 'WAF拦截页面，非真实漏洞',
            'honeypot': '可能是蜜罐，非真实服务',
            '蜜罐': '可能是蜜罐，非真实服务',
        }
        
        for indicator, reason in generic_fp_indicators.items():
            if indicator in detail:
                vuln['confidence'] -= 30
                vuln['fp_reasons'].append(reason)
                return  # Only apply one generic pattern

    def _stable_hash(self, value) -> str:
        """Return a stable hash for response-like data."""
        if value is None:
            return ""
        if isinstance(value, bytes):
            data = value
        elif isinstance(value, (dict, list, tuple)):
            data = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8", "ignore")
        else:
            data = str(value).encode("utf-8", "ignore")
        return hashlib.sha256(data).hexdigest()

    def _first_value(self, vuln: dict, keys: list):
        for key in keys:
            value = vuln.get(key)
            if value not in (None, ""):
                return value
        return None

    def _response_hash(self, vuln: dict, hash_keys: list, body_keys: list) -> str:
        explicit = self._first_value(vuln, hash_keys)
        if explicit:
            return str(explicit)
        body = self._first_value(vuln, body_keys)
        return self._stable_hash(body) if body is not None else ""

    def _combined_text(self, vuln: dict, detail: str) -> str:
        parts = [detail]
        for key in (
            "response", "response_body", "payload_response", "payload_response_body",
            "body", "evidence", "validation_evidence", "raw_response"
        ):
            value = vuln.get(key)
            if value:
                parts.append(str(value))
        return "\n".join(parts).lower()

    def _check_baseline_compare(self, vuln: dict, vuln_type: str, detail: str):
        """If baseline and payload responses match, the payload likely had no effect."""
        baseline_hash = self._response_hash(
            vuln,
            ["baseline_response_hash", "normal_response_hash", "control_response_hash"],
            ["baseline_response", "baseline_body", "normal_response", "control_response"],
        )
        payload_hash = self._response_hash(
            vuln,
            ["payload_response_hash", "attack_response_hash", "test_response_hash"],
            ["payload_response", "payload_body", "attack_response", "test_response"],
        )
        if baseline_hash and payload_hash and baseline_hash == payload_hash:
            vuln["confidence"] -= 60
            vuln["fp_reasons"].append("baseline and payload responses are identical; payload had no observable effect")

        baseline_status = str(self._first_value(vuln, ["baseline_status", "normal_status"]) or "")
        payload_status = str(self._first_value(vuln, ["payload_status", "attack_status"]) or "")
        baseline_len = self._first_value(vuln, ["baseline_length", "normal_length"])
        payload_len = self._first_value(vuln, ["payload_length", "attack_length"])
        if baseline_status and payload_status and baseline_status == payload_status and baseline_len is not None and payload_len is not None:
            try:
                if abs(int(baseline_len) - int(payload_len)) <= 3:
                    vuln["confidence"] -= 25
                    vuln["fp_reasons"].append("baseline and payload status/length are effectively identical")
            except (TypeError, ValueError):
                pass

    def _check_waf_detection(self, vuln: dict, vuln_type: str, detail: str):
        """WAF/block pages are not exploit evidence by themselves."""
        text = self._combined_text(vuln, detail)
        status = str(self._first_value(vuln, ["status", "status_code", "payload_status", "response_status"]) or "")
        waf_patterns = [
            r"\bwaf\b", r"web application firewall", r"access denied",
            r"request blocked", r"blocked by", r"security policy",
            r"malicious request", r"incident id", r"ray id",
            r"cloudflare", r"akamai", r"imperva", r"captcha",
        ]
        if (status in {"403", "406", "418", "429"} or "blocked" in text) and any(re.search(p, text) for p in waf_patterns):
            vuln["confidence"] -= 50
            vuln["fp_reasons"].append("response looks like WAF/block page, not vulnerability proof")

    def _check_self_idor(self, vuln: dict, vuln_type: str, detail: str):
        """IDOR tested against your own object is not authorization bypass."""
        if "idor" not in vuln_type and "authorization" not in vuln_type and "access control" not in vuln_type:
            return
        requested_id = self._first_value(vuln, ["requested_resource_id", "resource_id", "object_id", "target_user_id"])
        current_id = self._first_value(vuln, ["current_user_id", "tester_user_id", "account_a_id", "owner_id"])
        if requested_id and current_id and str(requested_id) == str(current_id):
            vuln["confidence"] -= 80
            vuln["fp_reasons"].append("IDOR test used the tester's own object/user id")
        if vuln.get("dual_account_tested") is False:
            vuln["confidence"] -= 45
            vuln["fp_reasons"].append("IDOR/authz finding was not tested with two owned accounts")

    def _check_public_data(self, vuln: dict, vuln_type: str, detail: str):
        """Authenticated data that is equally public is not authorization impact."""
        if vuln.get("data_is_public") or vuln.get("no_auth_also_returns_same_data"):
            vuln["confidence"] -= 70
            vuln["fp_reasons"].append("same data is available without authentication")
            return

        auth_hash = self._response_hash(
            vuln,
            ["auth_response_hash", "authenticated_response_hash"],
            ["auth_response", "authenticated_response", "auth_body"],
        )
        no_auth_hash = self._response_hash(
            vuln,
            ["no_auth_response_hash", "anonymous_response_hash"],
            ["no_auth_response", "anonymous_response", "no_auth_body"],
        )
        if auth_hash and no_auth_hash and auth_hash == no_auth_hash:
            vuln["confidence"] -= 70
            vuln["fp_reasons"].append("authenticated and anonymous responses are identical")

    def _check_time_delay_stability(self, vuln: dict, vuln_type: str, detail: str):
        """Time-based findings need stable delay beyond normal jitter."""
        if "time" not in vuln_type and "sqli" not in vuln_type and "blind" not in detail:
            return
        expected = vuln.get("expected_delay")
        observed = vuln.get("time_diff", vuln.get("observed_delay"))
        try:
            expected = float(expected)
            observed = float(observed)
        except (TypeError, ValueError):
            return
        if expected <= 0:
            return
        if not (expected * 0.7 <= observed <= expected * 1.5):
            vuln["confidence"] -= 40
            vuln["fp_reasons"].append("time delay is outside the expected range; likely network jitter or noise")

        samples = vuln.get("time_diffs") or vuln.get("delay_samples") or []
        if isinstance(samples, list) and len(samples) >= 3:
            try:
                values = [float(v) for v in samples]
                if max(values) - min(values) > expected:
                    vuln["confidence"] -= 25
                    vuln["fp_reasons"].append("time delay samples are unstable")
            except (TypeError, ValueError):
                pass
    
    def apply_filter(self, vulns: list, mode: str) -> list:
        """
        Apply filter and return cleaned vulnerability list.
        - auto mode: remove vulns below threshold, log reason
        - semi mode: show suspected FPs and ask user for confirmation
        """
        if not self.enabled or not vulns:
            return vulns
        
        # First, score all vulns
        self.filter_vulnerabilities(vulns)
        
        # Split into likely real and suspected FP
        likely_real = []
        suspected_fp = []
        
        for vuln in vulns:
            if vuln.get('confidence', 80) < self.auto_threshold:
                suspected_fp.append(vuln)
            else:
                likely_real.append(vuln)
        
        if not suspected_fp:
            return vulns
        
        # Log the filtering
        self.logger.log_event("FINDING", 
            f"误报过滤: {len(suspected_fp)} 个可疑误报 (confidence < {self.auto_threshold})")
        
        if mode == "auto":
            # Auto mode: filter out low confidence, log reason
            for vuln in suspected_fp:
                self.logger.log_event("SKIP", 
                    f"自动过滤误报: {vuln.get('type')} @ {vuln.get('url', '?')} "
                    f"[confidence={vuln.get('confidence')}] 原因: {vuln.get('fp_reason', '未知')}")
            return likely_real
        
        elif mode == "semi":
            # Semi mode: show user and ask
            try:
                from rich.console import Console
                from rich.table import Table
                from rich.prompt import Confirm
                console = Console()
                
                console.print(f"\n[bold yellow]⚠ 误报过滤器发现 {len(suspected_fp)} 个可疑误报:[/bold yellow]\n")
                
                table = Table(title="可疑误报列表")
                table.add_column("序号", style="dim")
                table.add_column("类型", style="cyan")
                table.add_column("URL", style="blue")
                table.add_column("可信度", style="red")
                table.add_column("原因", style="yellow")
                
                for i, vuln in enumerate(suspected_fp, 1):
                    table.add_row(
                        str(i),
                        vuln.get('type', '?'),
                        vuln.get('url', '?')[:50],
                        str(vuln.get('confidence', '?')),
                        vuln.get('fp_reason', '未知')[:60]
                    )
                
                console.print(table)
                
                if Confirm.ask("\n移除这些可疑误报？", default=True):
                    return likely_real
                else:
                    return vulns  # Keep all
                    
            except ImportError:
                # Fallback without Rich
                print(f"\n警告: {len(suspected_fp)} 个可疑误报")
                for vuln in suspected_fp:
                    print(f"  - {vuln.get('type')} @ {vuln.get('url', '?')} "
                          f"[confidence={vuln.get('confidence')}]")
                resp = input("移除这些可疑误报？(y/n): ")
                if resp.lower() == 'y':
                    return likely_real
                return vulns
        
        return vulns
