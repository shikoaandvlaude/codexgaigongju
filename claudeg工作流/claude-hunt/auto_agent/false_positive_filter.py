"""
False Positive Filter - 误报自动过滤模块
在验证阶段后对漏洞进行二次筛选，自动识别常见误报模式
"""


class FalsePositiveFilter:
    """误报自动过滤器"""
    
    def __init__(self, engine, logger, config: dict):
        self.engine = engine
        self.logger = logger
        self.config = config
        self.fp_config = config.get('false_positive_filter', {})
        self.enabled = self.fp_config.get('enabled', True)
        self.auto_threshold = self.fp_config.get('auto_threshold', 30)
        self.enabled_patterns = self.fp_config.get('patterns', 
            ['idor', 'cors', 'race_condition', 'xss', 'generic'])
    
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
