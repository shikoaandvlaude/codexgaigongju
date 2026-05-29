"""
Redline Checker — 红线审查模块
每N步自动检查是否越界、流量是否过大、是否触碰禁区
"""


class RedlineChecker:
    """SRC 红线审查器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.redline_config = config.get('redline', {})
        self.request_history = []  # 记录最近的请求状态码
        self.warnings = []
    
    def check(self, findings: dict, step_count: int) -> dict:
        """
        执行红线检查
        返回: {"stop": bool, "reason": str, "warnings": list}
        """
        result = {"stop": False, "reason": "", "warnings": []}
        
        # 1. 检查连续 403
        max_403 = self.redline_config.get('max_403_consecutive', 5)
        consecutive_403 = 0
        for code in reversed(self.request_history[-20:]):
            if code == 403:
                consecutive_403 += 1
            else:
                break
        
        if consecutive_403 >= max_403:
            result["stop"] = True
            result["reason"] = f"连续 {consecutive_403} 个 403 响应，可能已被 WAF 拦截"
            return result
        
        # 2. 检查 404 比例
        max_404_ratio = self.redline_config.get('max_404_ratio', 0.8)
        recent = self.request_history[-50:]
        if len(recent) > 10:
            ratio_404 = recent.count(404) / len(recent)
            if ratio_404 > max_404_ratio:
                result["warnings"].append(f"404比例过高: {ratio_404:.0%}")
                if ratio_404 > 0.95:
                    result["stop"] = True
                    result["reason"] = f"404比例达到 {ratio_404:.0%}，目标可能已封禁或路径全错"
                    return result
        
        # 3. 检查发现中是否有越界行为
        vulns = findings.get('vulnerabilities', [])
        for v in vulns:
            url = v.get('url', '')
            # 检查是否碰了禁止路径
            forbidden_paths = self.redline_config.get('forbidden_paths', [])
            for fp in forbidden_paths:
                if fp in url:
                    result["stop"] = True
                    result["reason"] = f"触碰禁止路径: {fp}"
                    return result
        
        # 4. 检查总请求数
        max_requests = self.config.get('rate_limit', {}).get('max_total_requests', 500)
        total = len(self.request_history)
        if total > max_requests * 0.8:
            result["warnings"].append(f"请求数接近上限: {total}/{max_requests}")
        if total >= max_requests:
            result["stop"] = True
            result["reason"] = f"已达最大请求数上限 {max_requests}"
            return result
        
        return result
    
    def record_response(self, status_code: int, response_text: str = ""):
        """记录一次响应"""
        self.request_history.append(status_code)
        
        # 检查响应中的禁止关键词
        forbidden_keywords = self.redline_config.get('forbidden_keywords', [])
        for kw in forbidden_keywords:
            if kw in response_text:
                self.warnings.append(f"响应中出现禁止关键词: '{kw}'")
    
    def check_scope(self, url: str, scope: list, out_of_scope: list) -> bool:
        """检查 URL 是否在授权范围内"""
        from urllib.parse import urlparse
        import fnmatch
        
        parsed = urlparse(url)
        host = parsed.hostname or ""
        
        # 检查是否在 out_of_scope
        for pattern in out_of_scope:
            if fnmatch.fnmatch(host, pattern):
                return False
        
        # 检查是否在 scope
        if not scope:
            return True  # 没定义scope就默认允许
        
        for pattern in scope:
            if fnmatch.fnmatch(host, pattern):
                return True
        
        return False
    
    def get_summary(self) -> str:
        """获取审查摘要"""
        total = len(self.request_history)
        if total == 0:
            return "暂无请求记录"
        
        code_counts = {}
        for code in self.request_history:
            code_counts[code] = code_counts.get(code, 0) + 1
        
        parts = [f"总请求: {total}"]
        for code, count in sorted(code_counts.items()):
            parts.append(f"{code}: {count}")
        
        return " | ".join(parts)
