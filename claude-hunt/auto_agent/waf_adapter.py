"""
WAF Adapter — WAF 指纹自适应模块
检测目标 WAF 类型，动态调整限速/UA/请求方式
"""

import random


# 常见 WAF 指纹 → 对应策略
WAF_STRATEGIES = {
    "cloudflare": {
        "name": "Cloudflare",
        "requests_per_second": 1,
        "use_browser": True,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "extra_headers": {"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"},
        "tips": "Cloudflare检测严格，建议用浏览器模式(playwright)绕过JS验证",
    },
    "aliyun": {
        "name": "阿里云WAF",
        "requests_per_second": 1,
        "use_browser": False,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "extra_headers": {"Accept": "text/html,application/xhtml+xml"},
        "tips": "阿里云WAF对频率敏感，必须带正常Cookie，建议登录后测试",
    },
    "baota": {
        "name": "宝塔WAF",
        "requests_per_second": 2,
        "use_browser": False,
        "user_agent": "Mozilla/5.0 (compatible; Baiduspider/2.0)",
        "extra_headers": {},
        "tips": "宝塔WAF规则较弱，可尝试路径大小写绕过(/Admin vs /admin)",
    },
    "tencent": {
        "name": "腾讯云WAF",
        "requests_per_second": 1,
        "use_browser": False,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "extra_headers": {},
        "tips": "腾讯云WAF对SQL注入检测严格，payload需编码绕过",
    },
    "unknown": {
        "name": "未知/无WAF",
        "requests_per_second": 5,
        "use_browser": False,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "extra_headers": {},
        "tips": "未检测到WAF，可以稍微快一点，但仍然注意限速",
    },
}

# 随机 UA 池
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]


class WAFAdapter:
    """WAF 自适应器"""

    def __init__(self, engine, logger):
        self.engine = engine
        self.logger = logger
        self.detected_waf = "unknown"
        self.strategy = WAF_STRATEGIES["unknown"]

    def detect(self, target: str) -> dict:
        """检测目标的 WAF 类型"""
        self.logger.log_event("FINDING", f"正在检测 {target} 的 WAF...")

        # 用 wafw00f 检测
        result = self.engine.execute_command(f"wafw00f {target} 2>/dev/null | tail -5")

        waf_type = "unknown"
        if result["success"] and result["output"]:
            output_lower = result["output"].lower()
            if "cloudflare" in output_lower:
                waf_type = "cloudflare"
            elif "alibaba" in output_lower or "aliyun" in output_lower:
                waf_type = "aliyun"
            elif "tencent" in output_lower:
                waf_type = "tencent"
            elif "baota" in output_lower or "bt.cn" in output_lower:
                waf_type = "baota"
            elif "no waf" in output_lower or "not detected" in output_lower:
                waf_type = "unknown"

        self.detected_waf = waf_type
        self.strategy = WAF_STRATEGIES.get(waf_type, WAF_STRATEGIES["unknown"])

        self.logger.log_event("FINDING",
            f"WAF检测结果: {self.strategy['name']} → 限速调整为 {self.strategy['requests_per_second']} req/s")

        return {
            "waf_type": waf_type,
            "strategy": self.strategy,
            "tips": self.strategy["tips"],
        }

    def get_rate_limit(self) -> float:
        """获取当前建议的限速"""
        return self.strategy["requests_per_second"]

    def get_user_agent(self) -> str:
        """获取随机 UA（从池中选）"""
        return random.choice(UA_POOL)

    def get_extra_headers(self) -> dict:
        """获取额外请求头"""
        headers = dict(self.strategy.get("extra_headers", {}))
        headers["User-Agent"] = self.get_user_agent()
        return headers

    def should_use_browser(self) -> bool:
        """是否应该用浏览器模式"""
        return self.strategy.get("use_browser", False)

    def adapt_command(self, command: str) -> str:
        """根据 WAF 策略调整命令参数"""
        rate = self.strategy["requests_per_second"]

        # 自动给工具加限速
        if "nuclei" in command and "-rate-limit" not in command:
            command += f" -rate-limit {rate} -c {max(1, rate)}"
        elif "httpx" in command and "-rate-limit" not in command:
            command += f" -rate-limit {rate * 2} -threads {max(1, rate)}"
        elif "ffuf" in command and "-rate" not in command:
            command += f" -rate {rate} -t {max(1, rate)}"
        elif "dalfox" in command and "--delay" not in command:
            delay_ms = int(1000 / rate) if rate > 0 else 1000
            command += f" --delay {delay_ms}"
        elif "katana" in command and "-delay" not in command:
            command += f" -delay {max(1, int(1/rate))} -c {max(1, rate)}"

        return command
