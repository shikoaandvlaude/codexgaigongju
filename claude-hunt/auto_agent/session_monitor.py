"""
Session Monitor — 账号状态监控模块
每N步检查 Session 是否仍然有效（未被踢/未触发风控）
"""

import time


class SessionMonitor:
    """账号状态监控器"""

    def __init__(self, engine, logger, config: dict):
        self.engine = engine
        self.logger = logger
        self.config = config
        self.session_config = config.get("session_monitor", {})
        self.check_url = self.session_config.get("check_url", "")
        self.cookie = self.session_config.get("cookie", "")
        self.expected_keyword = self.session_config.get("expected_keyword", "")
        self.check_interval = self.session_config.get("check_interval", 10)
        self.last_check_step = 0
        self.is_alive = True
        self.kick_count = 0

    def should_check(self, step_count: int) -> bool:
        """判断是否需要检查"""
        if not self.check_url or not self.cookie:
            return False
        return (step_count - self.last_check_step) >= self.check_interval

    def check(self, step_count: int) -> dict:
        """
        检查 Session 状态
        返回: {"alive": bool, "reason": str, "action": str}
        """
        if not self.check_url:
            return {"alive": True, "reason": "未配置监控URL", "action": "continue"}

        self.last_check_step = step_count

        # 发一个请求到已知正常页面
        cmd = (
            f'curl -s -o /dev/null -w "%{{http_code}}" '
            f'-H "Cookie: {self.cookie}" '
            f'-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" '
            f'"{self.check_url}"'
        )

        result = self.engine.execute_command(cmd, timeout=15)

        if not result["success"]:
            return {"alive": True, "reason": "检查请求失败(网络问题)", "action": "continue"}

        status_code = result["output"].strip()

        # 判断状态
        if status_code == "200":
            # 进一步检查响应内容（如果配置了关键词）
            if self.expected_keyword:
                content_cmd = (
                    f'curl -s '
                    f'-H "Cookie: {self.cookie}" '
                    f'-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" '
                    f'"{self.check_url}" | head -100'
                )
                content_result = self.engine.execute_command(content_cmd, timeout=15)
                if content_result["success"]:
                    body = content_result["output"]
                    # 检查是否有风控关键词
                    risk_keywords = ["验证码", "人机验证", "滑块", "captcha", "请完成验证"]
                    for kw in risk_keywords:
                        if kw in body:
                            self.is_alive = False
                            self.logger.log_event("REDLINE_STOP",
                                f"触发风控! 响应中出现: '{kw}'")
                            return {
                                "alive": False,
                                "reason": f"触发风控: 响应包含 '{kw}'",
                                "action": "stop"
                            }
                    # 检查预期关键词是否存在
                    if self.expected_keyword not in body:
                        self.kick_count += 1
                        if self.kick_count >= 2:
                            self.is_alive = False
                            self.logger.log_event("REDLINE_STOP",
                                f"Session失效! 连续{self.kick_count}次未找到预期内容")
                            return {
                                "alive": False,
                                "reason": f"Session可能失效(预期关键词不存在)",
                                "action": "stop"
                            }

            self.kick_count = 0
            return {"alive": True, "reason": "Session正常", "action": "continue"}

        elif status_code in ("302", "301"):
            self.is_alive = False
            self.logger.log_event("REDLINE_STOP", f"Session被踢! 收到 {status_code} 重定向")
            return {
                "alive": False,
                "reason": f"Session失效: {status_code} 重定向(可能被踢到登录页)",
                "action": "stop"
            }

        elif status_code == "403":
            self.kick_count += 1
            if self.kick_count >= 3:
                self.is_alive = False
                self.logger.log_event("REDLINE_STOP", f"IP可能被封! 连续{self.kick_count}次403")
                return {
                    "alive": False,
                    "reason": f"连续 {self.kick_count} 次 403，IP可能被封",
                    "action": "stop"
                }
            return {"alive": True, "reason": f"403 (第{self.kick_count}次，观察中)", "action": "slow_down"}

        elif status_code == "429":
            self.logger.log_event("WARNING", "收到 429 Too Many Requests，降速")
            return {"alive": True, "reason": "429 限速触发", "action": "slow_down"}

        else:
            return {"alive": True, "reason": f"状态码: {status_code}", "action": "continue"}
