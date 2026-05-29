#!/usr/bin/env python3
"""
Stealth HTTP — 隐蔽 HTTP 请求引擎

功能：
1. 真实浏览器 User-Agent 轮换（Chrome/Firefox/Safari/Edge 最新版）
2. 完整浏览器指纹模拟（Accept/Language/Encoding/Sec-Fetch 全套头）
3. Referer 链伪装（模拟从搜索引擎/上一页面跳转）
4. Cookie 一致性维护（同 session 内 Cookie 不变）
5. 请求间随机延迟（模拟人类浏览节奏）
6. TLS 指纹降噪（JA3 指纹伪装思路）
7. 请求顺序仿真（先首页 → 再子页面 → 再 API）
8. 与 proxy_rotator / traffic_controller 集成

用法：
    from stealth_http import StealthClient

    client = StealthClient(config)
    resp = await client.get("https://target.com/api/users")
    resp = await client.post("https://target.com/login", data={...})

    # 模拟完整浏览流程
    await client.browse_like_human("https://target.com")
"""

import asyncio
import random
import time
import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from urllib.parse import urlparse, urljoin


# ═══════════════════════════════════════════════════════════════
# User-Agent 库（2024-2025 真实浏览器）
# ═══════════════════════════════════════════════════════════════

USER_AGENTS = {
    "chrome_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    ],
    "chrome_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "chrome_linux": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "firefox_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    ],
    "firefox_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    ],
    "firefox_linux": [
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    ],
    "safari_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ],
    "edge_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ],
    "mobile_ios": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    ],
    "mobile_android": [
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    ],
}

# 所有 UA 平铺列表
ALL_USER_AGENTS = []
for ua_list in USER_AGENTS.values():
    ALL_USER_AGENTS.extend(ua_list)


# ═══════════════════════════════════════════════════════════════
# 浏览器指纹模板（与 UA 匹配的完整 Header 集）
# ═══════════════════════════════════════════════════════════════

BROWSER_PROFILES = {
    "chrome": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": '"Chromium";v="125", "Not.A/Brand";v="24", "Google Chrome";v="125"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
    },
    "chrome_api": {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": '"Chromium";v="125", "Not.A/Brand";v="24", "Google Chrome";v="125"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Connection": "keep-alive",
    },
    "firefox": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
    "safari": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    },
}

# Referer 伪装来源
REFERER_SOURCES = [
    "https://www.google.com/search?q={domain}",
    "https://www.google.com.hk/search?q={domain}",
    "https://www.baidu.com/s?wd={domain}",
    "https://www.bing.com/search?q={domain}",
    "https://search.yahoo.com/search?p={domain}",
    "",  # 直接访问（无 Referer）
    "",
]

# Accept-Language 变体
LANGUAGES = [
    "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "ja,en-US;q=0.9,en;q=0.8",
]


# ═══════════════════════════════════════════════════════════════
# 响应数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class StealthResponse:
    """隐蔽请求响应"""
    status_code: int = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    latency_ms: int = 0
    proxy_used: str = ""
    # 状态
    is_blocked: bool = False
    block_reason: str = ""


# ═══════════════════════════════════════════════════════════════
# 隐蔽 HTTP 客户端
# ═══════════════════════════════════════════════════════════════

class StealthClient:
    """隐蔽 HTTP 请求引擎"""

    def __init__(self, config: dict = None, proxy_rotator=None):
        self.config = config or {}
        self.proxy_rotator = proxy_rotator

        # 会话状态
        self._session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self._ua = None
        self._profile = None
        self._cookies: Dict[str, str] = {}
        self._last_request_time = 0
        self._request_count = 0
        self._visit_history: List[str] = []

        # 配置
        self.timeout = self.config.get("timeout", 15)
        self.min_delay = self.config.get("min_delay", 0.5)
        self.max_delay = self.config.get("max_delay", 3.0)
        self.rotate_ua_every = self.config.get("rotate_ua_every", 50)  # 每 50 请求换 UA
        self.use_referer = self.config.get("use_referer", True)
        self.browser_type = self.config.get("browser_type", "random")  # chrome/firefox/safari/random

        # 初始化浏览器身份
        self._init_identity()

    def _init_identity(self):
        """初始化浏览器身份（UA + 配套 Headers）"""
        if self.browser_type == "random":
            browser = random.choice(["chrome", "firefox", "safari", "edge"])
        else:
            browser = self.browser_type

        # 选择 UA
        if browser == "chrome":
            ua_pool = USER_AGENTS["chrome_win"] + USER_AGENTS["chrome_mac"]
        elif browser == "firefox":
            ua_pool = USER_AGENTS["firefox_win"] + USER_AGENTS["firefox_linux"]
        elif browser == "safari":
            ua_pool = USER_AGENTS["safari_mac"]
        elif browser == "edge":
            ua_pool = USER_AGENTS["edge_win"]
        else:
            ua_pool = ALL_USER_AGENTS

        self._ua = random.choice(ua_pool)

        # 选择配套 Profile
        if "Chrome" in self._ua or "Edg" in self._ua:
            self._profile = BROWSER_PROFILES["chrome"].copy()
        elif "Firefox" in self._ua:
            self._profile = BROWSER_PROFILES["firefox"].copy()
        elif "Safari" in self._ua and "Chrome" not in self._ua:
            self._profile = BROWSER_PROFILES["safari"].copy()
        else:
            self._profile = BROWSER_PROFILES["chrome"].copy()

        # 随机化 Accept-Language
        self._profile["Accept-Language"] = random.choice(LANGUAGES)

    # ─── 核心请求方法 ─────────────────────────────────────────

    async def get(self, url: str, headers: Dict = None,
                  params: Dict = None, **kwargs) -> StealthResponse:
        """隐蔽 GET 请求"""
        return await self._request("GET", url, headers=headers, params=params, **kwargs)

    async def post(self, url: str, data: Any = None, json_data: Dict = None,
                   headers: Dict = None, **kwargs) -> StealthResponse:
        """隐蔽 POST 请求"""
        return await self._request("POST", url, data=data, json_data=json_data,
                                   headers=headers, **kwargs)

    async def head(self, url: str, headers: Dict = None, **kwargs) -> StealthResponse:
        """隐蔽 HEAD 请求（不下载 body，减少日志体积）"""
        return await self._request("HEAD", url, headers=headers, **kwargs)

    async def _request(self, method: str, url: str, headers: Dict = None,
                       data: Any = None, json_data: Dict = None,
                       params: Dict = None, no_delay: bool = False,
                       is_api: bool = False) -> StealthResponse:
        """内部请求方法"""

        # 1. 请求间延迟（模拟人类节奏）
        if not no_delay:
            await self._human_delay()

        # 2. UA 轮换检查
        self._request_count += 1
        if self._request_count % self.rotate_ua_every == 0:
            self._init_identity()

        # 3. 构建隐蔽 Headers
        final_headers = self._build_headers(url, headers, is_api)

        # 4. 获取代理
        proxy_url = ""
        proxy_args = []
        if self.proxy_rotator:
            proxy_url = self.proxy_rotator.get_current() or ""
            if proxy_url:
                proxy_args = ["-x", proxy_url.replace("socks5://", "socks5h://")]

        # 5. 构建 curl 命令
        cmd = ["curl", "-s", "-m", str(self.timeout)]
        cmd.extend(["-X", method])
        cmd.extend(["-o", "-", "-w", "\n%{http_code}\n%{time_total}"])

        # Headers
        for k, v in final_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        # 代理
        cmd.extend(proxy_args)

        # Body
        if json_data:
            cmd.extend(["-H", "Content-Type: application/json"])
            cmd.extend(["-d", json.dumps(json_data)])
        elif data:
            if isinstance(data, dict):
                from urllib.parse import urlencode
                cmd.extend(["-d", urlencode(data)])
            else:
                cmd.extend(["-d", str(data)])

        # URL
        if params:
            from urllib.parse import urlencode
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urlencode(params)}"
        cmd.append(url)

        # 6. 执行请求
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout + 5
            )
            output = stdout.decode(errors="ignore")
            parts = output.rsplit("\n", 2)

            body = parts[0] if len(parts) >= 3 else output
            status = int(parts[-2].strip()) if len(parts) >= 3 and parts[-2].strip().isdigit() else 0
            latency = int((time.time() - start) * 1000)

        except (asyncio.TimeoutError, Exception) as e:
            return StealthResponse(status_code=0, body="", latency_ms=int((time.time()-start)*1000),
                                   proxy_used=proxy_url, is_blocked=False)

        # 7. 检测是否被拦截
        response = StealthResponse(
            status_code=status,
            body=body,
            latency_ms=latency,
            proxy_used=proxy_url,
        )
        self._detect_block(response)

        # 8. 反馈给代理轮换器
        if self.proxy_rotator and proxy_url:
            if response.is_blocked:
                self.proxy_rotator.mark_banned(proxy_url)
            elif status == 0:
                self.proxy_rotator.mark_failed(proxy_url)
            else:
                self.proxy_rotator.mark_success(proxy_url)

        # 9. 更新访问历史
        self._visit_history.append(url)
        self._last_request_time = time.time()

        return response

    # ─── Headers 构建 ─────────────────────────────────────────

    def _build_headers(self, url: str, custom_headers: Dict = None,
                       is_api: bool = False) -> Dict[str, str]:
        """构建完整的隐蔽 Headers"""
        headers = {}

        # 基础 Profile
        if is_api:
            profile = BROWSER_PROFILES.get("chrome_api", {})
        else:
            profile = self._profile

        headers.update(profile)

        # User-Agent
        headers["User-Agent"] = self._ua

        # Referer（模拟来源）
        if self.use_referer and self._visit_history:
            # 从上一个访问页面跳转
            headers["Referer"] = self._visit_history[-1]
        elif self.use_referer and random.random() > 0.3:
            # 第一次访问，模拟从搜索引擎来
            domain = urlparse(url).netloc
            ref_template = random.choice(REFERER_SOURCES)
            if ref_template:
                headers["Referer"] = ref_template.format(domain=domain)

        # Cookie（如果有）
        if self._cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            headers["Cookie"] = cookie_str

        # 自定义头（覆盖）
        if custom_headers:
            headers.update(custom_headers)

        return headers

    # ─── 人类行为模拟 ─────────────────────────────────────────

    async def _human_delay(self):
        """模拟人类浏览延迟"""
        elapsed = time.time() - self._last_request_time
        min_wait = self.min_delay - elapsed
        if min_wait > 0:
            # 正态分布随机延迟（更像人类）
            delay = random.gauss(
                (self.min_delay + self.max_delay) / 2,
                (self.max_delay - self.min_delay) / 4
            )
            delay = max(self.min_delay, min(delay, self.max_delay * 1.5))
            actual_wait = max(0, delay - elapsed)
            if actual_wait > 0:
                await asyncio.sleep(actual_wait)

    async def browse_like_human(self, base_url: str, depth: int = 2) -> List[StealthResponse]:
        """
        模拟真实人类浏览行为：
        1. 先访问首页
        2. 加载一些静态资源（模拟）
        3. 点击几个子页面
        4. 再访问 API
        """
        responses = []
        parsed = urlparse(base_url)

        # Step 1: 访问首页
        resp = await self.get(base_url)
        responses.append(resp)

        # Step 2: 短暂"阅读"延迟
        await asyncio.sleep(random.uniform(1.0, 3.0))

        # Step 3: 访问 robots.txt（正常浏览器行为）
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        resp = await self.get(robots_url)
        responses.append(resp)

        # Step 4: 模拟点击子页面
        common_paths = ["/about", "/contact", "/sitemap.xml", "/favicon.ico"]
        for path in random.sample(common_paths, min(depth, len(common_paths))):
            await asyncio.sleep(random.uniform(0.5, 2.0))
            sub_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = await self.head(sub_url)  # HEAD 减少流量
            responses.append(resp)

        return responses

    # ─── 封禁检测 ─────────────────────────────────────────────

    def _detect_block(self, response: StealthResponse):
        """检测是否被 WAF/服务器拦截"""
        # 状态码检测
        if response.status_code in (403, 406, 429, 503):
            response.is_blocked = True
            response.block_reason = f"HTTP {response.status_code}"
            return

        # 响应体关键词检测
        body_lower = response.body.lower()[:2000]
        block_indicators = [
            ("cloudflare", "Cloudflare WAF"),
            ("captcha", "CAPTCHA required"),
            ("rate limit", "Rate limited"),
            ("access denied", "Access denied"),
            ("blocked", "Request blocked"),
            ("forbidden", "Forbidden"),
            ("too many requests", "Too many requests"),
            ("请完成人机验证", "Human verification"),
            ("IP已被封禁", "IP banned"),
            ("访问被拒绝", "Access denied (CN)"),
            ("频率过快", "Rate limited (CN)"),
            ("安全验证", "Security check (CN)"),
        ]
        for keyword, reason in block_indicators:
            if keyword in body_lower:
                response.is_blocked = True
                response.block_reason = reason
                return

    # ─── Cookie 管理 ──────────────────────────────────────────

    def set_cookies(self, cookies: Dict[str, str]):
        """设置 Cookie"""
        self._cookies.update(cookies)

    def set_cookie(self, name: str, value: str):
        """设置单个 Cookie"""
        self._cookies[name] = value

    def clear_cookies(self):
        """清除所有 Cookie"""
        self._cookies.clear()

    # ─── 身份管理 ──────────────────────────────────────────────

    def new_identity(self):
        """完全更换浏览器身份（UA + Headers + Cookies）"""
        self._init_identity()
        self._cookies.clear()
        self._visit_history.clear()
        self._session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def get_identity_info(self) -> Dict:
        """获取当前身份信息"""
        return {
            "session_id": self._session_id,
            "user_agent": self._ua[:60] + "...",
            "browser": "Chrome" if "Chrome" in self._ua else "Firefox" if "Firefox" in self._ua else "Safari",
            "requests_sent": self._request_count,
            "cookies_count": len(self._cookies),
        }

    # ─── 批量请求 ─────────────────────────────────────────────

    async def get_many(self, urls: List[str], concurrency: int = 1,
                       delay: float = None) -> List[StealthResponse]:
        """
        批量 GET（带限速）
        concurrency=1 表示串行（最安全），>1 并发
        """
        results = []
        semaphore = asyncio.Semaphore(concurrency)

        async def _fetch(url):
            async with semaphore:
                if delay:
                    await asyncio.sleep(delay)
                return await self.get(url)

        if concurrency == 1:
            # 串行（最隐蔽）
            for url in urls:
                resp = await self.get(url)
                results.append(resp)
        else:
            # 并发
            tasks = [_fetch(url) for url in urls]
            results = await asyncio.gather(*tasks)

        return results

    # ─── 工具方法 ─────────────────────────────────────────────

    def get_curl_headers(self, url: str = "", is_api: bool = False) -> List[str]:
        """获取 curl 格式的 Header 参数列表"""
        headers = self._build_headers(url or "https://example.com", is_api=is_api)
        args = []
        for k, v in headers.items():
            args.extend(["-H", f"{k}: {v}"])
        return args

    def get_headers_dict(self, url: str = "", is_api: bool = False) -> Dict[str, str]:
        """获取字典格式的 Headers（供 requests/httpx 使用）"""
        return self._build_headers(url or "https://example.com", is_api=is_api)
