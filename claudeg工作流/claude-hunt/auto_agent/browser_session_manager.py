#!/usr/bin/env python3
"""
Browser Session Manager — Playwright 多会话管理
移植自 Shannon 框架的 Session Manager

特性：
1. 多浏览器会话隔离（每个 Agent/任务独立 session）
2. 自动登录 + 会话保活（Cookie/JWT/OAuth）
3. 网络请求拦截（API 发现 + 认证 token 提取）
4. 认证状态监控 + 自动刷新
5. 并行爬取支持（多 context 互不干扰）
6. 与 auth_manager.py 集成

用法：
    manager = BrowserSessionManager(config)
    await manager.start()
    
    # 获取已认证的 session
    session = await manager.get_session("agent1")
    page = await session.new_page()
    
    # 自动登录
    await manager.login(session_id="agent1")
    
    # 拦截网络请求发现 API
    apis = await manager.discover_apis("agent1")
"""

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from datetime import datetime

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    Browser = None
    BrowserContext = None
    Page = None


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class SessionConfig:
    """单个会话配置"""
    session_id: str = ""
    # 认证
    cookies: List[Dict] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    # 登录流程
    login_url: str = ""
    login_username: str = ""
    login_password: str = ""
    login_steps: List[str] = field(default_factory=list)
    # 验证
    check_url: str = ""
    check_keyword: str = ""
    # 浏览器
    headless: bool = True
    proxy: str = ""
    user_agent: str = ""



@dataclass
class DiscoveredAPI:
    """发现的 API 端点"""
    url: str = ""
    method: str = "GET"
    content_type: str = ""
    has_auth: bool = False
    auth_header: str = ""
    params: List[str] = field(default_factory=list)
    response_type: str = ""
    status_code: int = 0


@dataclass
class SessionState:
    """会话状态"""
    session_id: str = ""
    is_authenticated: bool = False
    last_check: float = 0
    cookies_count: int = 0
    discovered_apis: List[DiscoveredAPI] = field(default_factory=list)
    intercepted_tokens: List[str] = field(default_factory=list)
    pages_visited: int = 0
    errors: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# Browser Session Manager
# ═══════════════════════════════════════════════════════════════

class BrowserSessionManager:
    """
    Playwright 多会话浏览器管理器
    
    Shannon 风格：每个 Agent 分配独立 browser context，
    互不干扰，可并行操作。
    """

    # Shannon 的 session 映射（5个并行 Agent 各一个）
    DEFAULT_SESSIONS = ["agent1", "agent2", "agent3", "agent4", "agent5"]

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._contexts: Dict[str, BrowserContext] = {}
        self._states: Dict[str, SessionState] = {}
        self._api_cache: Dict[str, Set[str]] = {}
        self._running = False

    async def start(self, headless: bool = True):
        """启动浏览器"""
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("Playwright 未安装。运行: pip install playwright && playwright install chromium")

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=headless,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
            ]
        )
        self._running = True

    async def stop(self):
        """关闭浏览器"""
        for ctx in self._contexts.values():
            try:
                await ctx.close()
            except Exception:
                pass
        self._contexts.clear()

        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._running = False

    async def get_session(
        self,
        session_id: str,
        session_config: Optional[SessionConfig] = None,
    ) -> BrowserContext:
        """
        获取或创建浏览器会话
        
        每个 session_id 对应一个独立的 BrowserContext（隔离 cookies/storage）
        """
        if session_id in self._contexts:
            return self._contexts[session_id]

        if not self._browser:
            await self.start()

        # 创建新 context
        context_options = {
            "ignore_https_errors": True,
        }

        if session_config:
            if session_config.proxy:
                context_options["proxy"] = {"server": session_config.proxy}
            if session_config.user_agent:
                context_options["user_agent"] = session_config.user_agent

        context = await self._browser.new_context(**context_options)

        # 注入 cookies
        if session_config and session_config.cookies:
            await context.add_cookies(session_config.cookies)

        # 注入 headers
        if session_config and session_config.headers:
            await context.set_extra_http_headers(session_config.headers)

        # 设置网络拦截
        await self._setup_network_interception(context, session_id)

        self._contexts[session_id] = context
        self._states[session_id] = SessionState(session_id=session_id)
        self._api_cache[session_id] = set()

        return context


    async def login(
        self,
        session_id: str,
        login_url: str = "",
        username: str = "",
        password: str = "",
        login_steps: List[str] = None,
        success_url_contains: str = "",
        success_element: str = "",
    ) -> bool:
        """
        自动登录
        
        支持两种方式：
        1. 自然语言步骤（Shannon 风格）
        2. 通用表单检测
        """
        context = await self.get_session(session_id)
        page = await context.new_page()

        try:
            await page.goto(login_url, wait_until="networkidle", timeout=30000)

            if login_steps:
                # Shannon 风格：按自然语言步骤执行
                for step in login_steps:
                    await self._execute_login_step(page, step, username, password)
                    await asyncio.sleep(0.5)
            else:
                # 通用表单登录
                await self._generic_form_login(page, username, password)

            # 等待导航完成
            await asyncio.sleep(2)
            await page.wait_for_load_state("networkidle", timeout=10000)

            # 验证登录成功
            success = False
            if success_url_contains:
                success = success_url_contains in page.url
            elif success_element:
                success = await page.query_selector(success_element) is not None
            else:
                # 默认：URL 变了就算成功
                success = page.url != login_url

            if success:
                self._states[session_id].is_authenticated = True
                self._states[session_id].last_check = time.time()
                # 提取 cookies
                cookies = await context.cookies()
                self._states[session_id].cookies_count = len(cookies)

            await page.close()
            return success

        except Exception as e:
            self._states[session_id].errors.append(f"Login failed: {str(e)}")
            await page.close()
            return False

    async def _execute_login_step(self, page: Page, step: str, username: str, password: str):
        """执行 Shannon 风格的自然语言登录步骤"""
        step_lower = step.lower()

        # 替换变量
        step = step.replace("$username", username).replace("$password", password)

        if "type" in step_lower or "input" in step_lower or "fill" in step_lower:
            # 提取选择器和值
            selector_match = re.search(r'(?:into|in)\s+(?:the\s+)?(.+?)(?:\s+field)?$', step, re.IGNORECASE)
            value = username if "username" in step_lower or "email" in step_lower else password

            if selector_match:
                selector_hint = selector_match.group(1).strip()
                # 尝试常见选择器
                selectors = [
                    f'input[name*="{selector_hint}"]',
                    f'input[placeholder*="{selector_hint}"]',
                    f'input[id*="{selector_hint}"]',
                    f'input[type="email"]' if "email" in selector_hint else None,
                    f'input[type="password"]' if "password" in selector_hint else None,
                ]
                for sel in filter(None, selectors):
                    try:
                        el = await page.query_selector(sel)
                        if el:
                            await el.fill(value)
                            break
                    except Exception:
                        continue

        elif "click" in step_lower:
            # 提取按钮文本或选择器
            btn_match = re.search(r"click\s+(?:the\s+)?['\"]?(.+?)['\"]?\s*(?:button)?$", step, re.IGNORECASE)
            if btn_match:
                btn_text = btn_match.group(1).strip()
                selectors = [
                    f'button:has-text("{btn_text}")',
                    f'input[value*="{btn_text}"]',
                    f'a:has-text("{btn_text}")',
                    'button[type="submit"]',
                    'input[type="submit"]',
                ]
                for sel in selectors:
                    try:
                        el = await page.query_selector(sel)
                        if el:
                            await el.click()
                            break
                    except Exception:
                        continue

        elif "wait" in step_lower:
            await asyncio.sleep(2)

    async def _generic_form_login(self, page: Page, username: str, password: str):
        """通用表单登录（自动检测输入框）"""
        # 用户名/邮箱框
        username_selectors = [
            'input[type="email"]',
            'input[name="username"]', 'input[name="email"]',
            'input[name="login"]', 'input[name="user"]',
            'input[id="username"]', 'input[id="email"]',
            'input[autocomplete="username"]',
        ]
        for sel in username_selectors:
            el = await page.query_selector(sel)
            if el:
                await el.fill(username)
                break

        # 密码框
        password_selectors = [
            'input[type="password"]',
            'input[name="password"]', 'input[name="pass"]',
        ]
        for sel in password_selectors:
            el = await page.query_selector(sel)
            if el:
                await el.fill(password)
                break

        # 提交
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("登录")',
            'button:has-text("Login")',
            'button:has-text("Sign in")',
        ]
        for sel in submit_selectors:
            el = await page.query_selector(sel)
            if el:
                await el.click()
                break


    # ─── 网络拦截 + API 发现 ──────────────────────────────────

    async def _setup_network_interception(self, context: BrowserContext, session_id: str):
        """设置网络请求拦截"""
        async def on_request(route, request):
            # 记录 API 请求
            url = request.url
            if self._is_api_request(url):
                api = DiscoveredAPI(
                    url=url,
                    method=request.method,
                    content_type=request.headers.get("content-type", ""),
                    has_auth="authorization" in request.headers or "cookie" in request.headers,
                    auth_header=request.headers.get("authorization", ""),
                )
                # 提取参数
                if "?" in url:
                    params = re.findall(r'[?&](\w+)=', url)
                    api.params = params

                state = self._states.get(session_id)
                if state and url not in self._api_cache.get(session_id, set()):
                    state.discovered_apis.append(api)
                    self._api_cache.setdefault(session_id, set()).add(url)

                # 提取 token
                auth = request.headers.get("authorization", "")
                if auth and auth.startswith("Bearer "):
                    token = auth[7:]
                    if state and token not in state.intercepted_tokens:
                        state.intercepted_tokens.append(token[:50] + "...")

            await route.continue_()

        # 拦截所有请求
        await context.route("**/*", on_request)

    def _is_api_request(self, url: str) -> bool:
        """判断是否为 API 请求"""
        api_patterns = [
            "/api/", "/v1/", "/v2/", "/v3/",
            "/graphql", "/rest/", "/rpc/",
            ".json", "/ajax/",
        ]
        # 排除静态资源
        static_ext = [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico"]
        if any(url.endswith(ext) for ext in static_ext):
            return False
        return any(p in url.lower() for p in api_patterns)

    async def discover_apis(self, session_id: str, start_url: str = "", max_pages: int = 10) -> List[DiscoveredAPI]:
        """
        通过浏览操作发现 API 端点
        
        访问页面 → 拦截 XHR/Fetch → 收集 API 端点
        """
        context = await self.get_session(session_id)
        page = await context.new_page()

        try:
            if start_url:
                await page.goto(start_url, wait_until="networkidle", timeout=30000)
                await asyncio.sleep(2)

            # 点击页面上的主要链接，触发更多 API 请求
            links = await page.query_selector_all('a[href]')
            visited = set()
            pages_visited = 0

            for link in links[:max_pages]:
                try:
                    href = await link.get_attribute("href")
                    if href and href not in visited and not href.startswith("#"):
                        visited.add(href)
                        await link.click()
                        await asyncio.sleep(1)
                        await page.wait_for_load_state("networkidle", timeout=5000)
                        pages_visited += 1
                        await page.go_back()
                        await asyncio.sleep(0.5)
                except Exception:
                    continue

            self._states[session_id].pages_visited = pages_visited
            await page.close()

        except Exception as e:
            self._states[session_id].errors.append(f"API discovery error: {str(e)}")
            await page.close()

        return self._states.get(session_id, SessionState()).discovered_apis

    # ─── 会话状态检查 ──────────────────────────────────────

    async def check_auth_status(self, session_id: str, check_url: str = "", check_keyword: str = "") -> bool:
        """检查会话是否仍然有效"""
        if not check_url:
            return self._states.get(session_id, SessionState()).is_authenticated

        context = self._contexts.get(session_id)
        if not context:
            return False

        page = await context.new_page()
        try:
            resp = await page.goto(check_url, wait_until="networkidle", timeout=15000)
            if resp and resp.status == 200:
                if check_keyword:
                    content = await page.content()
                    is_valid = check_keyword in content
                else:
                    is_valid = True

                self._states[session_id].is_authenticated = is_valid
                self._states[session_id].last_check = time.time()
                await page.close()
                return is_valid
        except Exception:
            pass

        await page.close()
        self._states[session_id].is_authenticated = False
        return False

    async def refresh_session(self, session_id: str, session_config: SessionConfig) -> bool:
        """刷新过期的会话"""
        # 先检查是否过期
        is_valid = await self.check_auth_status(
            session_id, session_config.check_url, session_config.check_keyword
        )
        if is_valid:
            return True

        # 重新登录
        return await self.login(
            session_id=session_id,
            login_url=session_config.login_url,
            username=session_config.login_username,
            password=session_config.login_password,
            login_steps=session_config.login_steps,
        )

    # ─── 工具方法 ──────────────────────────────────────────

    async def get_cookies(self, session_id: str) -> List[Dict]:
        """获取会话的所有 cookies"""
        context = self._contexts.get(session_id)
        if context:
            return await context.cookies()
        return []

    async def get_cookie_string(self, session_id: str) -> str:
        """获取 Cookie 字符串（用于 curl/httpx）"""
        cookies = await self.get_cookies(session_id)
        return "; ".join(f"{c['name']}={c['value']}" for c in cookies)

    def get_state(self, session_id: str) -> SessionState:
        """获取会话状态"""
        return self._states.get(session_id, SessionState(session_id=session_id))

    def get_all_discovered_apis(self) -> List[DiscoveredAPI]:
        """获取所有会话发现的 API"""
        all_apis = []
        seen_urls = set()
        for state in self._states.values():
            for api in state.discovered_apis:
                if api.url not in seen_urls:
                    all_apis.append(api)
                    seen_urls.add(api.url)
        return all_apis

    def export_apis_for_fuzzing(self) -> List[Dict]:
        """
        导出发现的 API 为 auto_hunt 兼容格式
        可直接注入 findings["urls"] 和 findings["params"]
        """
        apis = self.get_all_discovered_apis()
        urls = []
        params = []
        for api in apis:
            urls.append(api.url)
            for param in api.params:
                param_url = f"{api.url.split('?')[0]}?{param}=FUZZ"
                params.append(param_url)
        return {"urls": urls, "params": params, "apis": [
            {"url": a.url, "method": a.method, "has_auth": a.has_auth, "params": a.params}
            for a in apis
        ]}

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()
