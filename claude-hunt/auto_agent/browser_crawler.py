#!/usr/bin/env python3
"""
Browser Crawler — Playwright 浏览器爬虫
解决现代 SPA (React/Vue/Angular) 应用的攻击面发现问题

核心能力：
1. 自动登录（Cookie/表单/OAuth）
2. 深度爬取 SPA 页面（等待 JS 渲染完成）
3. 拦截所有 XHR/Fetch 网络请求 → 发现隐藏 API
4. 提取页面中的链接/表单/事件处理器
5. 自动触发按钮/表单交互发现更多端点
6. 收集所有 JS 文件 URL 供后续分析
7. 截图关键页面（留证据）

依赖: pip install playwright && playwright install chromium
"""

import asyncio
import re
import json
import time
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs
from dataclasses import dataclass, field
from typing import Optional, Any

try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class CrawlResult:
    """爬取结果"""
    # 发现的 API 端点
    api_endpoints: list = field(default_factory=list)
    # 发现的 URL
    urls: list = field(default_factory=list)
    # JS 文件列表
    js_files: list = field(default_factory=list)
    # 表单
    forms: list = field(default_factory=list)
    # 网络请求记录
    network_requests: list = field(default_factory=list)
    # WebSocket 端点
    websocket_endpoints: list = field(default_factory=list)
    # 截图路径
    screenshots: list = field(default_factory=list)
    # 错误
    errors: list = field(default_factory=list)
    # 页面标题
    page_titles: dict = field(default_factory=dict)
    # 技术栈指纹
    tech_stack: dict = field(default_factory=dict)


@dataclass
class NetworkRequest:
    """网络请求记录"""
    method: str = ""
    url: str = ""
    headers: dict = field(default_factory=dict)
    post_data: str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body_preview: str = ""
    content_type: str = ""
    timestamp: float = 0.0


# ═══════════════════════════════════════════════════════════════
# Browser Crawler
# ═══════════════════════════════════════════════════════════════

class BrowserCrawler:
    """
    Playwright 浏览器爬虫

    用法:
        crawler = BrowserCrawler(config={
            "target": "https://target.com",
            "cookies": [{"name": "session", "value": "xxx", "domain": "target.com"}],
            "max_pages": 50,
            "max_depth": 3,
            "headless": True,
            "screenshot_dir": "/tmp/screenshots",
        })
        result = await crawler.crawl()
    """

    def __init__(self, config: dict = None):
        if not HAS_PLAYWRIGHT:
            raise ImportError(
                "需要安装 playwright:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            )

        self.config = config or {}
        self.target = self.config.get("target", "")
        self.cookies = self.config.get("cookies", [])
        self.max_pages = self.config.get("max_pages", 50)
        self.max_depth = self.config.get("max_depth", 3)
        self.headless = self.config.get("headless", True)
        self.screenshot_dir = self.config.get("screenshot_dir", "")
        self.wait_time = self.config.get("wait_time", 3000)  # ms
        self.timeout = self.config.get("timeout", 30000)  # ms
        self.proxy = self.config.get("proxy", None)

        # 登录配置
        self.login_url = self.config.get("login_url", "")
        self.login_username = self.config.get("login_username", "")
        self.login_password = self.config.get("login_password", "")
        self.login_username_selector = self.config.get("login_username_selector", "input[name='username'], input[type='email'], #username, #email")
        self.login_password_selector = self.config.get("login_password_selector", "input[name='password'], input[type='password'], #password")
        self.login_submit_selector = self.config.get("login_submit_selector", "button[type='submit'], input[type='submit'], .login-btn, #login-btn")

        # Scope 控制
        self.allowed_domains = self.config.get("allowed_domains", [])
        if self.target and not self.allowed_domains:
            parsed = urlparse(self.target)
            self.allowed_domains = [parsed.netloc]

        # 状态
        self.visited_urls: set = set()
        self.result = CrawlResult()
        self._network_log: list = []

    # ─── 主入口 ────────────────────────────────────────────────

    async def crawl(self) -> CrawlResult:
        """执行完整爬取"""
        async with async_playwright() as p:
            # 启动浏览器
            launch_args = {
                "headless": self.headless,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ]
            }
            if self.proxy:
                launch_args["proxy"] = {"server": self.proxy}

            browser = await p.chromium.launch(**launch_args)

            # 创建上下文（模拟真实浏览器）
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                locale="zh-CN",
                timezone_id="Asia/Shanghai",
            )

            # 设置 Cookie
            if self.cookies:
                await context.add_cookies(self.cookies)

            # 创建页面
            page = await context.new_page()

            # 注册网络拦截
            await self._setup_network_interception(page)

            try:
                # 如果需要登录
                if self.login_url and self.login_username:
                    await self._perform_login(page)

                # 开始爬取
                await self._crawl_page(page, self.target, depth=0)

                # 提取技术栈
                self.result.tech_stack = await self._detect_tech_stack(page)

            except Exception as e:
                self.result.errors.append(f"爬取异常: {str(e)}")
            finally:
                await browser.close()

        # 去重和整理
        self._deduplicate_results()
        return self.result

    # ─── 网络拦截 ──────────────────────────────────────────────

    async def _setup_network_interception(self, page: Page):
        """设置网络请求拦截 — 这是发现隐藏 API 的核心"""

        async def on_request(request):
            url = request.url
            method = request.method

            # 记录 API 请求
            if self._is_api_request(url, method):
                net_req = NetworkRequest(
                    method=method,
                    url=url,
                    headers=dict(request.headers),
                    post_data=request.post_data or "",
                    timestamp=time.time(),
                )
                self._network_log.append(net_req)
                self.result.api_endpoints.append({
                    "method": method,
                    "url": url,
                    "post_data": request.post_data[:500] if request.post_data else "",
                    "headers": {k: v for k, v in request.headers.items()
                               if k.lower() in ("authorization", "x-csrf-token", "content-type")},
                })

            # 记录 JS 文件
            if url.endswith(".js") or ".js?" in url:
                if url not in self.result.js_files:
                    self.result.js_files.append(url)

            # WebSocket
            if url.startswith("wss://") or url.startswith("ws://"):
                if url not in self.result.websocket_endpoints:
                    self.result.websocket_endpoints.append(url)

        async def on_response(response):
            # 记录响应状态
            for net_req in reversed(self._network_log):
                if net_req.url == response.url and net_req.response_status == 0:
                    net_req.response_status = response.status
                    net_req.content_type = response.headers.get("content-type", "")
                    net_req.response_headers = dict(response.headers)
                    break

        page.on("request", on_request)
        page.on("response", on_response)

    def _is_api_request(self, url: str, method: str) -> bool:
        """判断是否是 API 请求"""
        # 排除静态资源
        static_exts = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                      ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map")
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        if any(path_lower.endswith(ext) for ext in static_exts):
            return False

        # API 特征
        api_indicators = [
            "/api/", "/v1/", "/v2/", "/v3/",
            "/graphql", "/rest/", "/rpc/",
            "/ajax/", "/_api/", "/internal/",
        ]

        if any(ind in url.lower() for ind in api_indicators):
            return True

        # POST/PUT/DELETE 基本都是 API
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            return True

        # JSON 类型的 GET
        if "application/json" in url or "json" in url.lower():
            return True

        return False

    # ─── 登录 ─────────────────────────────────────────────────

    async def _perform_login(self, page: Page):
        """自动登录"""
        try:
            await page.goto(self.login_url, wait_until="networkidle", timeout=self.timeout)
            await page.wait_for_timeout(1000)

            # 填写用户名
            username_input = await page.query_selector(self.login_username_selector)
            if username_input:
                await username_input.fill(self.login_username)

            # 填写密码
            password_input = await page.query_selector(self.login_password_selector)
            if password_input:
                await password_input.fill(self.login_password)

            # 点击提交
            submit_btn = await page.query_selector(self.login_submit_selector)
            if submit_btn:
                await submit_btn.click()

            # 等待登录完成
            await page.wait_for_load_state("networkidle")
            await page.wait_for_timeout(2000)

        except Exception as e:
            self.result.errors.append(f"登录失败: {str(e)}")

    # ─── 爬取逻辑 ─────────────────────────────────────────────

    async def _crawl_page(self, page: Page, url: str, depth: int):
        """爬取单个页面"""
        if depth > self.max_depth:
            return
        if len(self.visited_urls) >= self.max_pages:
            return
        if url in self.visited_urls:
            return
        if not self._is_in_scope(url):
            return

        self.visited_urls.add(url)

        try:
            response = await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            if not response:
                return

            # 等待 JS 渲染
            await page.wait_for_timeout(self.wait_time)

            # 记录页面标题
            title = await page.title()
            self.result.page_titles[url] = title

            # 提取页面中的链接
            links = await self._extract_links(page, url)
            self.result.urls.extend(links)

            # 提取表单
            forms = await self._extract_forms(page, url)
            self.result.forms.extend(forms)

            # 尝试交互（点击按钮等）发现更多端点
            await self._interact_with_page(page)

            # 截图
            if self.screenshot_dir:
                await self._take_screenshot(page, url)

            # 递归爬取发现的链接
            for link in links[:10]:  # 每页最多跟进 10 个链接
                if link not in self.visited_urls:
                    await self._crawl_page(page, link, depth + 1)

        except Exception as e:
            self.result.errors.append(f"爬取 {url[:80]} 失败: {str(e)[:100]}")

    async def _extract_links(self, page: Page, base_url: str) -> list:
        """提取页面中所有链接"""
        links = set()

        # <a href="...">
        hrefs = await page.eval_on_selector_all(
            "a[href]",
            "elements => elements.map(e => e.href)"
        )
        for href in hrefs:
            full_url = urljoin(base_url, href)
            if self._is_in_scope(full_url):
                links.add(full_url)

        # JS 中的 URL 模式
        page_content = await page.content()
        js_urls = re.findall(
            r'(?:href|src|action|url|endpoint)\s*[=:]\s*["\']([^"\']+)["\']',
            page_content
        )
        for js_url in js_urls:
            if js_url.startswith("/") or js_url.startswith("http"):
                full_url = urljoin(base_url, js_url)
                if self._is_in_scope(full_url):
                    links.add(full_url)

        # data-* 属性中的 URL
        data_urls = await page.eval_on_selector_all(
            "[data-url], [data-href], [data-src], [data-api]",
            """elements => elements.map(e => 
                e.dataset.url || e.dataset.href || e.dataset.src || e.dataset.api
            ).filter(Boolean)"""
        )
        for data_url in data_urls:
            full_url = urljoin(base_url, data_url)
            if self._is_in_scope(full_url):
                links.add(full_url)

        return list(links)

    async def _extract_forms(self, page: Page, base_url: str) -> list:
        """提取页面中的表单"""
        forms = []

        form_data = await page.eval_on_selector_all(
            "form",
            """forms => forms.map(f => ({
                action: f.action || window.location.href,
                method: f.method || 'GET',
                inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                    name: i.name,
                    type: i.type,
                    value: i.value,
                    placeholder: i.placeholder
                })).filter(i => i.name)
            }))"""
        )

        for form in form_data:
            form["action"] = urljoin(base_url, form["action"])
            forms.append(form)

        return forms

    async def _interact_with_page(self, page: Page):
        """与页面交互 — 触发按钮/下拉菜单发现更多 API"""
        try:
            # 点击所有可见的按钮（非提交按钮）
            buttons = await page.query_selector_all(
                "button:not([type='submit']):visible, "
                "[role='button']:visible, "
                ".btn:visible, "
                "[class*='tab']:visible, "
                "[class*='menu-item']:visible"
            )

            for btn in buttons[:5]:  # 最多点 5 个
                try:
                    await btn.click(timeout=3000)
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass

            # 展开下拉菜单
            dropdowns = await page.query_selector_all(
                "select:visible, [class*='dropdown']:visible"
            )
            for dd in dropdowns[:3]:
                try:
                    await dd.click(timeout=2000)
                    await page.wait_for_timeout(500)
                except Exception:
                    pass

        except Exception:
            pass  # 交互失败不影响主流程

    # ─── 技术栈检测 ────────────────────────────────────────────

    async def _detect_tech_stack(self, page: Page) -> dict:
        """从页面特征检测技术栈"""
        tech = {}

        try:
            detection_script = """
            () => {
                const tech = {};
                // 前端框架
                if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector('[data-reactroot]'))
                    tech.frontend = 'React';
                else if (window.__VUE__)
                    tech.frontend = 'Vue.js';
                else if (window.ng || document.querySelector('[ng-app]'))
                    tech.frontend = 'Angular';
                else if (window.__NEXT_DATA__)
                    tech.frontend = 'Next.js';
                else if (window.__NUXT__)
                    tech.frontend = 'Nuxt.js';

                // 状态管理
                if (window.__REDUX_DEVTOOLS_EXTENSION__)
                    tech.state = 'Redux';
                if (window.__VUEX__)
                    tech.state = 'Vuex';

                // GraphQL
                if (document.querySelector('[data-graphql]') || window.__APOLLO_CLIENT__)
                    tech.api = 'GraphQL';

                // 其他
                if (window.jQuery) tech.jquery = jQuery.fn.jquery;
                if (window.firebase) tech.firebase = true;
                if (window.Sentry) tech.sentry = true;

                return tech;
            }
            """
            tech = await page.evaluate(detection_script)
        except Exception:
            pass

        return tech

    # ─── 截图 ─────────────────────────────────────────────────

    async def _take_screenshot(self, page: Page, url: str):
        """截图"""
        if not self.screenshot_dir:
            return
        try:
            import os
            os.makedirs(self.screenshot_dir, exist_ok=True)
            filename = hashlib.md5(url.encode()).hexdigest()[:12] + ".png"
            filepath = os.path.join(self.screenshot_dir, filename)
            await page.screenshot(path=filepath, full_page=False)
            self.result.screenshots.append({"url": url, "path": filepath})
        except Exception:
            pass

    # ─── 辅助 ─────────────────────────────────────────────────

    def _is_in_scope(self, url: str) -> bool:
        """检查 URL 是否在 scope 内"""
        if not url or not url.startswith("http"):
            return False
        parsed = urlparse(url)
        if not self.allowed_domains:
            return True
        return any(
            parsed.netloc == domain or parsed.netloc.endswith("." + domain)
            for domain in self.allowed_domains
        )

    def _deduplicate_results(self):
        """去重"""
        self.result.urls = list(set(self.result.urls))
        self.result.js_files = list(set(self.result.js_files))
        self.result.websocket_endpoints = list(set(self.result.websocket_endpoints))

        # API 端点去重（按 method+url）
        seen = set()
        unique_apis = []
        for api in self.result.api_endpoints:
            key = f"{api['method']}|{api['url']}"
            if key not in seen:
                seen.add(key)
                unique_apis.append(api)
        self.result.api_endpoints = unique_apis

    def get_summary(self) -> dict:
        """获取爬取摘要"""
        return {
            "pages_visited": len(self.visited_urls),
            "api_endpoints_found": len(self.result.api_endpoints),
            "urls_found": len(self.result.urls),
            "js_files_found": len(self.result.js_files),
            "forms_found": len(self.result.forms),
            "websocket_endpoints": len(self.result.websocket_endpoints),
            "network_requests": len(self._network_log),
            "tech_stack": self.result.tech_stack,
            "errors": len(self.result.errors),
        }
