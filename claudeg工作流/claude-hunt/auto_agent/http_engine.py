#!/usr/bin/env python3
"""
HTTP Engine — 真正的 HTTP 请求引擎
替代 subprocess curl，提供：
1. 异步批量请求
2. Session/Cookie 自动管理
3. 响应差异检测（注入点发现的核心）
4. 请求历史记录
5. 自动限速 + 重试
6. 代理支持（Burp/mitmproxy）

用法:
    from http_engine import HttpEngine
    engine = HttpEngine(cookies={"session": "abc"}, rate_limit=3)
    
    # 单次请求
    resp = await engine.request("GET", "https://target.com/api/user/1")
    
    # 响应差异检测
    diffs = await engine.diff_responses(
        "https://target.com/search?q=FUZZ",
        param="q",
        payloads=["test", "'", "\"", "{{7*7}}"]
    )
    
    # 批量并发
    results = await engine.concurrent_requests([
        ("POST", "https://target.com/redeem", {"json": {"code": "PROMO10"}})
    ] * 10)
"""

import asyncio
import hashlib
import time
import random
import re
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from dataclasses import dataclass, field

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class HttpResponse:
    """统一的 HTTP 响应结构"""
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    body_bytes: bytes = b""
    elapsed: float = 0.0
    url: str = ""
    method: str = ""
    content_length: int = 0
    content_type: str = ""
    # 差异分析用
    body_hash: str = ""
    word_count: int = 0
    line_count: int = 0
    error: str = ""

    def __post_init__(self):
        if self.body and not self.body_hash:
            self.body_hash = hashlib.md5(self.body.encode()).hexdigest()
        if self.body and not self.word_count:
            self.word_count = len(self.body.split())
        if self.body and not self.line_count:
            self.line_count = self.body.count('\n') + 1
        if not self.content_length and self.body:
            self.content_length = len(self.body)


@dataclass
class DiffResult:
    """响应差异分析结果"""
    payload: str = ""
    response: Optional[HttpResponse] = None
    # 与 baseline 的差异
    status_diff: bool = False
    length_diff: int = 0
    length_diff_percent: float = 0.0
    time_diff: float = 0.0
    word_diff: int = 0
    header_diff: list = field(default_factory=list)
    body_contains_payload: bool = False
    # 反射检测
    reflected: bool = False
    reflection_context: str = ""  # "html_tag", "html_attr", "js", "url", etc.
    # 异常评分 (0-100)
    anomaly_score: int = 0


# ═══════════════════════════════════════════════════════════════
# UA 池
# ═══════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]


# ═══════════════════════════════════════════════════════════════
# 主引擎
# ═══════════════════════════════════════════════════════════════

class HttpEngine:
    """
    真正的 HTTP 请求引擎
    支持异步请求、session 管理、响应差异检测
    """

    def __init__(self, config: dict = None):
        """
        config 可选项:
            cookies: dict — 全局 Cookie
            headers: dict — 全局请求头
            proxy: str — 代理地址 (http://127.0.0.1:8080)
            rate_limit: float — 每秒最大请求数
            timeout: float — 超时秒数
            max_retries: int — 最大重试次数
            rotate_ua: bool — 是否随机 UA
            verify_ssl: bool — 是否验证 SSL
            max_history: int — 最大历史记录数
        """
        self.config = config or {}
        self.cookies = self.config.get("cookies", {})
        self.headers = self.config.get("headers", {})
        self.proxy = self.config.get("proxy", None)
        self.rate_limit = self.config.get("rate_limit", 3.0)
        self.timeout = self.config.get("timeout", 15.0)
        self.max_retries = self.config.get("max_retries", 2)
        self.rotate_ua = self.config.get("rotate_ua", True)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.max_history = self.config.get("max_history", 1000)

        # 状态
        self.history: list[HttpResponse] = []
        self.request_count = 0
        self.last_request_time = 0.0
        self._client = None
        self._lock = asyncio.Lock()

    # ─── Client 管理 ───────────────────────────────────────────

    async def _get_client(self):
        """获取或创建 httpx 异步客户端"""
        if self._client is None or self._client.is_closed:
            if not HAS_HTTPX:
                raise ImportError(
                    "需要安装 httpx: pip install httpx\n"
                    "或: pip install httpx[http2]"
                )
            
            transport_kwargs = {}
            if not self.verify_ssl:
                transport_kwargs["verify"] = False
            
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                max_redirects=5,
                verify=not self.verify_ssl,
                proxies=self.proxy,
            )
        return self._client

    async def close(self):
        """关闭客户端"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ─── 核心请求方法 ───────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        cookies: dict = None,
        data: Any = None,
        json_data: Any = None,
        params: dict = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        """
        发送一个 HTTP 请求
        返回统一的 HttpResponse 对象
        """
        # 限速
        await self._rate_limit_wait()

        # 合并 headers
        req_headers = {**self.headers}
        if self.rotate_ua:
            req_headers["User-Agent"] = random.choice(USER_AGENTS)
        if headers:
            req_headers.update(headers)

        # 合并 cookies
        req_cookies = {**self.cookies}
        if cookies:
            req_cookies.update(cookies)

        # 重试逻辑
        last_error = ""
        for attempt in range(self.max_retries + 1):
            try:
                client = await self._get_client()
                start_time = time.time()

                resp = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers,
                    cookies=req_cookies,
                    data=data,
                    json=json_data,
                    params=params,
                    follow_redirects=allow_redirects,
                )

                elapsed = time.time() - start_time
                body_text = resp.text if len(resp.content) < 500000 else resp.text[:500000]

                http_resp = HttpResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=body_text,
                    body_bytes=resp.content[:100000],
                    elapsed=elapsed,
                    url=str(resp.url),
                    method=method.upper(),
                    content_length=len(resp.content),
                    content_type=resp.headers.get("content-type", ""),
                )

                # 记录历史
                self._record_history(http_resp)
                self.request_count += 1

                return http_resp

            except httpx.TimeoutException:
                last_error = f"Timeout after {self.timeout}s"
                if attempt < self.max_retries:
                    await asyncio.sleep(1 * (attempt + 1))
            except httpx.ConnectError as e:
                last_error = f"Connection error: {e}"
                if attempt < self.max_retries:
                    await asyncio.sleep(2 * (attempt + 1))
            except Exception as e:
                last_error = f"Request error: {e}"
                break

        # 所有重试失败
        return HttpResponse(
            url=url,
            method=method.upper(),
            error=last_error,
        )

    # ─── 响应差异检测（核心能力）─────────────────────────────────

    async def diff_responses(
        self,
        url: str,
        param: str,
        payloads: list[str],
        method: str = "GET",
        baseline_value: str = "test123",
        extra_headers: dict = None,
        cookies: dict = None,
        body_template: dict = None,
    ) -> list[DiffResult]:
        """
        响应差异检测 — 注入点发现的核心方法
        
        原理：
        1. 发送正常请求作为 baseline
        2. 依次替换参数为各种 payload
        3. 对比响应的 状态码/长度/时间/内容 差异
        4. 差异越大 → 越可能是注入点
        
        参数:
            url: 目标 URL（如果是 GET，参数在 URL 里）
            param: 要测试的参数名
            payloads: payload 列表
            method: HTTP 方法
            baseline_value: baseline 用的正常值
            extra_headers: 额外请求头
            cookies: 额外 Cookie
            body_template: POST body 模板 (dict)，param 会替换其中的值
        
        返回:
            DiffResult 列表，按 anomaly_score 降序排列
        """
        results = []

        # 1. 获取 baseline
        baseline = await self._send_with_param(
            url, param, baseline_value, method, extra_headers, cookies, body_template
        )
        if baseline.error:
            return results

        # 2. 发第二个 baseline 确认稳定性
        baseline2 = await self._send_with_param(
            url, param, baseline_value + "x", method, extra_headers, cookies, body_template
        )

        # 计算 baseline 自身的抖动范围
        baseline_jitter = abs(baseline.content_length - baseline2.content_length)
        time_jitter = abs(baseline.elapsed - baseline2.elapsed)

        # 3. 逐个测试 payload
        for payload in payloads:
            resp = await self._send_with_param(
                url, param, payload, method, extra_headers, cookies, body_template
            )

            if resp.error:
                continue

            # 4. 计算差异
            diff = DiffResult(payload=payload, response=resp)
            diff.status_diff = (resp.status_code != baseline.status_code)
            diff.length_diff = abs(resp.content_length - baseline.content_length)
            diff.time_diff = resp.elapsed - baseline.elapsed
            diff.word_diff = abs(resp.word_count - baseline.word_count)

            if baseline.content_length > 0:
                diff.length_diff_percent = (diff.length_diff / baseline.content_length) * 100

            # Header 差异
            diff.header_diff = self._compare_headers(baseline.headers, resp.headers)

            # 反射检测
            if payload in resp.body:
                diff.reflected = True
                diff.body_contains_payload = True
                diff.reflection_context = self._detect_reflection_context(resp.body, payload)

            # 5. 计算异常评分
            diff.anomaly_score = self._calculate_anomaly_score(
                diff, baseline_jitter, time_jitter
            )

            results.append(diff)

        # 按异常分排序
        results.sort(key=lambda x: x.anomaly_score, reverse=True)
        return results

    async def _send_with_param(
        self, url, param, value, method, extra_headers, cookies, body_template
    ) -> HttpResponse:
        """用指定参数值发送请求"""
        if method.upper() == "GET":
            # 替换 URL 中的参数
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [value]
            new_query = urlencode(qs, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            return await self.request("GET", new_url, headers=extra_headers, cookies=cookies)
        else:
            # POST/PUT — 替换 body 中的参数
            body = dict(body_template) if body_template else {}
            body[param] = value
            return await self.request(
                method, url, headers=extra_headers, cookies=cookies, json_data=body
            )

    # ─── 并发请求（竞态/批量测试）──────────────────────────────

    async def concurrent_requests(
        self,
        requests: list[tuple],
        concurrency: int = 10,
    ) -> list[HttpResponse]:
        """
        并发发送多个请求（用于竞态条件测试）
        
        requests: [(method, url, kwargs), ...]
        concurrency: 并发数
        
        所有请求会尽可能同时发出
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _send(method, url, kwargs):
            async with semaphore:
                return await self.request(method, url, **kwargs)

        # 创建所有 task
        tasks = []
        for req in requests:
            method = req[0]
            url = req[1]
            kwargs = req[2] if len(req) > 2 else {}
            tasks.append(_send(method, url, kwargs))

        # 同时启动
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 转换异常为 HttpResponse
        final = []
        for r in results:
            if isinstance(r, Exception):
                final.append(HttpResponse(error=str(r)))
            else:
                final.append(r)

        return final

    async def race_test(
        self,
        method: str,
        url: str,
        count: int = 20,
        headers: dict = None,
        cookies: dict = None,
        data: Any = None,
        json_data: Any = None,
    ) -> dict:
        """
        专用竞态条件测试
        同时发 N 个相同请求，分析响应差异
        
        返回:
            {
                "total": N,
                "success_count": 200 的个数,
                "unique_bodies": 不同响应体的数量,
                "responses": [HttpResponse, ...],
                "likely_vulnerable": bool,
                "evidence": str
            }
        """
        requests = []
        for _ in range(count):
            kwargs = {}
            if headers:
                kwargs["headers"] = headers
            if cookies:
                kwargs["cookies"] = cookies
            if data:
                kwargs["data"] = data
            if json_data:
                kwargs["json_data"] = json_data
            requests.append((method, url, kwargs))

        responses = await self.concurrent_requests(requests, concurrency=count)

        # 分析
        success_codes = [r for r in responses if r.status_code == 200]
        body_hashes = set(r.body_hash for r in responses if r.body_hash)

        likely_vulnerable = False
        evidence = ""

        if len(success_codes) == count and len(body_hashes) > 1:
            likely_vulnerable = True
            evidence = (
                f"所有 {count} 个请求都返回 200，但有 {len(body_hashes)} 种不同响应体，"
                f"说明服务端对并发请求产生了不同结果（可能重复执行了操作）"
            )
        elif len(success_codes) == count and len(body_hashes) == 1:
            evidence = (
                f"所有 {count} 个请求都返回 200 且响应相同，"
                f"可能是幂等操作，需检查后端数据是否重复变化"
            )

        return {
            "total": count,
            "success_count": len(success_codes),
            "unique_bodies": len(body_hashes),
            "responses": responses,
            "likely_vulnerable": likely_vulnerable,
            "evidence": evidence,
        }

    # ─── 辅助方法 ─────────────────────────────────────────────

    async def _rate_limit_wait(self):
        """限速等待"""
        async with self._lock:
            if self.rate_limit <= 0:
                return
            min_interval = 1.0 / self.rate_limit
            elapsed = time.time() - self.last_request_time
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self.last_request_time = time.time()

    def _record_history(self, resp: HttpResponse):
        """记录请求历史"""
        self.history.append(resp)
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]

    def _compare_headers(self, baseline_headers: dict, resp_headers: dict) -> list:
        """对比 header 差异"""
        diffs = []
        security_headers = [
            "x-frame-options", "x-content-type-options",
            "content-security-policy", "set-cookie",
            "www-authenticate", "location",
        ]
        for h in security_headers:
            b_val = baseline_headers.get(h, "")
            r_val = resp_headers.get(h, "")
            if b_val != r_val:
                diffs.append({"header": h, "baseline": b_val, "current": r_val})
        return diffs

    def _detect_reflection_context(self, body: str, payload: str) -> str:
        """检测 payload 在响应体中的反射上下文"""
        idx = body.find(payload)
        if idx == -1:
            return "none"

        # 取前后 100 字符分析上下文
        context_before = body[max(0, idx - 100):idx]
        context_after = body[idx + len(payload):idx + len(payload) + 100]
        surrounding = context_before + payload + context_after

        # 判断上下文
        if re.search(r'<script[^>]*>', context_before, re.I) and '</script>' in context_after:
            return "js_block"
        elif re.search(r'=\s*["\']?$', context_before):
            return "html_attr"
        elif re.search(r'<\w+[^>]*$', context_before):
            return "html_tag"
        elif re.search(r'style\s*=', context_before, re.I):
            return "css"
        elif re.search(r'url\s*\(', context_before, re.I):
            return "url_context"
        elif re.search(r'on\w+\s*=', context_before, re.I):
            return "event_handler"
        else:
            return "html_body"

    def _calculate_anomaly_score(
        self, diff: DiffResult, baseline_jitter: int, time_jitter: float
    ) -> int:
        """
        计算异常评分 (0-100)
        分数越高越可能是注入点
        """
        score = 0

        # 状态码变化 (权重最高)
        if diff.status_diff:
            score += 35

        # 长度差异超过 baseline 抖动
        if diff.length_diff > baseline_jitter * 2 + 10:
            if diff.length_diff_percent > 20:
                score += 25
            elif diff.length_diff_percent > 5:
                score += 15
            else:
                score += 8

        # 时间差异 (可能是盲注)
        if diff.time_diff > time_jitter + 2.0:
            score += 30  # 超过 2 秒的额外延迟
        elif diff.time_diff > time_jitter + 0.5:
            score += 10

        # 反射检测
        if diff.reflected:
            score += 20
            if diff.reflection_context in ("js_block", "event_handler"):
                score += 15  # 危险上下文
            elif diff.reflection_context == "html_attr":
                score += 10
            elif diff.reflection_context == "html_body":
                score += 5

        # Header 差异
        if diff.header_diff:
            score += 5

        return min(100, score)

    # ─── 便捷方法 ─────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("PATCH", url, **kwargs)

    def get_stats(self) -> dict:
        """获取请求统计"""
        return {
            "total_requests": self.request_count,
            "history_size": len(self.history),
            "status_codes": self._count_status_codes(),
        }

    def _count_status_codes(self) -> dict:
        codes = {}
        for r in self.history:
            code = str(r.status_code)
            codes[code] = codes.get(code, 0) + 1
        return codes
