#!/usr/bin/env python3
"""
Auth Manager — Token/Session 自动刷新管理器
解决黑盒测试中 session 过期导致整个流程中断的问题

支持的认证方式：
1. Cookie Session — 检测过期后自动重新登录
2. JWT Token — 检测 exp 字段，过期前自动 refresh
3. OAuth2 — 用 refresh_token 自动换新 access_token
4. API Key — 静态 key，不需要刷新（仅管理）
5. 自定义 Header — 如 X-Auth-Token

用法:
    auth = AuthManager(config={
        "type": "cookie",  # cookie/jwt/oauth2/apikey/custom
        "login_url": "https://target.com/api/login",
        "login_body": {"username": "test", "password": "pass123"},
        "session_cookie_name": "PHPSESSID",
        "check_url": "https://target.com/api/me",  # 验证登录态的URL
    })
    
    # 获取当前有效的认证信息
    headers, cookies = await auth.get_auth()
    
    # 手动触发刷新
    await auth.refresh()
    
    # 包装请求（自动处理认证）
    resp = await auth.authenticated_request(http_engine, "GET", url)
"""

import asyncio
import time
import json
import base64
import hashlib
from typing import Optional, Tuple
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class AuthState:
    """认证状态"""
    auth_type: str = ""           # cookie/jwt/oauth2/apikey/custom
    is_valid: bool = False
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    access_token: str = ""
    refresh_token: str = ""
    token_expires_at: float = 0.0  # Unix timestamp
    last_refresh: float = 0.0
    refresh_count: int = 0
    last_check: float = 0.0


# ═══════════════════════════════════════════════════════════════
# Auth Manager
# ═══════════════════════════════════════════════════════════════

class AuthManager:
    """
    Token/Session 自动刷新管理器
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.auth_type = self.config.get("type", "cookie")
        
        # 通用配置
        self.check_url = self.config.get("check_url", "")
        self.check_keyword = self.config.get("check_keyword", "")
        self.check_interval = self.config.get("check_interval", 60)  # 秒
        self.max_refresh_attempts = self.config.get("max_refresh_attempts", 3)
        
        # Cookie/Session 登录配置
        self.login_url = self.config.get("login_url", "")
        self.login_body = self.config.get("login_body", {})
        self.login_method = self.config.get("login_method", "POST")
        self.login_content_type = self.config.get("login_content_type", "json")
        self.session_cookie_name = self.config.get("session_cookie_name", "")
        self.csrf_url = self.config.get("csrf_url", "")
        self.csrf_field = self.config.get("csrf_field", "_token")
        
        # JWT 配置
        self.jwt_refresh_url = self.config.get("jwt_refresh_url", "")
        self.jwt_header_name = self.config.get("jwt_header_name", "Authorization")
        self.jwt_header_prefix = self.config.get("jwt_header_prefix", "Bearer ")
        self.jwt_refresh_before_exp = self.config.get("jwt_refresh_before_exp", 60)  # 过期前N秒刷新
        
        # OAuth2 配置
        self.oauth2_token_url = self.config.get("oauth2_token_url", "")
        self.oauth2_client_id = self.config.get("oauth2_client_id", "")
        self.oauth2_client_secret = self.config.get("oauth2_client_secret", "")
        self.oauth2_scope = self.config.get("oauth2_scope", "")
        
        # API Key 配置
        self.api_key = self.config.get("api_key", "")
        self.api_key_header = self.config.get("api_key_header", "X-API-Key")
        
        # 自定义 Header
        self.custom_headers = self.config.get("custom_headers", {})
        
        # 初始 Cookie（手动提供的）
        self.initial_cookies = self.config.get("cookies", {})
        
        # 状态
        self.state = AuthState(auth_type=self.auth_type)
        self._http = None  # 延迟绑定
        
        # 加载初始认证信息
        self._load_initial_auth()

    def _load_initial_auth(self):
        """加载初始认证信息"""
        if self.auth_type == "cookie" and self.initial_cookies:
            self.state.cookies = dict(self.initial_cookies)
            self.state.is_valid = True
        elif self.auth_type == "jwt" and self.config.get("access_token"):
            self.state.access_token = self.config["access_token"]
            self.state.refresh_token = self.config.get("refresh_token", "")
            self.state.headers = {
                self.jwt_header_name: f"{self.jwt_header_prefix}{self.state.access_token}"
            }
            self.state.is_valid = True
            self._parse_jwt_expiry()
        elif self.auth_type == "oauth2" and self.config.get("access_token"):
            self.state.access_token = self.config["access_token"]
            self.state.refresh_token = self.config.get("refresh_token", "")
            self.state.headers = {"Authorization": f"Bearer {self.state.access_token}"}
            self.state.is_valid = True
        elif self.auth_type == "apikey" and self.api_key:
            self.state.headers = {self.api_key_header: self.api_key}
            self.state.is_valid = True
        elif self.auth_type == "custom" and self.custom_headers:
            self.state.headers = dict(self.custom_headers)
            self.state.is_valid = True

    def bind_http_engine(self, http_engine):
        """绑定 HTTP 引擎"""
        self._http = http_engine

    # ─── 主接口 ────────────────────────────────────────────────

    async def get_auth(self) -> Tuple[dict, dict]:
        """
        获取当前有效的认证信息
        如果过期会自动刷新
        
        返回: (headers_dict, cookies_dict)
        """
        # 检查是否需要刷新
        if await self._needs_refresh():
            await self.refresh()

        return dict(self.state.headers), dict(self.state.cookies)

    async def refresh(self) -> bool:
        """
        手动触发认证刷新
        返回是否成功
        """
        if not self._http:
            return False

        if self.state.refresh_count >= self.max_refresh_attempts:
            return False

        success = False

        if self.auth_type == "cookie":
            success = await self._refresh_cookie_session()
        elif self.auth_type == "jwt":
            success = await self._refresh_jwt()
        elif self.auth_type == "oauth2":
            success = await self._refresh_oauth2()
        elif self.auth_type in ("apikey", "custom"):
            success = True  # 不需要刷新

        if success:
            self.state.is_valid = True
            self.state.last_refresh = time.time()
            self.state.refresh_count += 1
        else:
            self.state.is_valid = False

        return success

    async def check_validity(self) -> bool:
        """主动检查当前认证是否有效"""
        if not self._http or not self.check_url:
            return self.state.is_valid

        resp = await self._http.request(
            "GET", self.check_url,
            headers=self.state.headers,
            cookies=self.state.cookies,
        )

        if resp.status_code in (401, 403, 302):
            self.state.is_valid = False
            return False

        if resp.status_code == 200:
            if self.check_keyword:
                self.state.is_valid = self.check_keyword in resp.body
            else:
                self.state.is_valid = True
            self.state.last_check = time.time()

        return self.state.is_valid

    async def authenticated_request(self, http_engine, method: str, url: str, **kwargs):
        """
        带自动认证的请求
        如果 401/403 会自动重试一次
        """
        self._http = http_engine
        headers, cookies = await self.get_auth()

        # 合并用户提供的 headers
        req_headers = {**headers, **(kwargs.pop("headers", {}))}
        req_cookies = {**cookies, **(kwargs.pop("cookies", {}))}

        resp = await http_engine.request(
            method, url, headers=req_headers, cookies=req_cookies, **kwargs
        )

        # 如果 401/403，刷新后重试一次
        if resp.status_code in (401, 403):
            refreshed = await self.refresh()
            if refreshed:
                headers, cookies = await self.get_auth()
                req_headers = {**headers, **(kwargs.pop("headers", {}) if "headers" in kwargs else {})}
                req_cookies = {**cookies, **(kwargs.pop("cookies", {}) if "cookies" in kwargs else {})}
                resp = await http_engine.request(
                    method, url, headers=req_headers, cookies=req_cookies, **kwargs
                )

        return resp

    # ─── 刷新实现 ──────────────────────────────────────────────

    async def _refresh_cookie_session(self) -> bool:
        """Cookie/Session 刷新 — 重新登录"""
        if not self.login_url or not self.login_body:
            return False

        try:
            # 如果有 CSRF token，先获取
            csrf_token = ""
            if self.csrf_url:
                csrf_resp = await self._http.request("GET", self.csrf_url)
                if csrf_resp.status_code == 200:
                    # 尝试从响应中提取 CSRF token
                    import re
                    csrf_match = re.search(
                        rf'name=["\']?{re.escape(self.csrf_field)}["\']?\s+value=["\']([^"\']+)',
                        csrf_resp.body
                    )
                    if csrf_match:
                        csrf_token = csrf_match.group(1)

            # 构建登录请求
            login_data = dict(self.login_body)
            if csrf_token:
                login_data[self.csrf_field] = csrf_token

            if self.login_content_type == "json":
                resp = await self._http.request(
                    self.login_method, self.login_url,
                    json_data=login_data,
                )
            else:
                resp = await self._http.request(
                    self.login_method, self.login_url,
                    data=login_data,
                )

            # 检查登录是否成功
            if resp.status_code in (200, 201, 302):
                # 从响应头中提取 Set-Cookie
                set_cookies = resp.headers.get("set-cookie", "")
                if set_cookies:
                    self._parse_set_cookie(set_cookies)
                    return True

                # 从响应体中提取 token
                if resp.body:
                    try:
                        data = json.loads(resp.body)
                        token = (data.get("token") or data.get("access_token")
                                or data.get("session_id") or data.get("sessionId"))
                        if token:
                            if self.session_cookie_name:
                                self.state.cookies[self.session_cookie_name] = token
                            else:
                                self.state.headers["Authorization"] = f"Bearer {token}"
                            return True
                    except json.JSONDecodeError:
                        pass

            return False

        except Exception:
            return False

    async def _refresh_jwt(self) -> bool:
        """JWT Token 刷新"""
        if not self.jwt_refresh_url or not self.state.refresh_token:
            # 没有 refresh_token，尝试重新登录
            return await self._refresh_cookie_session()

        try:
            resp = await self._http.request(
                "POST", self.jwt_refresh_url,
                json_data={"refresh_token": self.state.refresh_token},
                headers={"Authorization": f"{self.jwt_header_prefix}{self.state.access_token}"},
            )

            if resp.status_code == 200 and resp.body:
                data = json.loads(resp.body)
                new_token = data.get("access_token") or data.get("token")
                if new_token:
                    self.state.access_token = new_token
                    self.state.headers[self.jwt_header_name] = f"{self.jwt_header_prefix}{new_token}"
                    if data.get("refresh_token"):
                        self.state.refresh_token = data["refresh_token"]
                    self._parse_jwt_expiry()
                    return True

            return False

        except Exception:
            return False

    async def _refresh_oauth2(self) -> bool:
        """OAuth2 Token 刷新"""
        if not self.oauth2_token_url or not self.state.refresh_token:
            return False

        try:
            token_data = {
                "grant_type": "refresh_token",
                "refresh_token": self.state.refresh_token,
                "client_id": self.oauth2_client_id,
            }
            if self.oauth2_client_secret:
                token_data["client_secret"] = self.oauth2_client_secret

            resp = await self._http.request(
                "POST", self.oauth2_token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if resp.status_code == 200 and resp.body:
                data = json.loads(resp.body)
                new_token = data.get("access_token")
                if new_token:
                    self.state.access_token = new_token
                    self.state.headers["Authorization"] = f"Bearer {new_token}"
                    if data.get("refresh_token"):
                        self.state.refresh_token = data["refresh_token"]
                    if data.get("expires_in"):
                        self.state.token_expires_at = time.time() + int(data["expires_in"])
                    return True

            return False

        except Exception:
            return False

    # ─── 辅助方法 ──────────────────────────────────────────────

    async def _needs_refresh(self) -> bool:
        """判断是否需要刷新"""
        if not self.state.is_valid:
            return True

        # JWT: 检查 exp
        if self.auth_type == "jwt" and self.state.token_expires_at:
            if time.time() >= self.state.token_expires_at - self.jwt_refresh_before_exp:
                return True

        # OAuth2: 检查 exp
        if self.auth_type == "oauth2" and self.state.token_expires_at:
            if time.time() >= self.state.token_expires_at - 60:
                return True

        # 定期检查（所有类型）
        if self.check_url and self._http:
            if time.time() - self.state.last_check >= self.check_interval:
                return not await self.check_validity()

        return False

    def _parse_jwt_expiry(self):
        """从 JWT 中解析过期时间"""
        token = self.state.access_token
        if not token:
            return

        try:
            # JWT: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                return

            # 解码 payload
            payload = parts[1]
            # 补齐 padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)

            if "exp" in data:
                self.state.token_expires_at = float(data["exp"])
        except Exception:
            pass

    def _parse_set_cookie(self, set_cookie_header: str):
        """解析 Set-Cookie 响应头"""
        # 简单解析，取第一个 name=value
        for cookie_str in set_cookie_header.split(","):
            cookie_str = cookie_str.strip()
            if "=" in cookie_str:
                parts = cookie_str.split(";")[0]  # 只取 name=value 部分
                name, _, value = parts.partition("=")
                name = name.strip()
                value = value.strip()
                if name and not name.lower() in ("path", "domain", "expires", "max-age", "secure", "httponly", "samesite"):
                    self.state.cookies[name] = value

    def get_state_summary(self) -> dict:
        """获取认证状态摘要"""
        return {
            "type": self.auth_type,
            "is_valid": self.state.is_valid,
            "has_cookies": bool(self.state.cookies),
            "has_headers": bool(self.state.headers),
            "has_access_token": bool(self.state.access_token),
            "has_refresh_token": bool(self.state.refresh_token),
            "token_expires_at": self.state.token_expires_at,
            "refresh_count": self.state.refresh_count,
            "last_refresh": self.state.last_refresh,
        }
