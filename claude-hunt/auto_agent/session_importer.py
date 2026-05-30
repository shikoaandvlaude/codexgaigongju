#!/usr/bin/env python3
"""
Session Importer — 登录态安全导入

解决问题：
- HackerOne 项目需要登录后测试，但工具不方便管理认证态
- 用户从浏览器/Burp 复制请求后，工具需要解析接口结构
- 敏感 token/cookie 不应长期保存，用完即焚

功能：
1. 从 Burp Suite 导出的 raw request 解析
2. 从浏览器 DevTools 复制的 cURL 命令解析
3. 从 HAR 文件导入
4. 自动提取：Cookie、Authorization、自定义 Header
5. 临时会话管理（TTL 过期自动清除）
6. 只提取接口结构（method/path/params），敏感值可脱敏

用法：
    from session_importer import SessionImporter

    si = SessionImporter()

    # 从 cURL 导入
    si.import_curl('curl -H "Authorization: Bearer xxx" https://api.syfe.com/me')

    # 从 Burp raw request 导入
    si.import_raw_request(raw_text)

    # 从 HAR 文件导入
    si.import_har("traffic.har")

    # 获取当前会话 headers
    headers = si.get_session_headers()

    # 获取提取的接口列表
    endpoints = si.get_endpoints()

    # 手动清除会话
    si.clear_session()

CLI:
    python session_importer.py --curl "curl ..."
    python session_importer.py --raw request.txt
    python session_importer.py --har traffic.har
    python session_importer.py --clear
"""

import json
import os
import re
import time
import hashlib
import shlex
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qs


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class ImportedEndpoint:
    """导入的接口信息"""
    method: str = "GET"
    url: str = ""
    path: str = ""
    host: str = ""
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    # 元数据
    source: str = ""           # curl/burp/har
    imported_at: str = ""
    notes: str = ""


@dataclass
class SessionData:
    """会话数据（临时存储）"""
    session_id: str = ""
    program_name: str = ""
    # 认证信息
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_header: str = ""      # Authorization header 值
    custom_headers: Dict[str, str] = field(default_factory=dict)
    # 提取的接口
    endpoints: List[ImportedEndpoint] = field(default_factory=list)
    # 生命周期
    created_at: str = ""
    expires_at: str = ""       # TTL 过期时间
    ttl_minutes: int = 120     # 默认 2 小时过期
    # 状态
    active: bool = True


# ═══════════════════════════════════════════════════════════════
# Session Importer
# ═══════════════════════════════════════════════════════════════

class SessionImporter:
    """登录态安全导入器"""

    def __init__(self, config: dict = None, program_name: str = ""):
        self.config = config or {}
        self.program_name = program_name
        self.session: SessionData = SessionData()
        self.sessions_dir = os.path.expanduser("~/.bai-agent/sessions")
        Path(self.sessions_dir).mkdir(parents=True, exist_ok=True)

        # 配置
        h1_config = self.config.get("h1_mode", {})
        self.default_ttl = h1_config.get("session_ttl_minutes", 120)
        self.auto_sanitize = h1_config.get("auto_sanitize_tokens", True)
        self.store_tokens = h1_config.get("store_tokens_locally", False)

        # 启动时清理过期会话
        self._cleanup_expired()

    # ═══════════════════════════════════════════════════════════
    # 导入方法
    # ═══════════════════════════════════════════════════════════

    def import_curl(self, curl_command: str) -> ImportedEndpoint:
        """
        从 cURL 命令导入请求
        支持从浏览器 DevTools → Copy as cURL 复制的命令
        """
        print("[*] 解析 cURL 命令...")

        endpoint = ImportedEndpoint(source="curl", imported_at=datetime.now().isoformat())

        # 清理多行
        curl_command = curl_command.replace("\\\n", " ").replace("\\\r\n", " ").strip()

        # 移除开头的 curl
        if curl_command.lower().startswith("curl"):
            curl_command = curl_command[4:].strip()

        try:
            tokens = shlex.split(curl_command)
        except ValueError:
            # shlex 解析失败，用简单分割
            tokens = curl_command.split()

        i = 0
        while i < len(tokens):
            token = tokens[i]

            if token in ("-X", "--request") and i + 1 < len(tokens):
                endpoint.method = tokens[i + 1].upper()
                i += 2
            elif token in ("-H", "--header") and i + 1 < len(tokens):
                header = tokens[i + 1]
                if ":" in header:
                    key, val = header.split(":", 1)
                    key, val = key.strip(), val.strip()
                    endpoint.headers[key] = val
                    # 提取认证信息
                    self._extract_auth_from_header(key, val)
                i += 2
            elif token in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(tokens):
                endpoint.body = tokens[i + 1]
                if endpoint.method == "GET":
                    endpoint.method = "POST"
                i += 2
            elif token in ("-b", "--cookie") and i + 1 < len(tokens):
                self._parse_cookie_string(tokens[i + 1])
                i += 2
            elif token.startswith("http"):
                endpoint.url = token.strip("'\"")
                parsed = urlparse(endpoint.url)
                endpoint.host = parsed.netloc
                endpoint.path = parsed.path
                endpoint.params = {k: v[0] if len(v) == 1 else v
                                   for k, v in parse_qs(parsed.query).items()}
                i += 1
            else:
                i += 1

        # 从 headers 中提取 content-type
        for k, v in endpoint.headers.items():
            if k.lower() == "content-type":
                endpoint.content_type = v
            elif k.lower() == "cookie":
                self._parse_cookie_string(v)

        self.session.endpoints.append(endpoint)
        self._activate_session()

        print(f"  [+] 导入成功: {endpoint.method} {endpoint.path}")
        print(f"      Host: {endpoint.host}")
        print(f"      Params: {len(endpoint.params)} 个")
        if self.session.auth_header:
            print(f"      Auth: {self._mask_token(self.session.auth_header)}")
        if self.session.cookies:
            print(f"      Cookies: {len(self.session.cookies)} 个")

        return endpoint

    def import_raw_request(self, raw: str) -> ImportedEndpoint:
        """
        从 Burp Suite raw request 导入
        格式：
            GET /api/users HTTP/1.1
            Host: api.example.com
            Cookie: session=abc123
            Authorization: Bearer xxx

            {"key": "value"}
        """
        print("[*] 解析 Burp raw request...")

        endpoint = ImportedEndpoint(source="burp", imported_at=datetime.now().isoformat())

        lines = raw.strip().split("\n")
        if not lines:
            print("[!] 空请求")
            return endpoint

        # 第一行：方法 路径 协议
        first_line = lines[0].strip()
        parts = first_line.split()
        if len(parts) >= 2:
            endpoint.method = parts[0].upper()
            path_with_params = parts[1]
            if "?" in path_with_params:
                endpoint.path, query = path_with_params.split("?", 1)
                endpoint.params = {k: v[0] if len(v) == 1 else v
                                   for k, v in parse_qs(query).items()}
            else:
                endpoint.path = path_with_params

        # 解析 headers（到空行为止）
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                body_start = i + 1
                break
            if ":" in line:
                key, val = line.split(":", 1)
                key, val = key.strip(), val.strip()
                endpoint.headers[key] = val
                self._extract_auth_from_header(key, val)

                if key.lower() == "host":
                    endpoint.host = val
                elif key.lower() == "content-type":
                    endpoint.content_type = val
                elif key.lower() == "cookie":
                    self._parse_cookie_string(val)

        # Body
        if body_start < len(lines):
            endpoint.body = "\n".join(lines[body_start:]).strip()

        # 构造完整 URL
        scheme = "https"
        endpoint.url = f"{scheme}://{endpoint.host}{endpoint.path}"

        self.session.endpoints.append(endpoint)
        self._activate_session()

        print(f"  [+] 导入成功: {endpoint.method} {endpoint.path}")
        print(f"      Host: {endpoint.host}")
        if self.session.auth_header:
            print(f"      Auth: {self._mask_token(self.session.auth_header)}")

        return endpoint

    def import_har(self, har_path: str, filter_host: str = "") -> List[ImportedEndpoint]:
        """
        从 HAR 文件导入（浏览器 DevTools → Network → Export HAR）
        """
        print(f"[*] 解析 HAR 文件: {har_path}")

        if not os.path.exists(har_path):
            print(f"[!] 文件不存在: {har_path}")
            return []

        with open(har_path, "r", encoding="utf-8") as f:
            har = json.load(f)

        entries = har.get("log", {}).get("entries", [])
        imported = []

        for entry in entries:
            request = entry.get("request", {})
            url = request.get("url", "")

            # 过滤
            if filter_host:
                parsed = urlparse(url)
                if filter_host.lower() not in parsed.netloc.lower():
                    continue

            # 跳过静态资源
            if any(url.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".woff"]):
                continue

            endpoint = ImportedEndpoint(
                source="har",
                imported_at=datetime.now().isoformat(),
                method=request.get("method", "GET"),
                url=url,
            )

            parsed = urlparse(url)
            endpoint.host = parsed.netloc
            endpoint.path = parsed.path
            endpoint.params = {k: v[0] if len(v) == 1 else v
                               for k, v in parse_qs(parsed.query).items()}

            # Headers
            for h in request.get("headers", []):
                name, value = h.get("name", ""), h.get("value", "")
                endpoint.headers[name] = value
                self._extract_auth_from_header(name, value)
                if name.lower() == "cookie":
                    self._parse_cookie_string(value)
                elif name.lower() == "content-type":
                    endpoint.content_type = value

            # Body
            post_data = request.get("postData", {})
            if post_data:
                endpoint.body = post_data.get("text", "")
                if not endpoint.content_type:
                    endpoint.content_type = post_data.get("mimeType", "")

            self.session.endpoints.append(endpoint)
            imported.append(endpoint)

        self._activate_session()
        print(f"  [+] 导入 {len(imported)} 个接口")

        # 按 host 分组显示
        hosts = {}
        for ep in imported:
            hosts.setdefault(ep.host, []).append(ep)
        for host, eps in hosts.items():
            print(f"      {host}: {len(eps)} 个接口")

        return imported

    # ═══════════════════════════════════════════════════════════
    # 会话管理
    # ═══════════════════════════════════════════════════════════

    def get_session_headers(self) -> Dict[str, str]:
        """获取当前会话的认证 headers（供其他模块使用）"""
        if not self.session.active:
            print("[!] 会话已过期，请重新导入")
            return {}

        if self._is_expired():
            self.clear_session()
            print("[!] 会话已过期（TTL），已自动清除")
            return {}

        headers = dict(self.session.custom_headers)
        if self.session.auth_header:
            headers["Authorization"] = self.session.auth_header
        if self.session.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())
            headers["Cookie"] = cookie_str
        return headers

    def get_endpoints(self) -> List[ImportedEndpoint]:
        """获取导入的接口列表"""
        return self.session.endpoints

    def get_endpoints_summary(self) -> str:
        """获取接口摘要（脱敏）"""
        lines = ["\n导入的接口列表:\n"]
        for i, ep in enumerate(self.session.endpoints, 1):
            params_str = f" ?{len(ep.params)}个参数" if ep.params else ""
            lines.append(f"  {i:3d}. {ep.method:6s} {ep.host}{ep.path}{params_str}")
        return "\n".join(lines)

    def clear_session(self):
        """清除当前会话（安全擦除）"""
        # 覆写敏感数据
        self.session.auth_header = ""
        self.session.cookies = {}
        self.session.custom_headers = {}
        self.session.active = False

        # 删除本地缓存文件
        session_file = os.path.join(self.sessions_dir, f"{self.session.session_id}.json")
        if os.path.exists(session_file):
            os.remove(session_file)

        print("[+] 会话已安全清除")

    def extend_session(self, minutes: int = 60):
        """延长会话有效期"""
        if self.session.active:
            new_expires = datetime.now() + timedelta(minutes=minutes)
            self.session.expires_at = new_expires.isoformat()
            print(f"[+] 会话延长 {minutes} 分钟，至 {self.session.expires_at[:16]}")

    # ═══════════════════════════════════════════════════════════
    # 内部方法
    # ═══════════════════════════════════════════════════════════

    def _activate_session(self):
        """激活会话"""
        if not self.session.session_id:
            self.session.session_id = hashlib.md5(
                f"{time.time()}_{self.program_name}".encode()
            ).hexdigest()[:12]
            self.session.program_name = self.program_name
            self.session.created_at = datetime.now().isoformat()
            self.session.expires_at = (
                datetime.now() + timedelta(minutes=self.default_ttl)
            ).isoformat()
            self.session.active = True

        # 如果配置允许本地存储
        if self.store_tokens:
            self._save_session()

    def _is_expired(self) -> bool:
        """检查会话是否过期"""
        if not self.session.expires_at:
            return False
        try:
            expires = datetime.fromisoformat(self.session.expires_at)
            return datetime.now() > expires
        except (ValueError, TypeError):
            return False

    def _extract_auth_from_header(self, key: str, value: str):
        """从 header 中提取认证信息"""
        key_lower = key.lower()
        if key_lower == "authorization":
            self.session.auth_header = value
        elif key_lower in ("x-api-key", "x-auth-token", "x-access-token",
                           "x-csrf-token", "x-xsrf-token"):
            self.session.custom_headers[key] = value

    def _parse_cookie_string(self, cookie_str: str):
        """解析 Cookie 字符串"""
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                key, val = pair.split("=", 1)
                self.session.cookies[key.strip()] = val.strip()

    def _mask_token(self, token: str) -> str:
        """脱敏 token 显示"""
        if len(token) <= 10:
            return "***"
        return f"{token[:8]}...{token[-4:]}"

    def _save_session(self):
        """保存会话到本地（加密建议后续加）"""
        path = os.path.join(self.sessions_dir, f"{self.session.session_id}.json")
        from dataclasses import asdict
        data = asdict(self.session)

        # 如果不允许存 token，脱敏处理
        if not self.store_tokens:
            data["auth_header"] = self._mask_token(data.get("auth_header", ""))
            data["cookies"] = {k: "***" for k in data.get("cookies", {})}

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _cleanup_expired(self):
        """清理过期会话文件"""
        if not os.path.exists(self.sessions_dir):
            return
        for fname in os.listdir(self.sessions_dir):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(self.sessions_dir, fname)
            try:
                with open(fpath, "r") as f:
                    data = json.load(f)
                expires = data.get("expires_at", "")
                if expires and datetime.now() > datetime.fromisoformat(expires):
                    os.remove(fpath)
            except (json.JSONDecodeError, ValueError, OSError):
                pass


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="登录态安全导入工具")
    parser.add_argument("--curl", help="从 cURL 命令导入")
    parser.add_argument("--raw", help="从 Burp raw request 文件导入")
    parser.add_argument("--har", help="从 HAR 文件导入")
    parser.add_argument("--filter", help="HAR 导入时过滤 host")
    parser.add_argument("--clear", action="store_true", help="清除所有会话")
    parser.add_argument("--status", action="store_true", help="显示当前会话状态")
    args = parser.parse_args()

    si = SessionImporter()

    if args.curl:
        si.import_curl(args.curl)
        print(si.get_endpoints_summary())
    elif args.raw:
        with open(args.raw, "r", encoding="utf-8") as f:
            raw_text = f.read()
        si.import_raw_request(raw_text)
        print(si.get_endpoints_summary())
    elif args.har:
        si.import_har(args.har, filter_host=args.filter or "")
        print(si.get_endpoints_summary())
    elif args.clear:
        si.clear_session()
    elif args.status:
        if si.session.active:
            print(f"\n会话状态: 活跃")
            print(f"  ID: {si.session.session_id}")
            print(f"  过期时间: {si.session.expires_at[:16]}")
            print(f"  接口数: {len(si.session.endpoints)}")
        else:
            print("\n无活跃会话")
    else:
        parser.print_help()
