#!/usr/bin/env python3
"""
Fiddler MCP Server
让 Claude Code 能够读取和操作 Fiddler 的抓包数据。

工作原理：
  Fiddler 可以把抓包数据导出为 SAZ 文件（本质是 zip）或者通过
  Fiddler 的 CustomRules 脚本自动把请求/响应保存到指定目录。

  本 MCP Server 读取这些导出的数据，供 Claude Code 分析。

配置方式：
  1. Fiddler 中设置自动导出：
     Rules → Customize Rules → 在 OnBeforeResponse 中添加保存逻辑
     或者手动导出 SAZ: File → Save → All Sessions → xxx.saz

  2. 配置 FIDDLER_EXPORT_DIR 环境变量指向导出目录

  3. 在 Claude Code settings 中配置本 MCP Server

使用：
  python3 server.py

Claude Code 配置 (~/.claude/settings.json):
  {
    "mcpServers": {
      "fiddler": {
        "command": "python3",
        "args": ["/path/to/fiddler-mcp/server.py"],
        "env": {
          "FIDDLER_EXPORT_DIR": "C:/Users/你的用户名/Documents/Fiddler2/Captures"
        }
      }
    }
  }
"""

import json
import os
import sys
import zipfile
import re
from pathlib import Path
from datetime import datetime

# MCP 协议通信（stdin/stdout JSON-RPC）
def send_response(id, result):
    msg = {"jsonrpc": "2.0", "id": id, "result": result}
    out = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(out.encode())}\r\n\r\n{out}")
    sys.stdout.flush()

def send_error(id, code, message):
    msg = {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}
    out = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(out.encode())}\r\n\r\n{out}")
    sys.stdout.flush()

# Fiddler SAZ 解析
class FiddlerParser:
    def __init__(self, export_dir=None):
        self.export_dir = Path(export_dir or os.environ.get(
            "FIDDLER_EXPORT_DIR",
            os.path.expanduser("~/Documents/Fiddler2/Captures")
        ))

    def list_captures(self, limit=20):
        """列出最近的抓包文件"""
        captures = []
        if not self.export_dir.exists():
            return captures

        # SAZ 文件
        for f in sorted(self.export_dir.glob("*.saz"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
            captures.append({
                "file": str(f),
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                "type": "saz"
            })

        # 文本导出的请求文件
        for f in sorted(self.export_dir.glob("*.txt"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
            captures.append({
                "file": str(f),
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                "type": "txt"
            })

        return captures[:limit]

    def parse_saz(self, saz_path, limit=50):
        """解析 SAZ 文件（Fiddler 的抓包存档格式）"""
        sessions = []
        try:
            with zipfile.ZipFile(saz_path, 'r') as z:
                # SAZ 内部结构: raw/0001_c.txt (request), raw/0001_s.txt (response)
                request_files = sorted([f for f in z.namelist() if f.endswith('_c.txt')])

                for req_file in request_files[:limit]:
                    session_num = req_file.split('/')[-1].replace('_c.txt', '')
                    resp_file = req_file.replace('_c.txt', '_s.txt')

                    request_raw = z.read(req_file).decode('utf-8', errors='replace')
                    response_raw = ""
                    if resp_file in z.namelist():
                        response_raw = z.read(resp_file).decode('utf-8', errors='replace')

                    # 解析请求行
                    req_lines = request_raw.split('\r\n')
                    method_line = req_lines[0] if req_lines else ""
                    parts = method_line.split(' ')
                    method = parts[0] if len(parts) >= 1 else "?"
                    url = parts[1] if len(parts) >= 2 else "?"
                    host = ""
                    for line in req_lines[1:]:
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            break

                    # 解析响应状态
                    resp_lines = response_raw.split('\r\n')
                    status_line = resp_lines[0] if resp_lines else ""
                    status_match = re.search(r'(\d{3})', status_line)
                    status_code = int(status_match.group(1)) if status_match else 0

                    sessions.append({
                        "id": session_num,
                        "method": method,
                        "url": url,
                        "host": host,
                        "status": status_code,
                        "request": request_raw[:2000],  # 限制大小
                        "response_headers": '\r\n'.join(resp_lines[:20]),
                        "response_body_preview": '\r\n'.join(resp_lines[resp_lines.index('') + 1:][:30]) if '' in resp_lines else ""
                    })
        except Exception as e:
            return {"error": str(e)}

        return sessions

    def search_params(self, saz_path, param_names=None):
        """搜索抓包中包含指定参数的请求"""
        sessions = self.parse_saz(saz_path)
        if isinstance(sessions, dict) and "error" in sessions:
            return sessions

        if not param_names:
            param_names = ["price", "amount", "qty", "id", "userId", "token", "code", "phone"]

        results = []
        for session in sessions:
            req = session.get("request", "")
            matched_params = []
            for param in param_names:
                if param.lower() in req.lower():
                    matched_params.append(param)
            if matched_params:
                results.append({
                    **session,
                    "matched_params": matched_params
                })

        return results

    def find_api_endpoints(self, saz_path):
        """从抓包中提取所有 API 端点"""
        sessions = self.parse_saz(saz_path)
        if isinstance(sessions, dict) and "error" in sessions:
            return sessions

        endpoints = {}
        for session in sessions:
            url = session.get("url", "")
            method = session.get("method", "")
            # 去掉查询参数
            base_url = url.split("?")[0]
            key = f"{method} {base_url}"
            if key not in endpoints:
                endpoints[key] = {
                    "method": method,
                    "url": base_url,
                    "host": session.get("host", ""),
                    "status_codes": [],
                    "count": 0
                }
            endpoints[key]["status_codes"].append(session.get("status", 0))
            endpoints[key]["count"] += 1

        # 去重 status_codes
        for ep in endpoints.values():
            ep["status_codes"] = list(set(ep["status_codes"]))

        return list(endpoints.values())

    def find_sensitive_data(self, saz_path):
        """搜索抓包中的敏感信息泄露"""
        sessions = self.parse_saz(saz_path)
        if isinstance(sessions, dict) and "error" in sessions:
            return sessions

        patterns = {
            "api_key": r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})',
            "token": r'(?:token|access_token|auth_token)["\s:=]+["\']?([a-zA-Z0-9_\-\.]{16,})',
            "password": r'(?:password|passwd|pwd)["\s:=]+["\']?([^\s"\'&]{4,})',
            "phone": r'\b1[3-9]\d{9}\b',
            "id_card": r'\b\d{17}[\dXx]\b',
            "email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            "jwt": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            "verification_code": r'(?:code|captcha|verify_code|sms_code)["\s:=]+["\']?(\d{4,6})'
        }

        findings = []
        for session in sessions:
            full_text = session.get("request", "") + session.get("response_body_preview", "")
            for pattern_name, regex in patterns.items():
                matches = re.findall(regex, full_text, re.IGNORECASE)
                if matches:
                    findings.append({
                        "session_id": session.get("id"),
                        "url": session.get("url"),
                        "type": pattern_name,
                        "matches": matches[:5],  # 最多5个
                        "risk": "high" if pattern_name in ("api_key", "password", "jwt", "verification_code") else "medium"
                    })

        return findings


# MCP 工具定义
TOOLS = [
    {
        "name": "fiddler_list_captures",
        "description": "列出 Fiddler 导出目录中最近的抓包文件",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "最大返回数量", "default": 20}
            }
        }
    },
    {
        "name": "fiddler_parse_saz",
        "description": "解析 Fiddler SAZ 抓包文件，提取所有 HTTP 请求/响应",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "SAZ 文件路径"},
                "limit": {"type": "integer", "description": "最大会话数", "default": 50}
            },
            "required": ["file"]
        }
    },
    {
        "name": "fiddler_search_params",
        "description": "搜索抓包中包含指定参数的请求（用于找注入点）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "SAZ 文件路径"},
                "params": {"type": "array", "items": {"type": "string"}, "description": "要搜索的参数名列表"}
            },
            "required": ["file"]
        }
    },
    {
        "name": "fiddler_find_endpoints",
        "description": "从抓包中提取所有 API 端点（去重统计）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "SAZ 文件路径"}
            },
            "required": ["file"]
        }
    },
    {
        "name": "fiddler_find_sensitive",
        "description": "搜索抓包中的敏感信息泄露（API Key、Token、手机号、验证码等）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "SAZ 文件路径"}
            },
            "required": ["file"]
        }
    }
]


def handle_request(request):
    """处理 MCP JSON-RPC 请求"""
    method = request.get("method", "")
    id = request.get("id")
    params = request.get("params", {})

    parser = FiddlerParser()

    if method == "initialize":
        send_response(id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fiddler-mcp", "version": "1.0.0"}
        })

    elif method == "tools/list":
        send_response(id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        try:
            if tool_name == "fiddler_list_captures":
                result = parser.list_captures(limit=args.get("limit", 20))
            elif tool_name == "fiddler_parse_saz":
                result = parser.parse_saz(args["file"], limit=args.get("limit", 50))
            elif tool_name == "fiddler_search_params":
                result = parser.search_params(args["file"], param_names=args.get("params"))
            elif tool_name == "fiddler_find_endpoints":
                result = parser.find_api_endpoints(args["file"])
            elif tool_name == "fiddler_find_sensitive":
                result = parser.find_sensitive_data(args["file"])
            else:
                send_error(id, -32601, f"Unknown tool: {tool_name}")
                return

            send_response(id, {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]
            })
        except Exception as e:
            send_response(id, {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True
            })

    elif method == "notifications/initialized":
        pass  # 无需响应

    else:
        if id is not None:
            send_error(id, -32601, f"Unknown method: {method}")


def main():
    """主循环 - 读取 stdin JSON-RPC 消息"""
    buffer = ""
    content_length = 0

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            buffer += line

            # 解析 Content-Length header
            if line.startswith("Content-Length:"):
                content_length = int(line.split(":")[1].strip())
                continue

            # 空行表示 header 结束，接下来读 body
            if line.strip() == "" and content_length > 0:
                body = sys.stdin.read(content_length)
                content_length = 0
                buffer = ""

                try:
                    request = json.loads(body)
                    handle_request(request)
                except json.JSONDecodeError:
                    pass

        except EOFError:
            break
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
