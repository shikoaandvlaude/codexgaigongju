#!/usr/bin/env python3
"""
RedOps MCP Server
让 Claude Code 能够调用 RedOps Agent 执行渗透测试任务。

RedOps 需要先启动: python redops/main.py (默认 localhost:8000)
本 MCP Server 通过 HTTP API 调用 RedOps。

Claude Code 配置 (~/.claude/settings.json):
  {
    "mcpServers": {
      "redops": {
        "command": "python3",
        "args": ["/path/to/redops-mcp/server.py"],
        "env": {
          "REDOPS_URL": "http://localhost:8000"
        }
      }
    }
  }
"""

import json
import os
import sys
import urllib.request
import urllib.error

REDOPS_URL = os.environ.get("REDOPS_URL", "http://localhost:8000")


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


def call_redops(endpoint, method="GET", data=None):
    """调用 RedOps API"""
    url = f"{REDOPS_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}

    if data:
        req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:200]}"}
    except urllib.error.URLError as e:
        return {"error": f"连接失败: {e.reason}. 请确认 RedOps 已启动 (python redops/main.py)"}
    except Exception as e:
        return {"error": str(e)}


TOOLS = [
    {
        "name": "redops_chat",
        "description": "向 RedOps Agent 发送自然语言指令（如：扫描目标、执行命令、分析结果）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "自然语言指令"},
                "session_id": {"type": "string", "description": "会话ID（可选，用于多轮对话）"}
            },
            "required": ["message"]
        }
    },
    {
        "name": "redops_scan",
        "description": "使用 RedOps 对目标执行漏洞扫描（Nuclei）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标URL或IP"},
                "scan_type": {"type": "string", "description": "扫描类型: full/quick/cve", "default": "quick"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "redops_exec",
        "description": "通过 RedOps 执行系统命令（nmap/dig/curl等）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的命令"}
            },
            "required": ["command"]
        }
    },
    {
        "name": "redops_fofa",
        "description": "通过 RedOps 使用 FOFA 搜索资产",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "FOFA 搜索语法"},
                "size": {"type": "integer", "description": "结果数量", "default": 10}
            },
            "required": ["query"]
        }
    },
    {
        "name": "redops_targets",
        "description": "管理 RedOps 渗透目标（列出/添加）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "操作: list/add", "default": "list"},
                "target": {"type": "string", "description": "添加目标时的URL/IP"}
            }
        }
    },
    {
        "name": "redops_status",
        "description": "查看 RedOps Agent 状态和当前任务",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]


def handle_request(request):
    method = request.get("method", "")
    id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        send_response(id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "redops-mcp", "version": "1.0.0"}
        })

    elif method == "tools/list":
        send_response(id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        try:
            if tool_name == "redops_chat":
                result = call_redops("/api/chat", "POST", {
                    "message": args["message"],
                    "session_id": args.get("session_id", "mcp-session")
                })

            elif tool_name == "redops_scan":
                result = call_redops("/api/scan/start", "POST", {
                    "target": args["target"],
                    "scan_type": args.get("scan_type", "quick")
                })

            elif tool_name == "redops_exec":
                result = call_redops("/api/chat", "POST", {
                    "message": f"执行命令: {args['command']}",
                    "session_id": "mcp-exec"
                })

            elif tool_name == "redops_fofa":
                result = call_redops("/api/connectors/fofa/search", "POST", {
                    "query": args["query"],
                    "size": args.get("size", 10)
                })

            elif tool_name == "redops_targets":
                action = args.get("action", "list")
                if action == "list":
                    result = call_redops("/api/targets")
                elif action == "add":
                    result = call_redops("/api/targets", "POST", {"url": args.get("target", "")})
                else:
                    result = {"error": f"Unknown action: {action}"}

            elif tool_name == "redops_status":
                result = call_redops("/api/system/status")

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
        pass

    else:
        if id is not None:
            send_error(id, -32601, f"Unknown method: {method}")


def main():
    buffer = ""
    content_length = 0

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            buffer += line

            if line.startswith("Content-Length:"):
                content_length = int(line.split(":")[1].strip())
                continue

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
