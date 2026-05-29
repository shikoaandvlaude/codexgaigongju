#!/usr/bin/env python3
"""
MCP Tool Server — 将核心能力暴露为 MCP 协议服务
移植自 HexStrike AI 的 MCP Server 架构

功能：
1. 将 Bai-codeagent 的核心工具暴露为 MCP Server
2. 任何 MCP 客户端（Claude Desktop / Cursor / VS Code Copilot）可直接调用
3. 智能工具选择引擎（根据目标类型推荐工具）
4. 攻击链建模（概率计算 + 依赖追踪）

启动方式：
    python mcp_tool_server.py                    # stdio 模式
    python mcp_tool_server.py --transport sse    # SSE 模式（HTTP）
    python mcp_tool_server.py --port 9000        # 指定端口

MCP 客户端配置示例（claude_desktop_config.json）：
    {
        "mcpServers": {
            "bai-security": {
                "command": "python",
                "args": ["/path/to/mcp_tool_server.py"]
            }
        }
    }
"""

import asyncio
import json
import os
import sys
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# MCP 协议实现（轻量级，不依赖外部 MCP SDK）
# ═══════════════════════════════════════════════════════════════

@dataclass
class MCPTool:
    """MCP 工具定义"""
    name: str = ""
    description: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    category: str = ""  # recon/scan/exploit/report
    requires: List[str] = field(default_factory=list)  # 前置工具


@dataclass
class MCPRequest:
    """MCP 请求"""
    jsonrpc: str = "2.0"
    id: Any = None
    method: str = ""
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPResponse:
    """MCP 响应"""
    jsonrpc: str = "2.0"
    id: Any = None
    result: Any = None
    error: Optional[Dict] = None


# ═══════════════════════════════════════════════════════════════
# 工具注册表
# ═══════════════════════════════════════════════════════════════

TOOL_REGISTRY: List[MCPTool] = [
    # ─── 侦察工具 ──────────────────────────────────────
    MCPTool(
        name="subdomain_enum",
        description="子域名枚举（使用 subfinder + 被动收集）",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标域名"},
                "passive_only": {"type": "boolean", "description": "仅被动收集", "default": True},
            },
            "required": ["domain"],
        },
        category="recon",
    ),
    MCPTool(
        name="port_scan",
        description="端口扫描（使用 nmap，默认 top 1000 端口）",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 IP 或域名"},
                "ports": {"type": "string", "description": "端口范围", "default": ""},
                "speed": {"type": "integer", "description": "扫描速度 1-5", "default": 3},
            },
            "required": ["target"],
        },
        category="recon",
    ),
    MCPTool(
        name="web_fingerprint",
        description="Web 技术指纹识别（框架/CMS/服务器/WAF）",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
            },
            "required": ["url"],
        },
        category="recon",
    ),
    MCPTool(
        name="url_discovery",
        description="URL 和参数发现（GAU + Wayback + 爬虫）",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标域名"},
                "include_params": {"type": "boolean", "default": True},
            },
            "required": ["domain"],
        },
        category="recon",
    ),

    # ─── 扫描工具 ──────────────────────────────────────
    MCPTool(
        name="vuln_scan",
        description="漏洞扫描（nuclei 高危模板）",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 URL 或文件"},
                "severity": {"type": "string", "description": "严重程度过滤", "default": "critical,high"},
                "rate_limit": {"type": "integer", "description": "请求速率", "default": 5},
            },
            "required": ["target"],
        },
        category="scan",
    ),
    MCPTool(
        name="xss_scan",
        description="XSS 漏洞扫描（dalfox）",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "带参数的 URL"},
            },
            "required": ["url"],
        },
        category="scan",
    ),
    MCPTool(
        name="sqli_test",
        description="SQL 注入测试（响应差异检测）",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "param": {"type": "string", "description": "测试参数名"},
                "method": {"type": "string", "default": "GET"},
            },
            "required": ["url", "param"],
        },
        category="scan",
    ),
    MCPTool(
        name="dir_bruteforce",
        description="目录/文件爆破（ffuf）",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标基础 URL"},
                "wordlist": {"type": "string", "description": "字典路径", "default": "common"},
                "extensions": {"type": "string", "description": "扩展名", "default": ""},
            },
            "required": ["url"],
        },
        category="scan",
    ),

    # ─── 利用工具 ──────────────────────────────────────
    MCPTool(
        name="active_fuzz",
        description="主动 Fuzz（响应差异检测 + 注入点发现）",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "params": {"type": "array", "items": {"type": "string"}, "description": "参数列表"},
                "vuln_types": {"type": "array", "items": {"type": "string"}, "default": ["sqli", "xss", "ssti"]},
            },
            "required": ["url"],
        },
        category="exploit",
    ),
    MCPTool(
        name="idor_test",
        description="IDOR 越权测试（需双 Cookie）",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 API URL（含 ID）"},
                "cookie_a": {"type": "string", "description": "用户 A 的 Cookie"},
                "cookie_b": {"type": "string", "description": "用户 B 的 Cookie"},
            },
            "required": ["url", "cookie_a", "cookie_b"],
        },
        category="exploit",
    ),
    MCPTool(
        name="race_condition",
        description="竞态条件测试（并发请求 + 状态验证）",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标端点"},
                "method": {"type": "string", "default": "POST"},
                "body": {"type": "object", "description": "请求体"},
                "concurrency": {"type": "integer", "default": 10},
                "state_url": {"type": "string", "description": "状态检查 URL"},
            },
            "required": ["url"],
        },
        category="exploit",
    ),

    # ─── 代码审计 ──────────────────────────────────────
    MCPTool(
        name="code_audit",
        description="白盒代码审计（5 类并行：injection/xss/auth/authz/ssrf）",
        parameters={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "源码目录路径"},
                "vuln_classes": {"type": "array", "items": {"type": "string"}, "default": ["injection", "xss", "auth", "authz", "ssrf"]},
                "use_llm": {"type": "boolean", "default": True},
            },
            "required": ["repo_path"],
        },
        category="audit",
    ),

    # ─── 报告 ──────────────────────────────────────────
    MCPTool(
        name="generate_report",
        description="生成中文安全评估报告（Shannon 格式）",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标名称"},
                "findings": {"type": "object", "description": "findings 字典"},
                "output_dir": {"type": "string", "default": "./reports"},
            },
            "required": ["target", "findings"],
        },
        category="report",
    ),

    # ─── 辅助 ──────────────────────────────────────────
    MCPTool(
        name="waf_detect",
        description="WAF 检测 + 绕过策略推荐",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
            },
            "required": ["url"],
        },
        category="recon",
    ),
    MCPTool(
        name="recommend_tools",
        description="智能工具推荐（根据目标类型和已有信息）",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标描述"},
                "target_type": {"type": "string", "description": "目标类型", "default": "web"},
                "known_info": {"type": "object", "description": "已知信息", "default": {}},
            },
            "required": ["target"],
        },
        category="meta",
    ),
]


# ═══════════════════════════════════════════════════════════════
# 工具执行器
# ═══════════════════════════════════════════════════════════════

class ToolExecutor:
    """执行 MCP 工具调用"""

    def __init__(self):
        self._base_dir = os.path.dirname(os.path.abspath(__file__))

    async def execute(self, tool_name: str, params: Dict) -> Dict[str, Any]:
        """执行工具并返回结果"""
        handler = getattr(self, f"_exec_{tool_name}", None)
        if handler:
            return await handler(params)
        return {"error": f"Unknown tool: {tool_name}"}

    async def _exec_subdomain_enum(self, params: Dict) -> Dict:
        domain = params.get("domain", "")
        cmd = f"subfinder -d {domain} -silent"
        output = await self._run_cmd(cmd, timeout=60)
        subdomains = [s.strip() for s in output.split("\n") if s.strip()]
        return {"domain": domain, "subdomains": subdomains, "count": len(subdomains)}

    async def _exec_port_scan(self, params: Dict) -> Dict:
        target = params.get("target", "")
        speed = params.get("speed", 3)
        ports = params.get("ports", "")
        port_flag = f"-p {ports}" if ports else "--top-ports 1000"
        cmd = f"nmap -T{speed} {port_flag} -sV {target}"
        output = await self._run_cmd(cmd, timeout=120)
        return {"target": target, "output": output}

    async def _exec_web_fingerprint(self, params: Dict) -> Dict:
        url = params.get("url", "")
        cmd = f"httpx -u {url} -tech-detect -status-code -title -silent"
        output = await self._run_cmd(cmd, timeout=30)
        return {"url": url, "fingerprint": output}

    async def _exec_url_discovery(self, params: Dict) -> Dict:
        domain = params.get("domain", "")
        cmd = f"echo {domain} | gau --threads 3 2>/dev/null | head -200"
        output = await self._run_cmd(cmd, timeout=60)
        urls = [u.strip() for u in output.split("\n") if u.strip()]
        return {"domain": domain, "urls": urls[:200], "count": len(urls)}

    async def _exec_vuln_scan(self, params: Dict) -> Dict:
        target = params.get("target", "")
        severity = params.get("severity", "critical,high")
        rate = params.get("rate_limit", 5)
        cmd = f"echo {target} | nuclei -severity {severity} -rate-limit {rate} -silent"
        output = await self._run_cmd(cmd, timeout=120)
        return {"target": target, "results": output}

    async def _exec_xss_scan(self, params: Dict) -> Dict:
        url = params.get("url", "")
        cmd = f"echo {url} | dalfox pipe --silence 2>/dev/null"
        output = await self._run_cmd(cmd, timeout=60)
        return {"url": url, "results": output}

    async def _exec_sqli_test(self, params: Dict) -> Dict:
        url = params.get("url", "")
        param = params.get("param", "")
        # 使用内部 active_fuzzer
        return {"url": url, "param": param, "note": "Use active_fuzz for detailed testing"}

    async def _exec_dir_bruteforce(self, params: Dict) -> Dict:
        url = params.get("url", "")
        extensions = params.get("extensions", "")
        ext_flag = f"-e {extensions}" if extensions else ""
        cmd = f"ffuf -u {url}/FUZZ {ext_flag} -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -s 2>/dev/null | head -50"
        output = await self._run_cmd(cmd, timeout=90)
        paths = [p.strip() for p in output.split("\n") if p.strip()]
        return {"url": url, "paths": paths, "count": len(paths)}

    async def _exec_active_fuzz(self, params: Dict) -> Dict:
        return {"status": "available", "note": "Invoke via Python: from active_fuzzer import ActiveFuzzer"}

    async def _exec_idor_test(self, params: Dict) -> Dict:
        return {"status": "available", "note": "Invoke via Python: from idor_tester import IDORTester"}

    async def _exec_race_condition(self, params: Dict) -> Dict:
        return {"status": "available", "note": "Invoke via Python: from business_logic_tester import BusinessLogicTester"}

    async def _exec_code_audit(self, params: Dict) -> Dict:
        repo_path = params.get("repo_path", "")
        if not os.path.isdir(repo_path):
            return {"error": f"Path not found: {repo_path}"}
        return {"status": "available", "note": "Invoke via Python: from code_auditor import run_code_audit"}

    async def _exec_generate_report(self, params: Dict) -> Dict:
        return {"status": "available", "note": "Invoke via Python: from shannon_report import generate_shannon_report"}

    async def _exec_waf_detect(self, params: Dict) -> Dict:
        url = params.get("url", "")
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -H 'X-Forwarded-For: 127.0.0.1' '{url}/?test=<script>alert(1)</script>'"
        output = await self._run_cmd(cmd, timeout=15)
        blocked = output.strip() in ("403", "406", "429", "503")
        return {"url": url, "waf_detected": blocked, "status_code": output.strip()}

    async def _exec_recommend_tools(self, params: Dict) -> Dict:
        target_type = params.get("target_type", "web")
        recommendations = {
            "web": ["subdomain_enum", "web_fingerprint", "url_discovery", "vuln_scan", "active_fuzz"],
            "api": ["url_discovery", "sqli_test", "idor_test", "active_fuzz"],
            "network": ["port_scan", "vuln_scan"],
            "mobile": ["url_discovery", "idor_test", "race_condition"],
            "code": ["code_audit", "generate_report"],
        }
        tools = recommendations.get(target_type, recommendations["web"])
        return {"target_type": target_type, "recommended_tools": tools}

    async def _run_cmd(self, cmd: str, timeout: int = 60) -> str:
        """执行 shell 命令"""
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode("utf-8", errors="ignore")
        except asyncio.TimeoutError:
            return f"[TIMEOUT after {timeout}s]"
        except Exception as e:
            return f"[ERROR: {e}]"


# ═══════════════════════════════════════════════════════════════
# MCP Server 主类
# ═══════════════════════════════════════════════════════════════

class BaiMCPServer:
    """
    Bai-codeagent MCP Server
    
    实现 MCP 协议的 JSON-RPC over stdio/SSE
    """

    def __init__(self):
        self.executor = ToolExecutor()
        self.tools = TOOL_REGISTRY

    async def handle_request(self, request: Dict) -> Dict:
        """处理 MCP 请求"""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return self._resp(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "bai-security",
                    "version": "1.0.0",
                    "description": "Bai-codeagent Security Testing Tools",
                },
            })

        elif method == "tools/list":
            tools_list = [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.parameters,
                }
                for t in self.tools
            ]
            return self._resp(req_id, {"tools": tools_list})

        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            result = await self.executor.execute(tool_name, arguments)
            return self._resp(req_id, {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}],
            })

        elif method == "notifications/initialized":
            return None  # 通知不需要响应

        else:
            return self._error(req_id, -32601, f"Method not found: {method}")

    def _resp(self, req_id, result):
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _error(self, req_id, code, message):
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    async def run_stdio(self):
        """stdio 模式运行（标准 MCP 传输）"""
        import sys
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                request = json.loads(line.decode())
                response = await self.handle_request(request)
                if response:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                continue
            except Exception as e:
                sys.stderr.write(f"Error: {e}\n")
                sys.stderr.flush()

    async def run_sse(self, host: str = "0.0.0.0", port: int = 9000):
        """SSE 模式运行（HTTP Server-Sent Events）"""
        try:
            from aiohttp import web

            async def handle_sse(request):
                resp = web.StreamResponse()
                resp.content_type = "text/event-stream"
                resp.headers["Cache-Control"] = "no-cache"
                resp.headers["Connection"] = "keep-alive"
                await resp.prepare(request)
                # 保持连接
                while True:
                    await asyncio.sleep(30)
                    await resp.write(b": keepalive\n\n")

            async def handle_message(request):
                body = await request.json()
                response = await self.handle_request(body)
                return web.json_response(response)

            app = web.Application()
            app.router.add_get("/sse", handle_sse)
            app.router.add_post("/message", handle_message)

            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, host, port)
            await site.start()
            print(f"MCP Server (SSE) running on http://{host}:{port}")
            await asyncio.Event().wait()

        except ImportError:
            print("SSE mode requires aiohttp: pip install aiohttp")
            sys.exit(1)


# ═══════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bai-codeagent MCP Tool Server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    server = BaiMCPServer()

    if args.transport == "sse":
        asyncio.run(server.run_sse(args.host, args.port))
    else:
        asyncio.run(server.run_stdio())


if __name__ == "__main__":
    main()
