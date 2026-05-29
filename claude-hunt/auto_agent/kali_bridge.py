#!/usr/bin/env python3
"""
Kali Bridge — SSH 远程调用 Kali 渗透工具

让 AI Agent 直接控制 Kali 虚拟机里的红队工具。

配置 config.yaml:
  kali:
    enabled: true
    host: "192.168.x.x"
    user: "kali"
    ssh_key: "~/.ssh/id_rsa"

用法:
    from kali_bridge import KaliBridge
    kb = KaliBridge(config)
    kb.nmap("target.com", "-sV -sC")
    kb.hydra("target.com", "ssh")
    kb.msf_run("exploit/multi/http/struts2_rce", {"RHOSTS": "target.com"})
    kb.run("任意命令")
"""
import os, subprocess, json, time
from pathlib import Path

class KaliBridge:
    FORBIDDEN = ["rm -rf /", "mkfs", "dd if=/dev/zero", ":(){"]

    def __init__(self, config=None):
        cfg = (config or {}).get("kali", {})
        self.enabled = cfg.get("enabled", False)
        self.host = cfg.get("host", "")
        self.user = cfg.get("user", "kali")
        self.port = cfg.get("port", 22)
        self.ssh_key = os.path.expanduser(cfg.get("ssh_key", "~/.ssh/id_rsa"))
        self.password = cfg.get("password", "")
        self.timeout = cfg.get("timeout", 300)
        self.results_dir = os.path.expanduser("~/.bai-agent/kali_results")
        Path(self.results_dir).mkdir(parents=True, exist_ok=True)

    def is_available(self):
        if not self.enabled or not self.host: return False
        r = self.run("echo OK", timeout=10)
        return r.get("success") and "OK" in r.get("output","")

    def run(self, command, timeout=None):
        if not self.enabled: return {"success":False,"output":"Kali未启用 config.yaml→kali.enabled:true"}
        if not self.host: return {"success":False,"output":"未配置Kali IP config.yaml→kali.host"}
        for f in self.FORBIDDEN:
            if f in command: return {"success":False,"output":f"[拒绝] {command}"}
        timeout = timeout or self.timeout
        ssh = self._ssh(command)
        try:
            r = subprocess.run(ssh, shell=True, capture_output=True, text=True, timeout=timeout)
            return {"success":r.returncode==0,"output":(r.stdout+r.stderr)[:10000],"command":command}
        except subprocess.TimeoutExpired:
            return {"success":False,"output":f"超时({timeout}s)","command":command}
        except Exception as e:
            return {"success":False,"output":str(e),"command":command}

    def nmap(self, target, args="-sV -sC", ports="1-1000"):
        r = self.run(f"nmap {args} -p {ports} {target} 2>&1", timeout=600)
        if r["success"]:
            r["open_ports"] = [l.strip() for l in r["output"].splitlines() if "/tcp" in l and "open" in l]
        return r

    def nmap_vuln(self, target):
        return self.nmap(target, "--script=vuln -sV", "1-10000")

    def masscan(self, target, ports="1-65535", rate=1000):
        return self.run(f"masscan {target} -p{ports} --rate={rate} 2>&1", timeout=300)

    def hydra(self, target, service="ssh", user_list=None, pass_list=None):
        ul = user_list or "/usr/share/wordlists/metasploit/unix_users.txt"
        pl = pass_list or "/usr/share/wordlists/rockyou.txt"
        return self.run(f"hydra -L {ul} -P {pl} {target} {service} -t 4 -f 2>&1|head -50", timeout=600)

    def crackmapexec(self, target, protocol="smb", user="", password=""):
        creds = f"-u '{user}' -p '{password}'" if user else ""
        return self.run(f"crackmapexec {protocol} {target} {creds} 2>&1", timeout=120)

    def enum4linux(self, target):
        return self.run(f"enum4linux -a {target} 2>&1|head -200", timeout=120)

    def gobuster(self, target, wordlist="/usr/share/wordlists/dirb/common.txt"):
        return self.run(f"gobuster dir -u {target} -w {wordlist} -t 10 --no-error 2>&1|head -100", timeout=180)

    def nikto(self, target):
        return self.run(f"nikto -h {target} -maxtime 300 2>&1|head -100", timeout=360)

    def whatweb(self, target):
        return self.run(f"whatweb {target} --color=never 2>&1", timeout=30)

    def wpscan(self, target):
        return self.run(f"wpscan --url {target} --enumerate u,vp --no-banner 2>&1|head -100", timeout=180)

    def responder(self, interface="eth0", timeout=60):
        return self.run(f"timeout {timeout} responder -I {interface} -wFb 2>&1|tail -30", timeout=timeout+10)

    def msf_run(self, module, options=None):
        opts = " ".join(f"set {k} {v};" for k,v in (options or {}).items())
        return self.run(f'msfconsole -qx "use {module}; {opts} run; exit" 2>&1|tail -50', timeout=120)

    def searchsploit(self, query):
        return self.run(f"searchsploit {query} --colour=no 2>&1|head -30", timeout=15)

    def hw_recon(self, target):
        return {"whatweb": self.whatweb(target), "nmap": self.nmap(target, "-sV -sC", "80,443,8080,8443,8888,3000,9090")}

    def hw_spray(self, target, users=None, passwords=None):
        users = users or ["admin","test","guest"]
        passwords = passwords or ["123456","admin","Admin@123","P@ssw0rd"]
        u = "\\n".join(users); p = "\\n".join(passwords)
        cmd = (f"echo -e '{u}'>/tmp/u.txt && echo -e '{p}'>/tmp/p.txt && "
               f"hydra -L /tmp/u.txt -P /tmp/p.txt {target} http-post-form "
               f"'/login:user=^USER^&pass=^PASS^:F=failed' -t 2 -W 3 2>&1|head -30")
        return self.run(cmd, timeout=120)

    def check_tools(self):
        tools = ["nmap","masscan","hydra","crackmapexec","enum4linux","gobuster","nikto","whatweb","wpscan","msfconsole","responder","searchsploit","hashcat"]
        r = self.run(f"which {' '.join(tools)} 2>/dev/null")
        avail = [t for t in tools if t in r.get("output","")]
        return {"available":avail,"missing":[t for t in tools if t not in avail]}

    def _ssh(self, command):
        key = f"-i {self.ssh_key}" if os.path.exists(self.ssh_key) else ""
        port = f"-p {self.port}" if self.port != 22 else ""
        opts = "-o StrictHostKeyChecking=no -o ConnectTimeout=10"
        if self.password and not os.path.exists(self.ssh_key):
            return f"sshpass -p '{self.password}' ssh {opts} {port} {self.user}@{self.host} '{command}'"
        return f"ssh {opts} {key} {port} {self.user}@{self.host} '{command}'"
