#!/usr/bin/env python3
"""
Intranet Scanner — 内网扫描编排模块

打进内网后的自动化信息收集：存活探测、端口扫描、服务识别、漏洞匹配。
整合 fscan/nmap/masscan 等工具的自动化调用和结果解析。

用法：
    from intranet_scanner import IntranetScanner
    scanner = IntranetScanner(kb)  # kb = KaliBridge

    # 快速存活探测
    alive = scanner.ping_sweep("10.0.0.0/24")

    # 全量端口扫描
    result = scanner.port_scan("10.0.0.0/24", ports="1-65535")

    # fscan 一键内网扫描
    result = scanner.fscan("10.0.0.0/24")

    # 服务识别+漏洞匹配
    vulns = scanner.service_vuln_match(alive_hosts)
"""

import re
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class Host:
    """内网主机"""
    ip: str = ""
    hostname: str = ""
    os: str = ""
    ports: List[Dict] = field(default_factory=list)  # [{"port":80,"service":"http","version":"nginx 1.18"}]
    vulns: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)  # ["dc","web","db","mail"]


@dataclass
class ScanResult:
    """扫描结果"""
    subnet: str = ""
    total_hosts: int = 0
    alive_hosts: List[Host] = field(default_factory=list)
    high_value_targets: List[Host] = field(default_factory=list)  # DC/DB/Admin
    scan_time: str = ""
    raw_output: str = ""


class IntranetScanner:
    """内网扫描编排器"""

    def __init__(self, kb=None, proxy=None):
        """
        Args:
            kb: KaliBridge 实例
            proxy: SOCKS5 代理地址（如通过隧道扫描）如 "socks5://127.0.0.1:1080"
        """
        self.kb = kb
        self.proxy = proxy
        self.results: List[ScanResult] = []

    def _run(self, cmd, timeout=120):
        if self.kb and self.kb.is_available():
            return self.kb.run(cmd, timeout=timeout)
        else:
            import subprocess
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:20000]}
            except Exception as e:
                return {"success": False, "output": str(e)}

    def _proxy_opt(self, tool="nmap"):
        """生成代理参数"""
        if not self.proxy:
            return ""
        if tool == "nmap":
            return f"--proxies {self.proxy}"
        elif tool == "curl":
            return f"--socks5 {self.proxy.replace('socks5://', '')}"
        elif tool == "proxychains":
            return "proxychains4 -q"
        return ""

    # ═══════════════════════════════════════════════════════════
    # 存活探测
    # ═══════════════════════════════════════════════════════════

    def ping_sweep(self, subnet: str, method="arp") -> List[str]:
        """快速存活探测"""
        if method == "arp":
            cmd = f"nmap -sn -PR {subnet} -oG - 2>/dev/null | grep 'Up' | awk '{{print $2}}'"
        elif method == "icmp":
            cmd = f"nmap -sn -PE {subnet} -oG - 2>/dev/null | grep 'Up' | awk '{{print $2}}'"
        elif method == "tcp":
            # TCP SYN 探测（适合禁 ping 环境）
            cmd = f"nmap -sn -PS22,80,443,445,3389 {subnet} -oG - 2>/dev/null | grep 'Up' | awk '{{print $2}}'"
        else:
            cmd = f"nmap -sn {subnet} -oG - 2>/dev/null | grep 'Up' | awk '{{print $2}}'"

        r = self._run(cmd, timeout=300)
        alive = [ip.strip() for ip in r.get("output", "").split("\n") if ip.strip()]
        return alive

    def nbtscan(self, subnet: str) -> List[Dict]:
        """NetBIOS 扫描（Windows 域环境）"""
        cmd = f"nbtscan -r {subnet} 2>/dev/null"
        r = self._run(cmd, timeout=60)
        hosts = []
        for line in r.get("output", "").split("\n"):
            parts = line.split()
            if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                hosts.append({"ip": parts[0], "netbios_name": parts[1] if len(parts) > 1 else ""})
        return hosts

    # ═══════════════════════════════════════════════════════════
    # 端口扫描
    # ═══════════════════════════════════════════════════════════

    def port_scan(self, target: str, ports="21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017",
                  mode="fast") -> List[Host]:
        """端口扫描"""
        if mode == "fast":
            cmd = f"nmap -sS -Pn -p {ports} {target} --open -oG - 2>/dev/null"
        elif mode == "full":
            cmd = f"nmap -sS -Pn -p 1-65535 {target} --open --min-rate 3000 -oG - 2>/dev/null"
        elif mode == "stealth":
            cmd = f"nmap -sS -Pn -p {ports} {target} --open -T2 --randomize-hosts -oG - 2>/dev/null"
        else:
            cmd = f"masscan {target} -p {ports} --rate 1000 --open-only 2>/dev/null"

        r = self._run(cmd, timeout=600)
        return self._parse_nmap_grep(r.get("output", ""))

    def service_scan(self, targets: List[str], ports="") -> List[Host]:
        """服务版本识别"""
        target_str = " ".join(targets[:20])
        port_opt = f"-p {ports}" if ports else "--top-ports 100"
        cmd = f"nmap -sV -sC {port_opt} {target_str} --open -oN - 2>/dev/null"
        r = self._run(cmd, timeout=600)
        # 简单解析
        hosts = []
        current_host = None
        for line in r.get("output", "").split("\n"):
            if "Nmap scan report for" in line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    if current_host:
                        hosts.append(current_host)
                    current_host = Host(ip=ip_match.group(1))
            elif current_host and "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_num = int(parts[0].split("/")[0])
                    service = parts[2] if len(parts) > 2 else ""
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    current_host.ports.append({
                        "port": port_num, "service": service, "version": version
                    })
        if current_host:
            hosts.append(current_host)
        return hosts

    # ═══════════════════════════════════════════════════════════
    # fscan — 一键内网扫描
    # ═══════════════════════════════════════════════════════════

    def fscan(self, target: str, extra_args="") -> Dict:
        """
        fscan 一键内网扫描（存活+端口+服务+漏洞+弱口令）
        推荐首选工具，Go 编写速度快
        """
        cmd = f"fscan -h {target} -o /tmp/fscan_result.txt {extra_args} 2>/dev/null; cat /tmp/fscan_result.txt"
        r = self._run(cmd, timeout=600)
        output = r.get("output", "")

        # 解析 fscan 结果
        result = {
            "alive": [],
            "ports": [],
            "vulns": [],
            "weak_passwords": [],
            "info": [],
            "raw": output[:5000],
        }

        for line in output.split("\n"):
            line = line.strip()
            if "[*] Alive" in line or "alive" in line.lower():
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    result["alive"].append(ip_match.group(1))
            elif "open" in line.lower() and re.search(r'\d+\.\d+\.\d+\.\d+:\d+', line):
                result["ports"].append(line)
            elif any(kw in line.lower() for kw in ["ms17-010", "cve-", "vuln", "poc"]):
                result["vulns"].append(line)
            elif any(kw in line.lower() for kw in ["密码", "password", "crack", "weak", "弱口令"]):
                result["weak_passwords"].append(line)
            elif line and not line.startswith("#"):
                result["info"].append(line)

        return result

    def fscan_smb(self, target: str) -> Dict:
        """fscan SMB 专项（MS17-010/弱口令）"""
        return self.fscan(target, extra_args="-m smb")

    def fscan_web(self, target: str) -> Dict:
        """fscan Web 专项（指纹/POC）"""
        return self.fscan(target, extra_args="-m web")

    # ═══════════════════════════════════════════════════════════
    # 高价值目标识别
    # ═══════════════════════════════════════════════════════════

    def identify_high_value(self, hosts: List[Host]) -> List[Host]:
        """识别高价值目标（DC/DB/Admin）"""
        hv_targets = []
        for host in hosts:
            tags = []
            for p in host.ports:
                port = p.get("port", 0)
                service = p.get("service", "").lower()
                version = p.get("version", "").lower()

                # 域控
                if port in [88, 389, 636, 464]:
                    tags.append("DC")
                # 数据库
                elif port in [1433, 3306, 5432, 1521, 27017, 6379]:
                    tags.append("DB")
                # 管理面板
                elif port in [3389, 5900, 8080, 8443, 9090]:
                    tags.append("ADMIN")
                # 邮件
                elif port in [25, 110, 143, 993, 995]:
                    tags.append("MAIL")
                # 文件服务
                elif port in [21, 445, 2049]:
                    tags.append("FILE")
                # Web
                elif port in [80, 443, 8000, 8080, 8888]:
                    tags.append("WEB")

                # 版本指纹判断
                if "exchange" in version:
                    tags.append("EXCHANGE")
                elif "vcenter" in version:
                    tags.append("VCENTER")
                elif "elastic" in version:
                    tags.append("ELASTIC")

            if tags:
                host.tags = list(set(tags))
                hv_targets.append(host)

        # 按价值排序：DC > DB > EXCHANGE > ADMIN > 其他
        priority = {"DC": 0, "EXCHANGE": 1, "VCENTER": 2, "DB": 3, "ADMIN": 4}
        hv_targets.sort(key=lambda h: min(priority.get(t, 99) for t in h.tags))
        return hv_targets

    # ═══════════════════════════════════════════════════════════
    # 漏洞匹配
    # ═══════════════════════════════════════════════════════════

    def service_vuln_match(self, hosts: List[Host]) -> List[Dict]:
        """根据服务版本匹配已知漏洞"""
        vuln_db = {
            "ms-sql": ["CVE-2020-0618 (RCE)", "弱口令 sa/空"],
            "mysql": ["CVE-2012-2122 (Auth Bypass)", "弱口令 root/空"],
            "redis": ["未授权访问→写SSH key/Cron", "CVE-2022-0543 (Lua RCE)"],
            "smb": ["MS17-010 (EternalBlue)", "MS08-067"],
            "rdp": ["CVE-2019-0708 (BlueKeep)", "弱口令爆破"],
            "ssh": ["弱口令爆破"],
            "elasticsearch": ["未授权访问", "CVE-2015-1427 (RCE)"],
            "mongodb": ["未授权访问"],
            "tomcat": ["CVE-2017-12615 (PUT 上传)", "弱口令 tomcat/tomcat"],
            "weblogic": ["CVE-2019-2725 (反序列化)", "CVE-2020-14882 (未授权RCE)"],
            "jboss": ["CVE-2017-12149 (反序列化)"],
            "vcenter": ["CVE-2021-21972 (RCE)", "CVE-2021-22005 (文件上传)"],
            "exchange": ["ProxyShell", "ProxyLogon"],
        }

        findings = []
        for host in hosts:
            for p in host.ports:
                service = p.get("service", "").lower()
                version = p.get("version", "").lower()
                for vuln_service, vulns in vuln_db.items():
                    if vuln_service in service or vuln_service in version:
                        findings.append({
                            "ip": host.ip,
                            "port": p.get("port"),
                            "service": service,
                            "version": version,
                            "potential_vulns": vulns,
                        })
        return findings

    # ═══════════════════════════════════════════════════════════
    # 弱口令爆破
    # ═══════════════════════════════════════════════════════════

    def brute_ssh(self, targets: List[str], users=None, passwords=None) -> List[Dict]:
        """SSH 弱口令爆破"""
        users = users or ["root", "admin", "ubuntu", "test"]
        passwords = passwords or ["123456", "admin", "root", "password", "toor", "admin123", "test", "P@ssw0rd"]
        target_str = " ".join(targets[:10])
        user_str = "\\n".join(users)
        pass_str = "\\n".join(passwords)
        cmd = (f"echo -e '{user_str}' > /tmp/u.txt && echo -e '{pass_str}' > /tmp/p.txt && "
               f"hydra -L /tmp/u.txt -P /tmp/p.txt -M <(echo -e '{target_str}') ssh -t 4 -f 2>/dev/null | grep 'login:' | head -20")
        r = self._run(cmd, timeout=300)
        results = []
        for line in r.get("output", "").split("\n"):
            if "login:" in line:
                results.append({"raw": line.strip()})
        return results

    def brute_smb(self, targets: List[str], users=None, passwords=None) -> List[Dict]:
        """SMB 弱口令"""
        users = users or ["administrator", "admin", "guest"]
        passwords = passwords or ["123456", "admin", "P@ssw0rd", "admin123", ""]
        results = []
        for target in targets[:10]:
            for u in users:
                for p in passwords:
                    cmd = f"crackmapexec smb {target} -u '{u}' -p '{p}' 2>/dev/null | grep '[+]' | head -5"
                    r = self._run(cmd, timeout=15)
                    if r.get("success") and "[+]" in r.get("output", ""):
                        results.append({"ip": target, "user": u, "password": p, "raw": r["output"].strip()})
                        break
        return results

    # ═══════════════════════════════════════════════════════════
    # 结果汇总
    # ═══════════════════════════════════════════════════════════

    def full_scan(self, subnet: str) -> ScanResult:
        """完整内网扫描流程"""
        print(f"[*] 开始内网扫描: {subnet}")
        result = ScanResult(subnet=subnet, scan_time=time.strftime("%Y-%m-%d %H:%M:%S"))

        # Step 1: 存活探测
        print("[*] Step 1: 存活探测...")
        alive_ips = self.ping_sweep(subnet, method="tcp")
        result.total_hosts = len(alive_ips)
        print(f"[+] 发现 {len(alive_ips)} 台存活主机")

        # Step 2: 端口扫描
        print("[*] Step 2: 端口扫描...")
        if alive_ips:
            hosts = self.port_scan(" ".join(alive_ips[:50]))
            result.alive_hosts = hosts
            print(f"[+] 扫描完成: {len(hosts)} 台有开放端口")

        # Step 3: 高价值目标
        print("[*] Step 3: 识别高价值目标...")
        hv = self.identify_high_value(result.alive_hosts)
        result.high_value_targets = hv
        if hv:
            print(f"[+] 高价值目标: {len(hv)} 台")
            for h in hv[:5]:
                print(f"    {h.ip} — {', '.join(h.tags)}")

        self.results.append(result)
        return result

    def generate_target_list(self, result: ScanResult) -> str:
        """生成目标清单（供队友使用）"""
        lines = [
            f"# 内网扫描结果 — {result.subnet}",
            f"# 扫描时间: {result.scan_time}",
            f"# 存活主机: {result.total_hosts}",
            "",
            "## 高价值目标",
        ]
        for h in result.high_value_targets:
            ports_str = ",".join(str(p["port"]) for p in h.ports[:10])
            lines.append(f"{h.ip}\t{','.join(h.tags)}\t{ports_str}")

        lines.append("\n## 全部存活主机")
        for h in result.alive_hosts:
            ports_str = ",".join(str(p["port"]) for p in h.ports[:10])
            lines.append(f"{h.ip}\t{ports_str}")

        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════
    # 工具方法
    # ═══════════════════════════════════════════════════════════

    def _parse_nmap_grep(self, output: str) -> List[Host]:
        """解析 nmap grepable 输出"""
        hosts = []
        for line in output.split("\n"):
            if "Host:" in line and "Ports:" in line:
                ip_match = re.search(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', line)
                if not ip_match:
                    continue
                host = Host(ip=ip_match.group(1))
                ports_section = line.split("Ports:")[1] if "Ports:" in line else ""
                for port_info in ports_section.split(","):
                    port_match = re.search(r'(\d+)/open/tcp//([^/]*)/?(.*)?/', port_info.strip())
                    if port_match:
                        host.ports.append({
                            "port": int(port_match.group(1)),
                            "service": port_match.group(2).strip(),
                            "version": port_match.group(3).strip() if port_match.group(3) else "",
                        })
                if host.ports:
                    hosts.append(host)
        return hosts
