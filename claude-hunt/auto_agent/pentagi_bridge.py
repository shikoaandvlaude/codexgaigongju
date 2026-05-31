#!/usr/bin/env python3
"""
PentAGI Bridge — 全自主 AI 渗透 Agent（WSL/Docker 沙箱隔离）

PentAGI (vxcontrol) 特点：
- 隔离执行，不封你真实 IP
- 自带 nmap/sqlmap/metasploit/nikto/hydra 等全套工具
- 多 Agent 架构：Researcher + Executor + Reporter
- 支持任意 LLM，Web UI + API

安装（WSL 方式，不需要 Docker Desktop）：
    # 1. 确保 WSL2 已启用
    wsl --install  # Windows 上跑一次就行

    # 2. 在 WSL 中安装
    wsl -d Ubuntu
    git clone https://github.com/vxcontrol/pentagi.git
    cd pentagi && cp .env.example .env
    # 填 OPENAI_API_KEY 或 ANTHROPIC_API_KEY
    # 在 WSL 内装 docker:
    sudo apt update && sudo apt install -y docker.io docker-compose-v2
    sudo service docker start
    docker compose up -d

    # 3. Windows 侧访问: http://localhost:8228

用法：
    from pentagi_bridge import PentAGIBridge
    pb = PentAGIBridge()
    result = pb.execute_task("对 target.com 做全面渗透测试")
    result = pb.sqlmap_safe("http://target.com/page?id=1")
"""

import json, os, subprocess, time
from pathlib import Path
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class PentAGIBridge:
    def __init__(self, config=None):
        self.config = config or {}
        cfg = self.config.get('pentagi', {})
        self.api_url = cfg.get('api_url', 'http://localhost:8228')
        self.pentagi_dir = os.path.expanduser(cfg.get('path', '~/pentagi'))
        self.output_dir = os.path.expanduser('~/.bai-agent/pentagi-reports')
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def is_available(self):
        if not HAS_REQUESTS:
            return False
        try:
            r = requests.get(f"{self.api_url}/health", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def start(self):
        """启动 PentAGI（优先 WSL 内 docker，fallback 本机 docker）"""
        if self.is_available():
            return True
        if not os.path.isdir(self.pentagi_dir):
            # 尝试 WSL 路径
            wsl_path = self.config.get('pentagi', {}).get('wsl_path', '/home/*/pentagi')
            return self._start_wsl(wsl_path)

        # 本机 docker
        try:
            subprocess.run("docker compose up -d", shell=True,
                          cwd=self.pentagi_dir, capture_output=True, timeout=120)
            for _ in range(20):
                time.sleep(3)
                if self.is_available():
                    return True
        except Exception:
            pass

        # fallback: 通过 WSL 启动
        return self._start_wsl()

    def _start_wsl(self, wsl_path=None):
        """通过 WSL 启动 PentAGI"""
        path = wsl_path or "/root/pentagi"
        try:
            # 先启动 WSL 内的 docker 服务
            subprocess.run(
                f'wsl -d Ubuntu bash -c "sudo service docker start && cd {path} && docker compose up -d"',
                shell=True, capture_output=True, timeout=120
            )
            for _ in range(20):
                time.sleep(3)
                if self.is_available():
                    return True
        except Exception:
            pass
        return False

    def execute_task(self, task, timeout=300):
        """下发自然语言渗透任务"""
        if not self.is_available() and not self.start():
            return {"error": "PentAGI 未运行", "findings": []}
        try:
            r = requests.post(f"{self.api_url}/api/tasks",
                            json={"prompt": task, "timeout": timeout}, timeout=timeout+10)
            if r.status_code in (200, 201):
                data = r.json()
                return {"success": True, "findings": data.get("findings", []),
                        "tools_used": data.get("tools_used", []),
                        "output": data.get("output", "")[:5000]}
            return {"success": False, "error": f"HTTP {r.status_code}", "output": r.text[:1000]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def run_tool(self, tool, args, timeout=180):
        """在沙箱中跑指定工具"""
        return self.execute_task(f"Run: {tool} {args}\nReturn full output.", timeout)

    def sqlmap_safe(self, url, level=3, risk=2, timeout=300):
        """在 Docker 沙箱中跑 sqlmap（不封你IP）"""
        args = f"-u '{url}' --batch --level={level} --risk={risk} --threads=3 --random-agent --smart"
        return self.run_tool("sqlmap", args, timeout)

    def auto_pentest(self, target, scope=None, timeout=600):
        """全自动渗透（PentAGI自己决策）"""
        scope_t = f" Scope: {', '.join(scope)}." if scope else ""
        task = f"Full pentest on {target}.{scope_t} Port scan, service ID, vuln test, exploit verification."
        return self.execute_task(task, timeout)
