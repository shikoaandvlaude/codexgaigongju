#!/usr/bin/env python3
"""
Strix Bridge — AI 自主渗透扫描器集成

Strix (usestrix.com) 特点：
- 像真人黑客动态测试，不是模式匹配
- 自动生成 PoC，零误报设计
- 支持 Web 应用/API/GitHub 仓库/域名/IP 扫描
- Docker 隔离执行，开源

安装：
    pip install strix-cli
    # 或 Docker:
    docker pull ghcr.io/usestrix/strix:latest
    # 配置:
    export ANTHROPIC_API_KEY=sk-xxx

用法：
    from strix_bridge import StrixBridge
    sb = StrixBridge()
    result = sb.scan_url("https://target.com")
    result = sb.scan_domain("target.com")
"""

import json, os, re, subprocess
from pathlib import Path
from datetime import datetime


class StrixBridge:
    def __init__(self, config=None):
        self.config = config or {}
        cfg = self.config.get('strix', {})
        self.strix_exe = cfg.get('path', 'strix')
        self.use_docker = cfg.get('docker', False)
        self.docker_image = cfg.get('image', 'ghcr.io/usestrix/strix:latest')
        self.output_dir = os.path.expanduser('~/.bai-agent/strix-reports')
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def is_available(self):
        try:
            cmd = f"{self.strix_exe} --version" if not self.use_docker else f"docker run --rm {self.docker_image} --version"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            return r.returncode == 0
        except Exception:
            return False

    def scan_url(self, url, focus=None, timeout=300):
        """扫描 Web URL"""
        cmd = self._cmd(f"scan {url}")
        if focus:
            cmd += f" --focus {','.join(focus)}"
        return self._run(cmd, timeout)

    def scan_domain(self, domain, timeout=600):
        """扫描域名（含子域名+端口+漏洞）"""
        return self._run(self._cmd(f"scan {domain} --type domain"), timeout)

    def scan_repo(self, repo_url, timeout=300):
        """扫描 GitHub 仓库（白盒）"""
        return self._run(self._cmd(f"scan {repo_url} --type repo"), timeout)

    def _cmd(self, args):
        if self.use_docker:
            return f"docker run --rm {self.docker_image} {args}"
        return f"{self.strix_exe} {args}"

    def _run(self, cmd, timeout):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout, encoding='utf-8', errors='replace')
            output = r.stdout + r.stderr
            rpt = os.path.join(self.output_dir, f"strix_{datetime.now().strftime('%Y%m%d_%H%M')}.txt")
            Path(rpt).write_text(output[:50000], encoding='utf-8')
            findings = self._parse(output)
            return {"success": r.returncode == 0, "findings": findings,
                    "pocs": [f for f in findings if f.get("poc")],
                    "critical_high": sum(1 for f in findings if f.get("severity") in ("critical", "high")),
                    "report_file": rpt, "raw_output": output[:3000]}
        except subprocess.TimeoutExpired:
            return {"error": f"超时({timeout}s)", "findings": []}
        except Exception as e:
            return {"error": str(e), "findings": []}

    def _parse(self, output):
        findings = []
        # JSON 格式
        try:
            m = re.search(r'\[[\s\S]*\{[\s\S]*"vulnerability"[\s\S]*\}[\s\S]*\]', output)
            if m:
                for item in json.loads(m.group(0)):
                    findings.append({"type": item.get("vulnerability", "?"), "url": item.get("url", ""),
                                    "severity": item.get("severity", "medium"), "poc": item.get("poc", ""),
                                    "detail": item.get("description", ""), "source": "strix"})
                return findings
        except (json.JSONDecodeError, AttributeError):
            pass
        # 文本格式
        for m in re.finditer(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.+)', output, re.I):
            findings.append({"type": m.group(2).strip(), "severity": m.group(1).lower(), "source": "strix"})
        return findings
