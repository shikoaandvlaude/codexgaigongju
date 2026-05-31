#!/usr/bin/env python3
"""
Shannon Bridge — 自主 AI 渗透测试框架集成

Shannon (KeygraphHQ) 特点：
- 分析源码 → 识别攻击面 → 自动发 exploit 验证（真打）
- 4阶段：侦察 → 并行漏洞分析 → 并行利用 → 报告
- XBOW 基准 96.15% — 能证明漏洞，不只是发现
- 支持白盒(有源码)和黑盒(shannon-uncontained fork)

安装：
    git clone https://github.com/KeygraphHQ/shannon.git
    cd shannon && ./shannon setup
    # 或黑盒 fork:
    git clone https://github.com/Steake/shannon-uncontained.git

用法：
    from shannon_bridge import ShannonBridge
    sb = ShannonBridge()
    result = sb.pentest("https://target.com")
    proof = sb.verify_finding(finding, "https://target.com")
"""

import json, os, re, subprocess, time
from pathlib import Path
from datetime import datetime


class ShannonBridge:
    def __init__(self, config=None):
        self.config = config or {}
        cfg = self.config.get('shannon', {})
        self.shannon_dir = os.path.expanduser(cfg.get('path', '~/shannon'))
        # 优先用 uncontained fork（黑盒能力强）
        uc = os.path.expanduser('~/shannon-uncontained')
        if os.path.isdir(uc):
            self.shannon_dir = uc
        self.shannon_exe = os.path.join(self.shannon_dir, 'shannon')
        self.output_dir = os.path.expanduser('~/.bai-agent/shannon-reports')
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def is_available(self):
        return os.path.isfile(self.shannon_exe) or os.path.isdir(self.shannon_dir)

    def pentest(self, target_url, repo_path="", timeout=600):
        """完整渗透：侦察→分析→利用→报告"""
        if not self.is_available():
            return {"error": "Shannon 未安装", "findings": []}
        cmd = f"{self.shannon_exe} start URL={target_url}"
        if repo_path and os.path.isdir(repo_path):
            cmd += f" REPO={repo_path}"
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout, cwd=self.shannon_dir, encoding='utf-8', errors='replace')
            output = r.stdout + r.stderr
            findings = self._parse(output)
            rpt = os.path.join(self.output_dir, f"shannon_{datetime.now().strftime('%Y%m%d_%H%M')}.txt")
            Path(rpt).write_text(output[:50000], encoding='utf-8')
            return {"success": r.returncode == 0, "findings": findings,
                    "exploits_proven": sum(1 for f in findings if f.get("exploited")),
                    "report_file": rpt, "raw_output": output[:3000]}
        except subprocess.TimeoutExpired:
            return {"error": f"超时({timeout}s)", "findings": []}
        except Exception as e:
            return {"error": str(e), "findings": []}

    def verify_finding(self, finding, target_url, timeout=120):
        """对单个漏洞做 exploit 验证"""
        if not self.is_available():
            return {"verified": False, "error": "Shannon 未安装"}
        vtype = finding.get('type', '?')
        ep = finding.get('url', '')
        cmd = f"{self.shannon_exe} start URL={target_url} FOCUS='{vtype}' ENDPOINT='{ep}'"
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout, cwd=self.shannon_dir, encoding='utf-8', errors='replace')
            output = r.stdout + r.stderr
            verified = any(kw in output.lower() for kw in
                          ['exploit successful', 'confirmed', 'proof of', 'rce achieved', 'data extracted'])
            return {"verified": verified, "proof": output[:2000], "confidence": 0.95 if verified else 0.3}
        except Exception as e:
            return {"verified": False, "error": str(e)}

    def _parse(self, output):
        findings = []
        for m in re.finditer(r'\{[^{}]*"vulnerability"[^{}]*\}', output):
            try:
                f = json.loads(m.group(0))
                findings.append({"type": f.get("vulnerability", "?"), "url": f.get("endpoint", ""),
                                "severity": f.get("severity", "medium"), "exploited": f.get("exploited", False),
                                "proof": f.get("proof", ""), "source": "shannon"})
            except json.JSONDecodeError:
                continue
        return findings
