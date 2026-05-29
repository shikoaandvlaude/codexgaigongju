"""Recon Phase — 信息搜集阶段"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_target
from .base import BasePhase


class ReconPhase(BasePhase):
    """信息搜集：子域名、DNS、存活探测、URL收集"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"subdomains": [], "alive_hosts": [], "urls": []}
        
        self.logger.log_phase_start("信息搜集 (Recon)")
        
        safe_target = sanitize_target(target)
        
        # Step 1: 子域名枚举
        self._step("子域名枚举", target, phase_findings, findings,
                   f"subfinder -d {shell_quote(safe_target)} -silent",
                   lambda out: [s for s in out.strip().split('\n') if s.strip()],
                   "subdomains")
        
        # Step 2: DNS 解析验证
        if phase_findings["subdomains"]:
            pipe_cmd = self._pipe_lines(phase_findings["subdomains"][:100])
            self._step("DNS解析", target, phase_findings, findings,
                       f"{pipe_cmd} | dnsx -silent 2>/dev/null",
                       lambda out: [s for s in out.strip().split('\n') if s.strip()],
                       "subdomains")
        
        # Step 3: HTTP 存活探测
        if phase_findings["subdomains"]:
            pipe_cmd = self._pipe_lines(phase_findings["subdomains"][:100])
            self._step("HTTP存活探测", target, phase_findings, findings,
                       f"{pipe_cmd} | httpx -silent -threads 5 -rate-limit 10 2>/dev/null",
                       lambda out: [s for s in out.strip().split('\n') if s.strip()],
                       "alive_hosts")
        
        # Step 4: URL 收集 (被动，不碰目标)
        self._step("历史URL收集(gau)", target, phase_findings, findings,
                   f"echo {shell_quote(safe_target)} | gau 2>/dev/null | head -200",
                   lambda out: [s for s in out.strip().split('\n') if s.strip()],
                   "urls")
        
        # Step 5: Wayback URL 补充
        self._step("Wayback URL", target, phase_findings, findings,
                   f"echo {shell_quote(safe_target)} | waybackurls 2>/dev/null | head -200",
                   lambda out: [u for u in out.strip().split('\n') if u.strip() and u not in phase_findings["urls"]],
                   "urls")
        
        # Step 6: AI 决策是否继续深入
        if self.mode == "auto":
            decision = self.engine.decide_next_action("recon", {**findings, **phase_findings}, target)
            if decision.get("action") == "execute":
                cmd = decision.get("command", "")
                if cmd and self._safe_command(cmd, target):
                    self._step("AI决策命令", target, phase_findings, findings,
                               cmd, lambda out: [], None)
        
        return phase_findings
