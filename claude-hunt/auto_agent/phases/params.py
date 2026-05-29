"""Params Phase — 参数发现阶段"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_target
from .base import BasePhase


class ParamPhase(BasePhase):
    """参数发现：从URL中提取参数、主动探测隐藏参数"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"params": [], "urls": []}
        
        self.logger.log_phase_start("参数发现 (Param Discovery)")
        
        safe_target = sanitize_target(target)
        
        # Step 1: ParamSpider 被动参数发现
        self._step("ParamSpider被动参数", target, phase_findings, findings,
                   f"paramspider -d {shell_quote(safe_target)} 2>/dev/null | head -100",
                   lambda out: [u for u in out.strip().split('\n') if u and '?' in u],
                   "urls")
        
        # Step 2: 从已有URL中提取有参数的
        urls_with_params = [u for u in findings.get('urls', []) if '?' in u]
        if urls_with_params:
            phase_findings["params"].extend(urls_with_params[:50])
        
        # Step 3: 用 gf 提取可能有漏洞的参数模式
        if findings.get('urls'):
            pipe_cmd = self._pipe_lines(findings['urls'][:100])
            self._step("gf提取XSS参数", target, phase_findings, findings,
                       f"{pipe_cmd} | gf xss 2>/dev/null | head -50",
                       lambda out: [u for u in out.strip().split('\n') if u],
                       "params")
            
            pipe_cmd = self._pipe_lines(findings['urls'][:100])
            self._step("gf提取SSRF参数", target, phase_findings, findings,
                       f"{pipe_cmd} | gf ssrf 2>/dev/null | head -50",
                       lambda out: [u for u in out.strip().split('\n') if u],
                       "params")
        
        # Step 4: AI 判断是否需要用 arjun 主动探测
        if self.mode == "auto" and findings.get('alive_hosts'):
            decision = self.engine.think(
                f"目标有 {len(findings['alive_hosts'])} 个存活主机，{len(phase_findings['params'])} 个已知参数。"
                f"是否需要用 arjun 对关键接口做主动参数探测？回答 YES 或 NO，如果YES给出具体URL。"
            )
            if "YES" in decision.upper():
                # 对第一个存活主机做探测
                host = findings['alive_hosts'][0]
                self._step("Arjun主动参数探测", target, phase_findings, findings,
                           f"arjun -u {shell_quote(host)} --stable 2>/dev/null | head -20",
                           lambda out: [out] if out.strip() else [],
                           "params")
        
        return phase_findings
