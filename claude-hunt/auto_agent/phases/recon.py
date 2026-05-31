"""Recon Phase — 信息搜集阶段（增强版）

增强内容：
- katana 主动爬虫（JS渲染页面也能抓到）
- JS 文件提取 + 接口/密钥发现
- 技术栈指纹识别（httpx -tech-detect）
- assetfinder 补充子域名
- 更大 URL 收集量（500+）
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_target
from .base import BasePhase


class ReconPhase(BasePhase):
    """信息搜集：子域名、DNS、存活探测、主动爬虫、JS分析、技术栈指纹"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"subdomains": [], "alive_hosts": [], "urls": [], "js_files": [], "tech_stack": []}
        
        self.logger.log_phase_start("信息搜集 (Recon — Enhanced)")
        
        safe_target = sanitize_target(target)
        
        # ═══ Step 1: 子域名枚举（多源）═══
        self._step("subfinder子域名", target, phase_findings, findings,
                   f"subfinder -d {shell_quote(safe_target)} -silent",
                   lambda out: [s for s in out.strip().split('\n') if s.strip()],
                   "subdomains")
        
        # assetfinder 补充（被动，速度快）
        self._step("assetfinder补充", target, phase_findings, findings,
                   f"assetfinder --subs-only {shell_quote(safe_target)} 2>/dev/null",
                   lambda out: [s for s in out.strip().split('\n') 
                               if s.strip() and s.strip() not in phase_findings["subdomains"]],
                   "subdomains")
        
        # ═══ Step 2: DNS 解析验证 ═══
        if phase_findings["subdomains"]:
            pipe_cmd = self._pipe_lines(phase_findings["subdomains"][:200])
            self._step("DNS解析", target, phase_findings, findings,
                       f"{pipe_cmd} | dnsx -silent 2>/dev/null",
                       lambda out: [s for s in out.strip().split('\n') if s.strip()],
                       "subdomains")
        
        # ═══ Step 3: HTTP 存活探测 + 技术栈指纹 ═══
        if phase_findings["subdomains"]:
            pipe_cmd = self._pipe_lines(phase_findings["subdomains"][:200])
            self._step("HTTP存活+技术栈指纹", target, phase_findings, findings,
                       f"{pipe_cmd} | httpx -silent -threads 5 -rate-limit 10 -tech-detect -status-code -title -follow-redirects 2>/dev/null",
                       self._parse_httpx_tech,
                       "alive_hosts")
        
        # ═══ Step 4: 被动 URL 收集（多源，更大量）═══
        self._step("历史URL(gau)", target, phase_findings, findings,
                   f"echo {shell_quote(safe_target)} | gau --threads 3 2>/dev/null | sort -u | head -500",
                   lambda out: [s for s in out.strip().split('\n') if s.strip()],
                   "urls")
        
        self._step("Wayback URL", target, phase_findings, findings,
                   f"echo {shell_quote(safe_target)} | waybackurls 2>/dev/null | sort -u | head -500",
                   lambda out: [u for u in out.strip().split('\n') if u.strip() and u not in phase_findings["urls"]],
                   "urls")
        
        # ═══ Step 5: katana 主动爬虫（能渲染JS、发现SPA隐藏路由）═══
        if phase_findings["alive_hosts"]:
            # 取前5个存活主机做主动爬虫
            hosts_to_crawl = [h.split()[0] if ' ' in h else h 
                             for h in phase_findings["alive_hosts"][:5]]
            pipe_cmd = self._pipe_lines(hosts_to_crawl)
            self._step("katana主动爬虫", target, phase_findings, findings,
                       f"{pipe_cmd} | katana -d 3 -jc -silent -rate-limit 10 -c 3 2>/dev/null | sort -u | head -300",
                       lambda out: [u for u in out.strip().split('\n') 
                                   if u.strip() and u not in phase_findings["urls"]],
                       "urls")
        
        # ═══ Step 6: JS 文件提取（高价值：密钥、内部API、隐藏端点）═══
        all_urls = phase_findings["urls"]
        js_urls = [u for u in all_urls if '.js' in u.lower() and not u.endswith('.json')]
        if js_urls:
            phase_findings["js_files"] = list(set(js_urls))[:100]
            self.logger.log_event("FINDING", f"发现 {len(phase_findings['js_files'])} 个JS文件")
            
            # 用 grep 快速扫 JS 中的 API 端点和密钥
            js_sample = js_urls[:20]
            pipe_cmd = self._pipe_lines(js_sample)
            self._step("JS接口/密钥提取", target, phase_findings, findings,
                       f"{pipe_cmd} | while read js; do "
                       f"curl -s --max-time 10 \"$js\" 2>/dev/null | "
                       f"grep -oE '(api|internal|admin|v[0-9])/[a-zA-Z0-9_/]+' | "
                       f"sort -u; done | sort -u | head -100",
                       self._parse_js_endpoints,
                       "urls")
            
            # 密钥模式匹配
            pipe_cmd = self._pipe_lines(js_sample[:10])
            self._step("JS密钥泄露检测", target, phase_findings, findings,
                       f"{pipe_cmd} | while read js; do "
                       f"curl -s --max-time 10 \"$js\" 2>/dev/null | "
                       f"grep -oEi '(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|aws_|AKIA)[\"\\x27:= ]+[a-zA-Z0-9/+_\\-]{{16,}}' | "
                       f"head -5; done",
                       self._parse_js_secrets,
                       "urls")
        
        # ═══ Step 7: 子域名接管检测（快速）═══
        if phase_findings["subdomains"]:
            pipe_cmd = self._pipe_lines(phase_findings["subdomains"][:100])
            self._step("子域名接管检测", target, phase_findings, findings,
                       f"{pipe_cmd} | while read sub; do "
                       f"host \"$sub\" 2>/dev/null | grep -q 'NXDOMAIN\\|not found' && echo \"TAKEOVER_CANDIDATE: $sub\"; "
                       f"done | head -20",
                       self._parse_takeover,
                       "urls")
        
        # ═══ Step 8: AI 决策是否继续深入 ═══
        if self.mode == "auto":
            decision = self.engine.decide_next_action("recon", {**findings, **phase_findings}, target)
            if decision.get("action") == "execute":
                cmd = decision.get("command", "")
                if cmd and self._safe_command(cmd, target):
                    self._step("AI决策命令", target, phase_findings, findings,
                               cmd, lambda out: [], None)
        
        return phase_findings
    
    def _parse_httpx_tech(self, output: str) -> list:
        """解析 httpx 带技术栈检测的输出，同时提取存活主机和技术栈信息"""
        hosts = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            # httpx 输出格式: https://example.com [200] [Title] [tech1,tech2]
            hosts.append(line)
            # 提取技术栈标记到日志
            if '[' in line:
                self.logger.log_event("TECH", line[:200])
        return hosts
    
    def _parse_js_endpoints(self, output: str) -> list:
        """解析从JS中提取的API端点，补全为完整URL"""
        endpoints = []
        for line in output.strip().split('\n'):
            path = line.strip()
            if path and len(path) > 3:
                # 标记为从 JS 中发现的端点
                endpoints.append(f"[JS_ENDPOINT] /{path}")
        if endpoints:
            self.logger.log_event("FINDING", f"从JS中发现 {len(endpoints)} 个隐藏端点")
        return endpoints
    
    def _parse_js_secrets(self, output: str) -> list:
        """解析JS中的密钥泄露"""
        secrets = []
        for line in output.strip().split('\n'):
            if line.strip() and len(line.strip()) > 10:
                secrets.append(f"[JS_SECRET] {line.strip()[:200]}")
                self.logger.log_event("FINDING", f"⚠️ JS密钥泄露: {line.strip()[:100]}")
        return secrets
    
    def _parse_takeover(self, output: str) -> list:
        """解析子域名接管候选"""
        candidates = []
        for line in output.strip().split('\n'):
            if 'TAKEOVER_CANDIDATE:' in line:
                sub = line.replace('TAKEOVER_CANDIDATE:', '').strip()
                candidates.append(f"[TAKEOVER] {sub}")
                self.logger.log_event("FINDING", f"⚠️ 子域名接管候选: {sub}")
        return candidates
