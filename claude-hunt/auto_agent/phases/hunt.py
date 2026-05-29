"""Hunt Phase — 漏洞挖掘阶段"""

import sys
import os
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_url
from .base import BasePhase


class HuntPhase(BasePhase):
    """漏洞挖掘：XSS、CORS、密钥泄露、并发竞态、IDOR越权"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"vulnerabilities": [], "secrets": []}
        
        self.logger.log_phase_start("漏洞挖掘 (Hunt)")
        
        # Step 1: Nuclei 扫描（限速+只扫高危）
        alive = findings.get('alive_hosts', [])
        if alive:
            pipe_cmd = self._pipe_lines(alive[:20])
            self._step("Nuclei高危扫描", target, phase_findings, findings,
                       f"{pipe_cmd} | nuclei -severity critical,high -rate-limit 5 -c 3 -silent 2>/dev/null | head -50",
                       self._parse_nuclei,
                       "vulnerabilities")
        
        # Step 2: XSS 检测 (dalfox)
        params = findings.get('params', [])
        xss_urls = [p for p in params if '?' in p][:10]
        if xss_urls:
            pipe_cmd = self._pipe_lines(xss_urls)
            self._step("Dalfox XSS检测", target, phase_findings, findings,
                       f"{pipe_cmd} | dalfox pipe --worker 2 --delay 300 --silence 2>/dev/null | head -20",
                       self._parse_dalfox,
                       "vulnerabilities")
        
        # Step 3: CORS 错配检测
        if alive:
            pipe_cmd = self._pipe_lines(alive[:10])
            self._step("CORS错配检测", target, phase_findings, findings,
                       f"{pipe_cmd} | while read h; do curl -s -H 'Origin: https://evil.com' -I \"$h\" 2>/dev/null | grep -i 'access-control' && echo \"CORS: $h\"; done | head -20",
                       self._parse_cors,
                       "vulnerabilities")
        
        # Step 4: 密钥泄露扫描
        safe_org = target.split('.')[0] if '.' in target else target
        self._step("TruffleHog密钥扫描", target, phase_findings, findings,
                   f"trufflehog github --org={shell_quote(safe_org)} --only-verified --json 2>/dev/null | head -10",
                   self._parse_secrets,
                   "secrets")
        
        # Step 5: 并发竞态检测（SRC高价值）
        self._race_condition_test(target, findings, phase_findings)
        
        # Step 6: IDOR 越权检测（多账号对比）
        self._idor_test(target, findings, phase_findings)
        
        # Step 7: AI 决策额外攻击面
        if self.mode == "auto":
            combined = {**findings, **phase_findings}
            decision = self.engine.decide_next_action("hunt", combined, target)
            if decision.get("action") == "execute":
                cmd = decision.get("command", "")
                if cmd and self._safe_command(cmd, target):
                    self._step(f"AI: {decision.get('reason', '额外探测')}", target, 
                               phase_findings, findings, cmd, lambda out: [], None)
        
        return phase_findings
    
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
