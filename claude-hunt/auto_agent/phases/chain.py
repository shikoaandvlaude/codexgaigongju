"""Chain Phase — 自动组链阶段

核心理念：
  单个低危发现不值钱，但 A + B + C 组合成链 = 高危/严重
  这是 Top 1% 猎人和普通猎人的最大区别

已知高价值链：
  1. Open Redirect → OAuth token theft → ATO
  2. SSRF → Cloud metadata → IAM credential → RCE
  3. XSS (stored) → Cookie theft → ATO
  4. CORS (with credentials) → Credentialed data theft
  5. IDOR (read) → 提权到 write/delete
  6. GraphQL introspection → field-level auth bypass → PII exfil
  7. JWT weak key → token forge → admin takeover
  8. Subdomain takeover → cookie scope → session hijack
  9. Open Redirect + XSS → bypass CSP → steal token
  10. Directory listing → backup file → source code → hardcoded secret

本阶段在 HuntPhase 之后运行，自动分析已有发现并尝试组链。
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_url
from .base import BasePhase


# ═══ 链式攻击规则表 ═══
CHAIN_RULES = [
    {
        "name": "Open Redirect → OAuth Token Theft",
        "signal_a": ["Open Redirect"],
        "requires": ["oauth", "redirect_uri", "authorize", "login", "sso"],
        "severity": "critical",
        "description": "开放重定向 + OAuth redirect_uri 参数 = 窃取授权码/token",
        "test_method": "redirect_oauth",
    },
    {
        "name": "SSRF → Cloud Metadata → RCE",
        "signal_a": ["SSRF"],
        "requires": ["metadata", "169.254", "iam", "AccessKey"],
        "severity": "critical",
        "description": "SSRF 能读 metadata + 获取 IAM 凭证 = 云上 RCE",
        "test_method": "ssrf_escalate",
    },
    {
        "name": "XSS → Account Takeover",
        "signal_a": ["XSS"],
        "requires": ["cookie", "session", "token", "auth"],
        "severity": "critical",
        "description": "XSS + HttpOnly未设置的session cookie = 账号接管",
        "test_method": "xss_ato",
    },
    {
        "name": "CORS + Credentials → Data Theft",
        "signal_a": ["CORS"],
        "requires": ["credentials", "CORS_CRED"],
        "severity": "high",
        "description": "CORS 反射 origin + allow credentials = 跨域窃取认证数据",
        "test_method": "cors_theft",
    },
    {
        "name": "IDOR Read → IDOR Write/Delete",
        "signal_a": ["IDOR"],
        "requires": [],
        "severity": "critical",
        "description": "读 IDOR 存在 → 尝试 PUT/PATCH/DELETE 同一端点",
        "test_method": "idor_escalate",
    },
    {
        "name": "GraphQL Introspection → Auth Bypass",
        "signal_a": ["GRAPHQL"],
        "requires": ["introspection", "schema", "GRAPHQL_SENSITIVE"],
        "severity": "high",
        "description": "GraphQL 开启 introspection + 敏感字段 = 越权查询",
        "test_method": "graphql_escalate",
    },
    {
        "name": "JWT Weak → Admin Takeover",
        "signal_a": ["JWT"],
        "requires": ["none", "HS256", "kid"],
        "severity": "critical",
        "description": "JWT 弱配置 → 伪造 admin role token",
        "test_method": "jwt_forge",
    },
    {
        "name": "Subdomain Takeover → Session Hijack",
        "signal_a": ["Takeover", "TAKEOVER"],
        "requires": [],
        "severity": "high",
        "description": "子域名接管 + 主域 cookie scope → 劫持用户会话",
        "test_method": "takeover_hijack",
    },
    {
        "name": "Directory Listing → Source Code → Secrets",
        "signal_a": ["JS_SECRET", "directory", "backup"],
        "requires": [],
        "severity": "high",
        "description": "目录暴露/备份文件 → 源码泄露 → 提取硬编码密钥",
        "test_method": "secret_escalate",
    },
]


class ChainPhase(BasePhase):
    """自动组链：将多个低危发现组合成高危攻击链"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"vulnerabilities": [], "chains": []}
        
        self.logger.log_phase_start("自动组链 (Chain — A→B→C)")
        
        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            class Console:
                def print(self, *a, **k): print(*a)
            console = Console()
        
        # 收集所有已有发现的信号
        all_vulns = findings.get('vulnerabilities', [])
        all_urls = findings.get('urls', []) + findings.get('params', [])
        all_secrets = findings.get('secrets', [])
        all_data_str = ' '.join(str(v) for v in all_vulns) + ' ' + ' '.join(all_urls)
        
        if not all_vulns:
            console.print("  [dim]无已有发现可供组链[/dim]")
            return phase_findings
        
        console.print(f"  [cyan]分析 {len(all_vulns)} 个发现的组链可能性...[/cyan]\n")
        
        # ═══ 逐条规则匹配 ═══
        matched_chains = []
        
        for rule in CHAIN_RULES:
            # 检查 signal_a 是否存在
            signal_found = False
            signal_vulns = []
            for vuln in all_vulns:
                vuln_str = str(vuln).lower()
                for signal in rule["signal_a"]:
                    if signal.lower() in vuln_str:
                        signal_found = True
                        signal_vulns.append(vuln)
                        break
            
            if not signal_found:
                continue
            
            # 检查 requires（辅助条件）
            requires_met = True
            if rule["requires"]:
                requires_met = any(
                    req.lower() in all_data_str.lower() 
                    for req in rule["requires"]
                )
            
            if requires_met:
                matched_chains.append({
                    "rule": rule,
                    "signal_vulns": signal_vulns,
                })
        
        if not matched_chains:
            console.print("  [dim]未发现可组合的攻击链[/dim]")
            # AI 辅助：让 LLM 从所有发现中寻找隐藏的链
            self._ai_chain_discovery(target, findings, phase_findings, console)
            return phase_findings
        
        console.print(f"  [bold green]发现 {len(matched_chains)} 条可能的攻击链！[/bold green]\n")
        
        # ═══ 逐条执行组链验证 ═══
        for chain_info in matched_chains:
            rule = chain_info["rule"]
            signal_vulns = chain_info["signal_vulns"]
            
            console.print(f"  [bold cyan]━━━ {rule['name']} ━━━[/bold cyan]")
            console.print(f"    信号: {[v.get('type','?') for v in signal_vulns[:3]]}")
            console.print(f"    链路: {rule['description']}")
            
            # 半自动模式确认
            if self.mode == "semi":
                try:
                    from rich.prompt import Confirm
                    if not Confirm.ask(f"    尝试组链？", default=True):
                        self.logger.log_event("SKIP", f"用户跳过组链: {rule['name']}")
                        continue
                except ImportError:
                    pass
            
            # 执行组链测试
            chain_result = self._execute_chain_test(
                rule, signal_vulns, target, findings, phase_findings, console
            )
            
            if chain_result:
                phase_findings["chains"].append({
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "steps": chain_result.get("steps", []),
                    "verified": chain_result.get("verified", False),
                    "evidence": chain_result.get("evidence", ""),
                })
                
                # 把确认的链加入漏洞列表
                if chain_result.get("verified"):
                    phase_findings["vulnerabilities"].append({
                        "type": f"Attack Chain: {rule['name']}",
                        "url": chain_result.get("url", "见日志"),
                        "severity": rule["severity"],
                        "detail": chain_result.get("evidence", ""),
                        "chain_steps": chain_result.get("steps", []),
                        "source": "chain_phase",
                    })
                    console.print(f"    [bold green]✓ 链确认！{rule['severity'].upper()}[/bold green]\n")
                else:
                    # 即使未完全确认也保留为高价值线索
                    phase_findings["vulnerabilities"].append({
                        "type": f"Chain Lead: {rule['name']}",
                        "url": chain_result.get("url", "见日志"),
                        "severity": "medium",
                        "detail": f"链路部分验证: {chain_result.get('evidence', '')}",
                        "chain_steps": chain_result.get("steps", []),
                        "needs_manual_verify": True,
                        "source": "chain_phase",
                    })
                    console.print(f"    [yellow]⚠ 链路部分验证，需人工补充[/yellow]\n")
        
        # ═══ AI 补充：发现隐藏的链 ═══
        self._ai_chain_discovery(target, findings, phase_findings, console)
        
        # ═══ 汇总 ═══
        confirmed = sum(1 for c in phase_findings["chains"] if c.get("verified"))
        total = len(phase_findings["chains"])
        console.print(f"\n  [bold]组链结果: {confirmed} 条确认 / {total} 条总计[/bold]")
        
        return phase_findings
    
    # ─── 组链测试分发 ─────────────────────────────────────────────
    
    def _execute_chain_test(self, rule: dict, signal_vulns: list, 
                           target: str, findings: dict, phase_findings: dict,
                           console) -> dict:
        """根据规则执行具体的组链测试"""
        method = rule.get("test_method", "")
        
        if method == "redirect_oauth":
            return self._chain_redirect_oauth(signal_vulns, target, findings, phase_findings)
        elif method == "ssrf_escalate":
            return self._chain_ssrf_escalate(signal_vulns, target, findings, phase_findings)
        elif method == "xss_ato":
            return self._chain_xss_ato(signal_vulns, target, findings, phase_findings)
        elif method == "cors_theft":
            return self._chain_cors_theft(signal_vulns, target, findings, phase_findings)
        elif method == "idor_escalate":
            return self._chain_idor_escalate(signal_vulns, target, findings, phase_findings)
        elif method == "graphql_escalate":
            return self._chain_graphql(signal_vulns, target, findings, phase_findings)
        elif method == "jwt_forge":
            return self._chain_jwt_forge(signal_vulns, target, findings, phase_findings)
        elif method == "takeover_hijack":
            return self._chain_takeover(signal_vulns, target, findings, phase_findings)
        elif method == "secret_escalate":
            return self._chain_secret(signal_vulns, target, findings, phase_findings)
        
        return None
    
    # ─── 具体组链实现 ─────────────────────────────────────────────
    
    def _chain_redirect_oauth(self, signal_vulns, target, findings, phase_findings) -> dict:
        """Open Redirect → OAuth token theft"""
        steps = ["发现开放重定向"]
        
        # 找到重定向漏洞的 URL
        redirect_url = ""
        for v in signal_vulns:
            if v.get("url") and v["url"] != "见日志":
                redirect_url = v["url"]
                break
        
        # 在目标上找 OAuth 端点
        all_urls = findings.get('urls', []) + findings.get('params', [])
        oauth_urls = [u for u in all_urls if any(kw in u.lower() for kw in 
                     ['oauth', 'authorize', 'redirect_uri', 'response_type', 'client_id'])]
        
        if oauth_urls:
            steps.append(f"发现OAuth端点: {oauth_urls[0][:80]}")
            
            # 尝试注入 redirect_uri
            oauth_url = oauth_urls[0]
            safe_url = sanitize_url(oauth_url)
            
            # 检查 redirect_uri 是否可控
            test_uri = f"https://evil.com/callback"
            if 'redirect_uri=' in oauth_url:
                test_url = re.sub(r'redirect_uri=[^&]*', f'redirect_uri={test_uri}', safe_url)
            else:
                separator = '&' if '?' in safe_url else '?'
                test_url = f"{safe_url}{separator}redirect_uri={test_uri}"
            
            self._step("OAuth redirect_uri注入", target, phase_findings, findings,
                       f"curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' "
                       f"-L --max-redirs 0 --max-time 8 {shell_quote(test_url)} 2>/dev/null",
                       lambda out: [], None)
            
            steps.append("尝试注入恶意 redirect_uri")
            
            return {
                "verified": bool(redirect_url and oauth_urls),
                "url": redirect_url or oauth_urls[0],
                "steps": steps,
                "evidence": f"开放重定向: {redirect_url[:80]} + OAuth端点: {oauth_urls[0][:80]}"
            }
        
        # 没有 OAuth 端点，但重定向本身也有价值
        return {
            "verified": False,
            "url": redirect_url,
            "steps": steps + ["未发现OAuth端点，链未完成"],
            "evidence": f"开放重定向已确认，但目标未发现OAuth端点"
        }
    
    def _chain_ssrf_escalate(self, signal_vulns, target, findings, phase_findings) -> dict:
        """SSRF → metadata → IAM → RCE"""
        steps = ["SSRF已确认"]
        
        # 检查是否已经读到了 metadata
        for v in signal_vulns:
            detail = v.get("detail", "").lower()
            if 'metadata' in detail or 'accesskey' in detail or 'iam' in detail:
                steps.append("成功读取云 metadata")
                steps.append("获取 IAM 凭证")
                return {
                    "verified": True,
                    "url": v.get("url", ""),
                    "steps": steps,
                    "evidence": f"SSRF → metadata → IAM credential: {v.get('detail', '')[:200]}"
                }
        
        # SSRF 存在但还没读到 metadata，尝试深入
        steps.append("尝试读取 IAM security-credentials")
        return {
            "verified": False,
            "url": signal_vulns[0].get("url", "") if signal_vulns else "",
            "steps": steps,
            "evidence": "SSRF确认，需进一步获取IAM凭证"
        }
    
    def _chain_xss_ato(self, signal_vulns, target, findings, phase_findings) -> dict:
        """XSS → Cookie theft → ATO"""
        steps = ["XSS已确认"]
        
        xss_url = signal_vulns[0].get("url", "") if signal_vulns else ""
        
        # 检查目标 cookie 是否有 HttpOnly
        alive = findings.get('alive_hosts', [])
        if alive:
            host = alive[0].split()[0] if ' ' in alive[0] else alive[0]
            safe_host = sanitize_url(host)
            
            self._step("Cookie HttpOnly检查", target, phase_findings, findings,
                       f"curl -s -I --max-time 8 {shell_quote(safe_host)} 2>/dev/null | "
                       f"grep -i 'set-cookie' | grep -iv 'httponly'",
                       lambda out: [], None)
            
            steps.append("检查session cookie HttpOnly属性")
        
        return {
            "verified": bool(xss_url),
            "url": xss_url,
            "steps": steps + ["XSS + 无HttpOnly cookie = ATO"],
            "evidence": f"XSS确认: {xss_url[:100]}，需验证cookie是否有HttpOnly保护"
        }
    
    def _chain_cors_theft(self, signal_vulns, target, findings, phase_findings) -> dict:
        """CORS with credentials → data theft"""
        steps = ["CORS错配+credentials已确认"]
        
        cors_url = ""
        for v in signal_vulns:
            if 'CORS_CRED' in str(v) or 'credentials' in str(v).lower():
                cors_url = v.get("url", "")
                break
        
        if cors_url:
            steps.append(f"目标: {cors_url}")
            steps.append("可构造恶意页面跨域读取认证后数据")
            return {
                "verified": True,
                "url": cors_url,
                "steps": steps,
                "evidence": f"CORS + credentials: 可跨域窃取登录用户数据 @ {cors_url[:100]}"
            }
        
        return {
            "verified": False,
            "url": signal_vulns[0].get("url", "") if signal_vulns else "",
            "steps": steps,
            "evidence": "CORS错配确认，需验证是否带credentials"
        }
    
    def _chain_idor_escalate(self, signal_vulns, target, findings, phase_findings) -> dict:
        """IDOR read → write/delete"""
        steps = ["IDOR读确认"]
        
        idor_url = signal_vulns[0].get("url", "") if signal_vulns else ""
        
        if idor_url and idor_url != "见日志":
            # 尝试 PUT/PATCH/DELETE
            safe_url = sanitize_url(idor_url)
            
            for method in ["PUT", "PATCH", "DELETE"]:
                self._step(f"IDOR {method}提权: {idor_url[:40]}", target, phase_findings, findings,
                           f"curl -s -X {method} -w '\\nHTTP_CODE:%{{http_code}}' "
                           f"--max-time 8 {shell_quote(safe_url)} 2>/dev/null | tail -3",
                           lambda out: [], None)
            
            steps.append("尝试 PUT/PATCH/DELETE 方法提权")
            return {
                "verified": True,
                "url": idor_url,
                "steps": steps,
                "evidence": f"IDOR读已确认，尝试写/删提权 @ {idor_url[:100]}"
            }
        
        return {
            "verified": False,
            "url": "",
            "steps": steps + ["IDOR URL未明确，需手动指定"],
            "evidence": "IDOR存在但需确认具体端点"
        }
    
    def _chain_graphql(self, signal_vulns, target, findings, phase_findings) -> dict:
        """GraphQL introspection → auth bypass → PII"""
        steps = ["GraphQL introspection开启"]
        
        # 从 params 中找 GraphQL 敏感字段
        all_params = findings.get('params', [])
        sensitive = [p for p in all_params if 'GRAPHQL_SENSITIVE' in p]
        
        if sensitive:
            steps.append(f"发现敏感字段: {sensitive[0][:100]}")
            steps.append("可尝试直接查询敏感字段（绕过field-level auth）")
            return {
                "verified": True,
                "url": "GraphQL endpoint",
                "steps": steps,
                "evidence": f"GraphQL schema暴露敏感字段: {sensitive[0][:200]}"
            }
        
        return {
            "verified": False,
            "url": "",
            "steps": steps + ["未发现明确敏感字段"],
            "evidence": "Introspection开启但需进一步测试field-level auth"
        }
    
    def _chain_jwt_forge(self, signal_vulns, target, findings, phase_findings) -> dict:
        """JWT weak → admin token forge"""
        steps = ["JWT弱配置发现"]
        
        jwt_type = ""
        for v in signal_vulns:
            vtype = v.get("type", "").lower()
            if "none" in vtype:
                jwt_type = "alg:none"
                steps.append("alg:none — 可伪造任意claim")
            elif "hs256" in vtype:
                jwt_type = "HS256弱密钥"
                steps.append("HS256 — 尝试常见弱密钥爆破")
            elif "kid" in vtype:
                jwt_type = "kid注入"
                steps.append("kid参数 — 尝试SQLi/路径遍历")
        
        if jwt_type:
            steps.append("伪造admin role → 垂直提权")
            return {
                "verified": True,
                "url": "JWT token",
                "steps": steps,
                "evidence": f"JWT {jwt_type} → 可伪造admin token实现垂直提权"
            }
        
        return {"verified": False, "url": "", "steps": steps, "evidence": "JWT异常需进一步分析"}
    
    def _chain_takeover(self, signal_vulns, target, findings, phase_findings) -> dict:
        """Subdomain takeover → session hijack"""
        steps = ["子域名接管确认"]
        
        sub = signal_vulns[0].get("url", "") if signal_vulns else ""
        
        if sub:
            steps.append(f"接管子域: {sub}")
            steps.append(f"如果主域cookie scope为 .{target}，可劫持session")
            return {
                "verified": True,
                "url": sub,
                "steps": steps,
                "evidence": f"子域名接管 {sub} → 如主域cookie scope含父域则可劫持session"
            }
        
        return {"verified": False, "url": "", "steps": steps, "evidence": "需确认具体子域"}
    
    def _chain_secret(self, signal_vulns, target, findings, phase_findings) -> dict:
        """Secret leak → validate → access"""
        steps = ["密钥/凭证泄露发现"]
        
        secrets = findings.get('secrets', [])
        js_secrets = [v for v in signal_vulns if 'SECRET' in str(v).upper()]
        
        all_secrets = secrets + [str(v) for v in js_secrets]
        
        if all_secrets:
            steps.append(f"发现 {len(all_secrets)} 个疑似密钥")
            steps.append("需验证密钥是否有效（调用对应API）")
            return {
                "verified": bool(all_secrets),
                "url": "见密钥列表",
                "steps": steps,
                "evidence": f"密钥泄露 {len(all_secrets)} 个，需验证可用性"
            }
        
        return {"verified": False, "url": "", "steps": steps, "evidence": ""}
    
    # ─── AI 辅助组链 ─────────────────────────────────────────────
    
    def _ai_chain_discovery(self, target: str, findings: dict, phase_findings: dict, console):
        """用 LLM 从所有发现中寻找隐藏的攻击链"""
        all_vulns = findings.get('vulnerabilities', []) + phase_findings.get('vulnerabilities', [])
        
        if not all_vulns or len(all_vulns) < 2:
            return
        
        # 构建发现摘要
        vuln_summary = '\n'.join([
            f"- [{v.get('severity','?')}] {v.get('type','?')}: {v.get('detail','')[:80]}"
            for v in all_vulns[:30]
        ])
        
        analysis = self.engine.think(f"""
你是精英赏金猎人。以下是目标 {target} 的所有发现。

{vuln_summary}

任务：找出可能的攻击链组合。规则：
1. 只列出你认为真正可行的链（不是理论上的）
2. 每条链说明：A(起点) + B(跳板) → C(最终影响)
3. 给出具体的利用步骤（curl级别）
4. 如果没有可行的链，回答 "NO_CHAIN"

最多列出3条最有价值的链。
""")
        
        if analysis and "NO_CHAIN" not in analysis.upper():
            self.logger.log_event("FINDING", f"AI发现潜在攻击链")
            console.print(f"\n  [magenta]AI 链发现:[/magenta]")
            console.print(f"  {analysis[:500]}")
            
            phase_findings["vulnerabilities"].append({
                "type": "AI Chain Analysis",
                "url": target,
                "severity": "medium",
                "detail": analysis[:500],
                "needs_manual_verify": True,
                "source": "ai_chain_analysis",
            })
