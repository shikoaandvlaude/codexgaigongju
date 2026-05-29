"""
Verify Phase — 漏洞深度验证阶段（四证齐全）
在 validate(7问门控) 之后、report(出报告) 之前执行。
确保 AI 发现的漏洞不是幻觉/误报。

验证四证：
1. Code Path Proof — 具体文件、行号、调用链
2. Runtime Proof — 本地运行验证（如果可能）
3. Observable Artifact — HTTP响应、日志、截图
4. Counter-Hypothesis — 主动找"为什么它可能不成立"
"""

from .base import BasePhase


class VerifyPhase(BasePhase):
    """漏洞深度验证：四证齐全 + 反证检查"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"vulnerabilities": []}
        
        self.logger.log_phase_start("深度验证 (Verify — 四证齐全)")
        
        vulns = findings.get('vulnerabilities', [])
        validated = [v for v in vulns if v.get('validated')]
        
        if not validated:
            self.logger.log_event("SKIP", "无已验证漏洞需要深度验证")
            return phase_findings
        
        try:
            from rich.console import Console
            from rich.prompt import Confirm
            console = Console()
        except ImportError:
            class Console:
                def print(self, *a, **k): print(*a)
            class Confirm:
                @staticmethod
                def ask(msg, default=True): return input(f"{msg} (y/n): ").lower() != 'n'
            console = Console()
        
        for i, vuln in enumerate(validated):
            console.print(f"\n[bold cyan]━━━ 验证第 {i+1}/{len(validated)} 个漏洞 ━━━[/bold cyan]")
            console.print(f"  类型: {vuln.get('type')}")
            console.print(f"  URL: {vuln.get('url')}")
            console.print(f"  严重程度: {vuln.get('severity')}")
            
            # ═══════════════════════════════════════════
            # 证1: Code Path Proof（代码路径证明）
            # ═══════════════════════════════════════════
            self.logger.log_event("FINDING", f"[证1] 代码路径分析: {vuln.get('type')}")
            
            code_proof = self.engine.think(f"""
对以下漏洞进行代码路径验证：

目标: {target}
漏洞类型: {vuln.get('type')}
URL: {vuln.get('url')}
详情: {vuln.get('detail')}

请回答：
1. 【文件位置】漏洞代码在哪个文件、哪一行？
2. 【调用链】从入口到漏洞触发的完整调用链是什么？
3. 【关键代码】触发漏洞的关键代码片段是什么？
4. 【认证检查】这个路由/接口有没有中间件认证？有没有全局认证？

如果你不确定，请明确说"无法确认"。不要猜测。
""")
            
            self.logger.log_command("AI: Code Path Analysis", 
                                    {"success": True, "output": code_proof, "returncode": 0},
                                    "代码路径证明")
            
            # ═══════════════════════════════════════════
            # 证2: Runtime Proof（运行时证明）
            # ═══════════════════════════════════════════
            self.logger.log_event("FINDING", f"[证2] 运行时验证尝试")
            
            runtime_proof = self.engine.think(f"""
对于漏洞 {vuln.get('type')} @ {vuln.get('url')}：

问题：
1. 你是否实际执行了 HTTP 请求来验证这个漏洞？
2. 如果是，请给出：
   - 具体的 curl 命令
   - 实际收到的 HTTP 响应状态码
   - 响应 body 的关键内容
3. 如果没有实际执行，请明确回答：
   "此发现仅基于静态分析/工具输出，未经运行时确认。"

诚实回答。不要编造响应内容。
""")
            
            self.logger.log_command("AI: Runtime Verification",
                                    {"success": True, "output": runtime_proof, "returncode": 0},
                                    "运行时证明")
            
            # ═══════════════════════════════════════════
            # 证3: Observable Artifact（可观察证据）
            # ═══════════════════════════════════════════
            self.logger.log_event("FINDING", f"[证3] 证据收集")
            
            artifact = self.engine.think(f"""
对于漏洞 {vuln.get('type')} @ {vuln.get('url')}：

请整理你手上的证据：
1. 有没有实际的 HTTP 请求/响应记录？
2. 有没有工具输出（nuclei/dalfox/trufflehog等）的原始输出？
3. 有没有日志/截图/terminal transcript？
4. 证据的可信度如何（1-10分）？为什么？

如果证据不足，请明确说明缺什么。
""")
            
            self.logger.log_command("AI: Evidence Collection",
                                    {"success": True, "output": artifact, "returncode": 0},
                                    "证据收集")
            
            # ═══════════════════════════════════════════
            # 证4: Counter-Hypothesis（反证检查）
            # ═══════════════════════════════════════════
            self.logger.log_event("FINDING", f"[证4] 反证检查（找理由推翻自己）")
            
            counter = self.engine.think(f"""
现在假设这个漏洞是 **误报**。

漏洞: {vuln.get('type')} @ {vuln.get('url')}

请主动寻找以下可能让这个漏洞不成立的因素：
1. 有没有全局认证中间件（app.use/router.use）我可能漏看了？
2. 有没有部署配置使得该路由默认不可达？
3. 有没有其他防护层（WAF/CDN/IP白名单）？
4. 工具输出是不是误报（nuclei模板匹配不精确）？
5. 有没有任何"它可能不是真洞"的理由？

诚实列出所有反对理由。最后给出你的最终判断：
- CONFIRMED（确认是真洞，反证都不成立）
- UNCERTAIN（有疑点，需要更多验证）
- LIKELY_FALSE（很可能是误报）
""")
            
            self.logger.log_command("AI: Counter-Hypothesis Check",
                                    {"success": True, "output": counter, "returncode": 0},
                                    "反证检查")
            
            # ═══════════════════════════════════════════
            # 最终判定
            # ═══════════════════════════════════════════
            final_verdict = "UNCERTAIN"
            if "CONFIRMED" in counter.upper():
                final_verdict = "CONFIRMED"
            elif "LIKELY_FALSE" in counter.upper():
                final_verdict = "LIKELY_FALSE"
            
            self.logger.log_event("FINDING", 
                f"[最终判定] {final_verdict} — {vuln.get('type')} @ {vuln.get('url')}")
            
            console.print(f"\n  [bold]最终判定: {final_verdict}[/bold]")
            
            # 半自动模式：让用户最终确认
            if self.mode == "semi":
                console.print(f"\n  [yellow]请你自己判断：[/yellow]")
                console.print(f"    代码证明: {code_proof[:100]}...")
                console.print(f"    运行时: {runtime_proof[:100]}...")
                console.print(f"    反证: {counter[:100]}...")
                
                user_confirm = Confirm.ask("  你认为这是真洞吗？", default=(final_verdict == "CONFIRMED"))
                if not user_confirm:
                    final_verdict = "USER_REJECTED"
                    self.logger.log_event("SKIP", f"用户判定为误报: {vuln.get('type')}")
                    continue
            
            # 只有 CONFIRMED 的才进入报告阶段
            if final_verdict == "CONFIRMED":
                vuln["verified_4proof"] = True
                vuln["code_proof"] = code_proof[:500]
                vuln["runtime_proof"] = runtime_proof[:500]
                vuln["artifact"] = artifact[:500]
                vuln["counter_check"] = counter[:500]
                phase_findings["vulnerabilities"].append(vuln)
                console.print(f"  [green]✓ 四证齐全，进入报告阶段[/green]")
            elif final_verdict == "UNCERTAIN":
                console.print(f"  [yellow]⚠ 证据不充分，建议手动补充验证后再提交[/yellow]")
                # 仍然记录但标记为 uncertain
                vuln["verified_4proof"] = False
                vuln["needs_manual_verify"] = True
                phase_findings["vulnerabilities"].append(vuln)
            else:
                console.print(f"  [red]✗ 判定为误报/证据不足，不出报告[/red]")
        
        return phase_findings
