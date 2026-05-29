"""Validate Phase — 漏洞验证阶段"""

from .base import BasePhase


class ValidatePhase(BasePhase):
    """漏洞验证：7问门控，确认漏洞真实可利用"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"vulnerabilities": []}
        
        self.logger.log_phase_start("漏洞验证 (Validate)")
        
        vulns = findings.get('vulnerabilities', [])
        if not vulns:
            self.logger.log_event("SKIP", "无漏洞需要验证")
            return phase_findings
        
        for i, vuln in enumerate(vulns[:5]):  # 最多验证5个
            self.logger.log_event("FINDING", f"验证第 {i+1}/{min(len(vulns), 5)} 个: {vuln.get('type')} @ {vuln.get('url', '?')}")
            
            # AI 7问门控
            validation = self.engine.think(f"""
对以下疑似漏洞进行 7 问门控验证：

漏洞类型: {vuln.get('type')}
URL: {vuln.get('url')}
详情: {vuln.get('detail')}

7个问题：
1. 这个漏洞是真实可复现的吗？（不是误报）
2. 攻击者能实际利用吗？（不是理论上的）
3. 影响范围有多大？（单用户/多用户/全站）
4. 需要什么前提条件？（登录/特定权限）
5. 能造成什么实际危害？
6. 是否有证据证明？（截图/响应）
7. 严重程度评估？（严重/高危/中危/低危）

回答 VALID（确认）或 INVALID（误报），并给出理由和严重程度。
格式: VALID/INVALID | 严重程度 | 一句话理由
""")
            
            if "VALID" in validation.upper():
                vuln["validated"] = True
                severity = "medium"
                if "严重" in validation or "critical" in validation.lower():
                    severity = "critical"
                elif "高危" in validation or "high" in validation.lower():
                    severity = "high"
                vuln["severity"] = severity
                phase_findings["vulnerabilities"].append(vuln)
                
                self.logger.log_event("FINDING", f"✓ 确认漏洞: [{severity}] {vuln.get('type')}")
                
                # 全自动模式下发现高危/严重 → 暂停
                if self.mode == "auto" and severity in ["critical", "high"]:
                    try:
                        from rich.prompt import Confirm
                        from rich.console import Console
                        Console().print(f"\n[bold red]⚠️ 发现 {severity} 漏洞! 请确认是否继续[/bold red]")
                        if not Confirm.ask("继续验证剩余漏洞?", default=True):
                            break
                    except ImportError:
                        pass
            else:
                self.logger.log_event("SKIP", f"✗ 误报: {vuln.get('type')} — {validation[:100]}")
        
        return phase_findings
