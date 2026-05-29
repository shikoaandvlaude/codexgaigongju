"""Report Phase — 报告生成阶段"""

import os
import platform
from datetime import datetime
from .base import BasePhase


class ReportPhase(BasePhase):
    """报告生成：为每个确认漏洞生成 SRC 提交格式报告"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {}
        
        self.logger.log_phase_start("报告生成 (Report)")
        
        vulns = findings.get('vulnerabilities', [])
        validated = [v for v in vulns if v.get('validated')]
        
        if not validated:
            self.logger.log_event("SKIP", "无已验证漏洞，跳过报告生成")
            return phase_findings
        
        # 为每个漏洞生成报告
        for i, vuln in enumerate(validated):
            report = self._generate_report(target, vuln)
            
            # 保存报告到桌面
            desktop = self._get_desktop()
            filename = f"vuln_report_{target}_{vuln.get('type', 'unknown')}_{i+1}.md"
            filepath = os.path.join(desktop, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
            
            self.logger.log_event("FINDING", f"报告已生成: {filepath}")
        
        return phase_findings
    
    def _generate_report(self, target: str, vuln: dict) -> str:
        """用 AI 生成完整报告"""
        
        prompt = f"""请生成一份中国 SRC 平台标准格式的漏洞报告（中文）：

漏洞信息：
- 目标: {target}
- 类型: {vuln.get('type')}
- URL: {vuln.get('url')}
- 严重程度: {vuln.get('severity')}
- 详情: {vuln.get('detail')}

报告格式要求：
# 漏洞标题（简洁明确）
## 一、漏洞概述
## 二、复现步骤（带具体请求/响应）
## 三、危害说明
## 四、修复建议

注意：不要编造不存在的数据，基于实际发现写。"""
        
        report = self.engine.think(prompt)
        
        # 加上元信息头
        header = f"""---
target: {target}
type: {vuln.get('type')}
severity: {vuln.get('severity')}
url: {vuln.get('url')}
date: {datetime.now().strftime('%Y-%m-%d')}
agent: Bai Auto-Hunt v1.0
---

"""
        return header + report
    
    def _get_desktop(self) -> str:
        """获取桌面路径"""
        system = platform.system()
        if system == "Windows":
            return os.path.join(os.path.expanduser("~"), "Desktop")
        elif system == "Darwin":
            return os.path.join(os.path.expanduser("~"), "Desktop")
        else:
            for p in ["Desktop", "桌面"]:
                path = os.path.join(os.path.expanduser("~"), p)
                if os.path.exists(path):
                    return path
            return os.path.expanduser("~")
