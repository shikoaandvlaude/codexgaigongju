"""Report phase: generate reports only for gate-passed findings."""

import os
import platform
import re
from datetime import datetime

from .base import BasePhase

try:
    from report_gate import filter_reportable_findings
except ImportError:
    try:
        from ..report_gate import filter_reportable_findings
    except ImportError:
        filter_reportable_findings = None


class ReportPhase(BasePhase):
    """Generate SRC-style reports for findings that pass the strict report gate."""

    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {}

        self.logger.log_phase_start("报告生成 (Report)")

        vulns = findings.get("vulnerabilities", [])
        validated = [
            v
            for v in vulns
            if v.get("validated") or v.get("deep_validated") or v.get("real_validated") or v.get("verified_4proof")
        ]

        if not validated:
            self.logger.log_event("SKIP", "No validated findings to report")
            return phase_findings

        if filter_reportable_findings and self.engine.config.get("report_gate", {}).get("enabled", True):
            reportable, rejected = filter_reportable_findings(validated, self.engine.config)
            for vuln, failures in rejected:
                self.logger.log_event(
                    "SKIP",
                    f"report gate rejected {vuln.get('type')} @ {vuln.get('url', '?')}: "
                    f"{'; '.join(failures)}",
                )
            validated = reportable

        if not validated:
            self.logger.log_event("SKIP", "Report gate blocked all findings; keep them as leads, not reports")
            return phase_findings

        desktop = self._get_desktop()
        for i, vuln in enumerate(validated, 1):
            report = self._generate_report(target, vuln)
            filename = self._safe_filename(f"vuln_report_{target}_{vuln.get('type', 'unknown')}_{i}.md")
            filepath = os.path.join(desktop, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report)

            self.logger.log_event("FINDING", f"report generated: {filepath}")

        return phase_findings

    def _generate_report(self, target: str, vuln: dict) -> str:
        prompt = f"""Write a concise Chinese SRC/HackerOne-style vulnerability report.

Use only the evidence below. Do not invent requests, responses, impact, accounts, or data.
Avoid theoretical language such as "could/might/可能" unless it is clearly marked as a limitation.

Target: {target}
Type: {vuln.get('type')}
URL: {vuln.get('url')}
Severity: {vuln.get('severity')}
Impact: {vuln.get('impact')}
Detail: {vuln.get('detail')}
Evidence: {vuln.get('evidence') or vuln.get('validation_evidence')}
Reproduction count: {vuln.get('reproduction_count')}
Validation confidence: {vuln.get('validation_confidence') or vuln.get('confidence')}
Report gate failures: {vuln.get('report_gate_failures', [])}

Format:
# 漏洞标题
## 一、漏洞概述
## 二、复现步骤
## 三、证据
## 四、安全影响
## 五、修复建议
"""

        report = self.engine.think(prompt)

        header = f"""---
target: {target}
type: {vuln.get('type')}
severity: {vuln.get('severity')}
url: {vuln.get('url')}
date: {datetime.now().strftime('%Y-%m-%d')}
agent: Bai Auto-Hunt v1.0
report_gate_passed: {vuln.get('report_gate_passed', True)}
reproduction_count: {vuln.get('reproduction_count')}
---

"""
        return header + report

    def _safe_filename(self, filename: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._") or "vuln_report.md"

    def _get_desktop(self) -> str:
        system = platform.system()
        if system in {"Windows", "Darwin"}:
            return os.path.join(os.path.expanduser("~"), "Desktop")
        for name in ["Desktop", "桌面"]:
            path = os.path.join(os.path.expanduser("~"), name)
            if os.path.exists(path):
                return path
        return os.path.expanduser("~")
