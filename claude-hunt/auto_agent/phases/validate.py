"""Validate phase: reduce noise before report generation."""

from .base import BasePhase

try:
    from false_positive_filter import FalsePositiveFilter
except ImportError:
    try:
        from ..false_positive_filter import FalsePositiveFilter
    except ImportError:
        FalsePositiveFilter = None


class ValidatePhase(BasePhase):
    """Validate candidate findings with FP filtering and AI 7-question review."""

    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"vulnerabilities": []}

        self.logger.log_phase_start("漏洞验证 (Validate)")

        vulns = findings.get("vulnerabilities", [])
        if not vulns:
            self.logger.log_event("SKIP", "No vulnerabilities to validate")
            return phase_findings

        if FalsePositiveFilter:
            fp_filter = FalsePositiveFilter(self.engine, self.logger, self.engine.config)
            before_count = len(vulns)
            vulns = fp_filter.apply_filter(vulns, self.mode)
            filtered_count = before_count - len(vulns)
            if filtered_count:
                self.logger.log_event(
                    "SKIP",
                    f"false-positive prefilter removed {filtered_count} low-confidence findings",
                )

        validation_cfg = self.engine.config.get("validation", {})
        min_confidence = validation_cfg.get("min_confidence")
        if min_confidence is not None:
            try:
                min_confidence = float(min_confidence)
                if min_confidence <= 1:
                    min_confidence *= 100
            except (TypeError, ValueError):
                min_confidence = None

        if min_confidence:
            kept = []
            for vuln in vulns:
                confidence = vuln.get("validation_confidence", vuln.get("confidence", 0))
                try:
                    confidence = float(confidence)
                    if confidence <= 1:
                        confidence *= 100
                except (TypeError, ValueError):
                    confidence = 0
                if confidence and confidence < min_confidence:
                    self.logger.log_event(
                        "SKIP",
                        f"validation confidence below threshold: {vuln.get('type')} "
                        f"[{confidence:.0f} < {min_confidence:.0f}]",
                    )
                else:
                    kept.append(vuln)
            vulns = kept

        for i, vuln in enumerate(vulns[:5]):
            self.logger.log_event(
                "FINDING",
                f"Validating {i + 1}/{min(len(vulns), 5)}: {vuln.get('type')} @ {vuln.get('url', '?')}",
            )

            validation = self.engine.think(f"""
Run a strict 7-question validation gate for this suspected vulnerability.

Type: {vuln.get('type')}
URL: {vuln.get('url')}
Detail: {vuln.get('detail')}
Evidence: {vuln.get('evidence') or vuln.get('validation_evidence')}
Impact: {vuln.get('impact')}
Confidence: {vuln.get('confidence')}
Reproduction count: {vuln.get('reproduction_count', 0)}

Questions:
1. Is the issue concretely exploitable, not theoretical?
2. Is there real evidence from requests/responses?
3. If IDOR/authz, was it tested with two owned accounts?
4. Is it not a standalone always-rejected issue?
5. Is it reproducible at least twice?
6. Is the exposed data/action not public already?
7. Does severity/CVSS match actual impact?

Reply exactly:
VALID|severity|one-line proof
or
INVALID|reason
""")

            if validation.strip().upper().startswith("VALID"):
                vuln["validated"] = True
                severity = "medium"
                validation_l = validation.lower()
                if "critical" in validation_l or "严重" in validation:
                    severity = "critical"
                elif "high" in validation_l or "高危" in validation:
                    severity = "high"
                elif "low" in validation_l or "低危" in validation:
                    severity = "low"
                vuln["severity"] = severity
                vuln["validation_gate_ai"] = validation[:500]
                phase_findings["vulnerabilities"].append(vuln)

                self.logger.log_event("FINDING", f"validated finding: [{severity}] {vuln.get('type')}")

                if self.mode == "auto" and severity in ["critical", "high"]:
                    try:
                        from rich.console import Console
                        from rich.prompt import Confirm

                        Console().print(f"\n[bold red]High-impact finding: {severity}[/bold red]")
                        if not Confirm.ask("Continue validating remaining findings?", default=True):
                            break
                    except ImportError:
                        pass
            else:
                self.logger.log_event(
                    "SKIP",
                    f"validation rejected {vuln.get('type')}: {validation[:100]}",
                )

        return phase_findings
