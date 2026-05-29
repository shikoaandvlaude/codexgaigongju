"""Strict report gate for bounty/SRC submissions.

The scanner may keep weak leads for manual follow-up, but report generation
should only accept findings with concrete proof, reproducibility, and impact.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


ALWAYS_REJECTED_STANDALONE = {
    "missing_headers",
    "missing_security_headers",
    "graphql_introspection",
    "self_xss",
    "open_redirect_standalone",
    "open_redirect",
    "ssrf_dns_only",
    "logout_csrf",
    "missing_cookie_flags",
    "rate_limit_noncritical",
    "banner_disclosure",
    "version_disclosure",
    "software_version_disclosure",
    "tabnabbing",
    "clickjacking_no_sensitive_action",
}

THEORETICAL_PHRASES = (
    "could",
    "might",
    "may allow",
    "may lead",
    "possible",
    "possibly",
    "potential",
    "potentially",
    "likely",
    "suspected",
    "if an attacker",
    "theoretical",
    "maybe",
    "可能",
    "疑似",
    "理论",
    "猜测",
    "或许",
)

PROOF_TERMS = (
    "http",
    "request",
    "response",
    "status",
    "curl",
    "payload",
    "baseline",
    "diff",
    "account",
    "cookie",
    "token",
    "header",
    "json",
    "body",
    "returned",
    "observed",
    "reproduced",
    "200",
    "403",
    "请求",
    "响应",
    "状态码",
    "账号",
    "复现",
    "返回",
    "证据",
)


def _get_config(config: dict | None, section: str, default: dict | None = None) -> dict:
    if not config:
        return default or {}
    value = config.get(section)
    if isinstance(value, dict):
        return value
    return default or {}


def finding_get(finding: Any, *names: str, default: Any = None) -> Any:
    """Read the first populated field from a dict-like or object finding."""
    for name in names:
        if isinstance(finding, dict):
            value = finding.get(name)
        else:
            value = getattr(finding, name, None)
        if value not in (None, "", [], {}):
            return value
    return default


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "ok", "confirmed"}


def _normalize_type(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    aliases = {
        "open_redirect": "open_redirect_standalone",
        "redirect": "open_redirect_standalone",
        "missing_httponly": "missing_cookie_flags",
        "missing_secure_cookie": "missing_cookie_flags",
        "rate_limit": "rate_limit_noncritical",
        "version": "version_disclosure",
        "banner": "banner_disclosure",
    }
    return aliases.get(text, text)


def _text(*values: Any) -> str:
    return "\n".join(str(v) for v in values if v not in (None, "", [], {}))


def _has_theory_language(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in THEORETICAL_PHRASES)


def _has_concrete_text(value: Any, block_theory: bool = True) -> bool:
    text = str(value or "").strip()
    if len(text) < 8:
        return False
    lowered = text.lower()
    has_proof_term = any(term in lowered for term in PROOF_TERMS)
    if block_theory and _has_theory_language(text) and not has_proof_term:
        return False
    return True


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_idor_type(vuln_type: str) -> bool:
    return any(part in vuln_type for part in ("idor", "authz", "authorization", "access_control"))


def _is_cvss_reasonable(finding: Any) -> bool:
    severity = str(finding_get(finding, "severity", default="")).lower()
    cvss = _float_value(finding_get(finding, "cvss", "cvss_score", default=0.0), 0.0)
    impact_text = _text(
        finding_get(finding, "impact"),
        finding_get(finding, "security_impact"),
        finding_get(finding, "detail"),
    ).lower()

    if not cvss:
        return True
    if severity == "critical" and cvss < 9.0:
        return False
    if severity == "high" and cvss < 7.0:
        return False
    if severity in {"critical", "high"} and not any(
        term in impact_text
        for term in (
            "takeover",
            "account",
            "private",
            "sensitive",
            "token",
            "admin",
            "delete",
            "write",
            "pii",
            "payment",
            "越权",
            "接管",
            "敏感",
            "隐私",
        )
    ):
        return False
    return True


def _signal_count(finding: Any) -> int:
    signals = set()
    if _as_bool(finding_get(finding, "real_validated", "deep_validated")):
        signals.add("real_validator")
    if _as_bool(finding_get(finding, "multi_model_validated")):
        signals.add("multi_model")
    if _as_bool(finding_get(finding, "verified_4proof")):
        signals.add("four_proof")
    if _as_bool(finding_get(finding, "reproducible")) or _int_value(finding_get(finding, "reproduction_count")) >= 2:
        signals.add("reproducible")
    if finding_get(finding, "baseline_response_hash") and finding_get(finding, "payload_response_hash"):
        signals.add("baseline_compare")
    if finding_get(finding, "request_sent") and finding_get(finding, "response_received"):
        signals.add("request_response")
    if finding_get(finding, "validation_gate_ai"):
        signals.add("ai_gate")
    if _as_bool(finding_get(finding, "dual_account_tested")):
        signals.add("dual_account")

    methods = finding_get(finding, "validation_methods", "validation_method", "methods", default=[])
    if isinstance(methods, str):
        methods = [m.strip() for m in re.split(r"[,;+]", methods) if m.strip()]
    if isinstance(methods, Iterable):
        for method in methods:
            if method:
                signals.add(f"method:{str(method).lower()}")
    return len(signals)


def seven_question_gate(finding: Any, config: dict | None = None) -> tuple[bool, list[str]]:
    """Return (is_reportable, failure_reasons) for one finding."""
    report_cfg = _get_config(config, "report_gate", config if isinstance(config, dict) else {})
    validation_cfg = _get_config(config, "validation", {})
    failures: list[str] = []

    block_theory = report_cfg.get("block_theoretical_language", True)
    vuln_type = _normalize_type(finding_get(finding, "type", "vuln_type"))
    raw_type = str(finding_get(finding, "type", "vuln_type", default="")).lower()

    rejected = set(report_cfg.get("always_rejected_standalone", []) or []) | ALWAYS_REJECTED_STANDALONE
    rejected = {_normalize_type(item) for item in rejected}
    if vuln_type in rejected:
        failures.append(f"type is always rejected standalone: {vuln_type}")

    impact = finding_get(finding, "impact", "security_impact", "impact_description")
    if report_cfg.get("require_impact", True) and not _has_concrete_text(impact, block_theory):
        failures.append("missing concrete security impact")

    evidence = finding_get(
        finding,
        "evidence",
        "validation_evidence",
        "proof",
        "runtime_proof",
        "request_response",
        "observed_behavior",
        "validation_gate_ai",
    )
    if report_cfg.get("require_evidence", True) and not _has_concrete_text(evidence, block_theory):
        failures.append("missing concrete request/response evidence")

    min_repro = _int_value(report_cfg.get("min_reproduction_count", 2), 2)
    repro_count = _int_value(finding_get(finding, "reproduction_count"), 0)
    if repro_count < min_repro:
        failures.append(f"reproduction_count below {min_repro}")

    if _as_bool(finding_get(finding, "data_is_public", "no_auth_also_returns_same_data")):
        failures.append("data is public or anonymous response matches authenticated response")

    if _is_idor_type(raw_type):
        if report_cfg.get("require_dual_account_for_idor", True) and not _as_bool(
            finding_get(finding, "dual_account_tested", "two_account_tested")
        ):
            failures.append("IDOR/authz finding lacks two-owned-account proof")
        if report_cfg.get("require_private_data_for_idor", True) and not _as_bool(
            finding_get(finding, "private_data_observed", "require_private_data_met")
        ):
            failures.append("IDOR/authz finding does not show private data/action impact")

    if validation_cfg.get("require_dual_method", False) and _signal_count(finding) < 2:
        failures.append("fewer than two independent validation signals")

    min_conf = validation_cfg.get("min_confidence", None)
    if min_conf is not None:
        threshold = _float_value(min_conf)
        if threshold <= 1:
            threshold *= 100
        confidence = finding_get(finding, "confidence", "validation_confidence", default=0)
        confidence_value = _float_value(confidence)
        if confidence_value <= 1:
            confidence_value *= 100
        if confidence_value and confidence_value < threshold:
            failures.append(f"confidence below validation minimum ({confidence_value:.0f} < {threshold:.0f})")

    if not _is_cvss_reasonable(finding):
        failures.append("severity/CVSS appears higher than demonstrated impact")

    if isinstance(finding, dict):
        finding["report_gate_passed"] = not failures
        finding["report_gate_failures"] = failures

    return not failures, failures


def filter_reportable_findings(findings: list[Any], config: dict | None = None) -> tuple[list[Any], list[tuple[Any, list[str]]]]:
    kept: list[Any] = []
    rejected: list[tuple[Any, list[str]]] = []
    for finding in findings:
        passed, failures = seven_question_gate(finding, config)
        if passed:
            kept.append(finding)
        else:
            rejected.append((finding, failures))
    return kept, rejected
