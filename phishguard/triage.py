"""Operational disposition mapping for SOC Level 1 triage."""

DISPOSITIONS = (
    "likely_benign",
    "suspicious_escalate",
    "malicious_escalate",
    "insufficient_evidence",
)


_DIRECT_MALICIOUS_SIGNALS = {
    "attachment_type_mismatch",
    "bidi_attachment_filename",
    "display_destination_mismatch",
    "double_extension_attachment",
    "malicious_url_reputation",
}


def disposition_for_findings(risk_level: str, findings: list[dict]) -> str:
    """Map risk and concrete evidence to a cautious L1 disposition.

    A HIGH score means the message should be escalated, not that PhishGuard
    has proven malicious intent. Reserve the malicious disposition for a
    CRITICAL score or a direct artifact signal that an analyst can act on.
    """
    if risk_level == "CRITICAL":
        return "malicious_escalate"
    if risk_level == "HIGH" and any(
        finding.get("check") in _DIRECT_MALICIOUS_SIGNALS
        for finding in findings
    ):
        return "malicious_escalate"
    if risk_level in ("MEDIUM", "HIGH"):
        return "suspicious_escalate"
    return "likely_benign"
