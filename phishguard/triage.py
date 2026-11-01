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


def disposition_for_findings(
    risk_level: str,
    findings: list[dict],
    *,
    evidence_sufficient: bool = True,
) -> str:
    """Map risk and concrete evidence to a cautious L1 disposition.

    A HIGH score means the message should be escalated, not that PhishGuard
    has proven malicious intent. Reserve the malicious disposition for a
    CRITICAL score or a direct artifact signal that an analyst can act on.

    A direct signal also sets a floor. These checks name a specific artifact
    an analyst can act on — an executable wearing a document name, a link
    whose text and destination disagree — so one of them is never reported as
    ``likely_benign`` merely because the total score stayed under the MEDIUM
    threshold. The weights and the thresholds were calibrated separately, and
    the heaviest direct signal is 40 against a HIGH threshold of 70, so
    without this floor a confirmed artifact could be buried by arithmetic.
    """
    if not evidence_sufficient and not findings:
        return "insufficient_evidence"
    has_direct_signal = any(
        finding.get("check") in _DIRECT_MALICIOUS_SIGNALS
        for finding in findings
    )
    if risk_level == "CRITICAL":
        return "malicious_escalate"
    if risk_level == "HIGH" and has_direct_signal:
        return "malicious_escalate"
    if risk_level in ("MEDIUM", "HIGH") or has_direct_signal:
        return "suspicious_escalate"
    return "likely_benign"
