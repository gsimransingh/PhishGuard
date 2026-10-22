"""Disposition mapping, including the 0.7 floor for direct artifact signals."""

import pytest

from phishguard.triage import disposition_for_findings

DIRECT = [{"check": "attachment_type_mismatch"}]
INDIRECT = [{"check": "dkim_missing"}]


@pytest.mark.parametrize("risk_level, findings, expected", [
    ("LOW", DIRECT, "suspicious_escalate"),       # floor: never likely_benign
    ("MEDIUM", DIRECT, "suspicious_escalate"),
    ("HIGH", DIRECT, "malicious_escalate"),       # malicious still needs HIGH+
    ("CRITICAL", INDIRECT, "malicious_escalate"),
    ("HIGH", INDIRECT, "suspicious_escalate"),
    ("LOW", INDIRECT, "likely_benign"),
    ("LOW", [], "likely_benign"),
])
def test_disposition_mapping(risk_level, findings, expected):
    assert disposition_for_findings(risk_level, findings) == expected


@pytest.mark.parametrize("check", [
    "attachment_type_mismatch",
    "bidi_attachment_filename",
    "display_destination_mismatch",
    "double_extension_attachment",
    "malicious_url_reputation",
])
def test_every_direct_signal_escalates_from_low(check):
    assert disposition_for_findings("LOW", [{"check": check}]) == "suspicious_escalate"


def test_no_findings_and_no_evidence_is_insufficient():
    assert disposition_for_findings("LOW", [], evidence_sufficient=False) == "insufficient_evidence"
