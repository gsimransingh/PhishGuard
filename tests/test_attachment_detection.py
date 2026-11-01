"""Regression tests for attachment evidence extraction.

These cover the P0 gaps from the 2026-10-22 review, where mail carrying an
executable came back ``likely_benign`` with the attachment not even listed as
an indicator. Each test was an ``xfail(strict=True)`` entry in
``test_known_gaps.py`` until the fix landed.
"""

from phishguard.analyzer import analyze
from phishguard.email_parser import parse_eml

HEADERS = (
    "From: {sender}\n"
    "To: analyst@example.com\n"
    "Subject: Invoice\n"
    "Date: Wed, 29 Jul 2026 09:20:00 +0000\n"
    "Message-ID: <att@example.test>\n"
    "{extra}"
    "MIME-Version: 1.0\n"
)
# "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00" — the start of a Windows PE file.
MZ_PAYLOAD_B64 = "TVqQAAMAAAAEAAAA"
PDF_PAYLOAD_B64 = "JVBERi0xLjQK"  # "%PDF-1.4\n"


def _multipart_with_part(part_headers: str, payload: str = MZ_PAYLOAD_B64) -> str:
    return (
        HEADERS.format(sender="billing@sender.example", extra="")
        + 'Content-Type: multipart/mixed; boundary="b"\n\n'
        + "--b\nContent-Type: text/plain\n\nSee attached.\n"
        + f"--b\n{part_headers}Content-Transfer-Encoding: base64\n\n{payload}\n--b--\n"
    )


def _analyze(tmp_path, raw: str) -> dict:
    path = tmp_path / "att.eml"
    path.write_text(raw, encoding="utf-8")
    return analyze(parse_eml(str(path)), str(path))


def _checks(report: dict) -> set[str]:
    return {finding["check"] for finding in report["findings"]}


# --- attachments are found regardless of Content-Disposition ----------------

def test_inline_disposition_attachment_is_extracted(tmp_path):
    raw = _multipart_with_part(
        'Content-Type: application/octet-stream; name="invoice.exe"\n'
        'Content-Disposition: inline; filename="invoice.exe"\n'
    )
    report = _analyze(tmp_path, raw)

    assert "risky_attachment_extension" in _checks(report)
    assert report["iocs"]["attachments"][0]["disposition"] == "inline"


def test_attachment_without_any_disposition_is_extracted(tmp_path):
    """The filename lives only on the Content-Type "name" parameter here."""
    raw = _multipart_with_part('Content-Type: application/octet-stream; name="invoice.exe"\n')
    report = _analyze(tmp_path, raw)

    assert "risky_attachment_extension" in _checks(report)
    assert report["iocs"]["attachments"][0]["filename"] == "invoice.exe"
    assert report["iocs"]["attachments"][0]["disposition"] == "none"


def test_message_body_parts_are_not_counted_as_attachments(tmp_path):
    raw = (
        HEADERS.format(sender="a@sender.example", extra="")
        + 'Content-Type: multipart/alternative; boundary="b"\n\n'
        + "--b\nContent-Type: text/plain\n\nHello.\n"
        + "--b\nContent-Type: text/html\n\n<p>Hello.</p>\n--b--\n"
    )
    assert _analyze(tmp_path, raw)["iocs"]["attachments"] == []


def test_single_part_plain_message_has_no_attachments(tmp_path):
    raw = HEADERS.format(sender="a@sender.example", extra="") + (
        "Content-Type: text/plain\n\nJust a note.\n"
    )
    assert _analyze(tmp_path, raw)["iocs"]["attachments"] == []


# --- file signatures beat the filename and the declared type ----------------

def test_executable_bytes_behind_document_name_are_flagged(tmp_path):
    raw = _multipart_with_part(
        "Content-Type: application/octet-stream\n"
        'Content-Disposition: attachment; filename="invoice.pdf"\n'
    )
    report = _analyze(tmp_path, raw)
    findings = {finding["check"]: finding for finding in report["findings"]}

    assert "attachment_type_mismatch" in findings
    assert findings["attachment_type_mismatch"]["evidence"]["detected_type"] == "pe_executable"


def test_matching_signature_and_extension_is_not_flagged(tmp_path):
    raw = _multipart_with_part(
        "Content-Type: application/pdf\n"
        'Content-Disposition: attachment; filename="invoice.pdf"\n',
        payload=PDF_PAYLOAD_B64,
    )
    report = _analyze(tmp_path, raw)

    assert report["iocs"]["attachments"][0]["detected_type"] == "pdf"
    assert not _checks(report) & {
        "attachment_type_mismatch", "attachment_signature_mismatch"
    }
    assert report["disposition"] == "likely_benign"


def test_unknown_signature_is_not_treated_as_a_mismatch(tmp_path):
    """"No expectation" must not read as "mismatch"."""
    raw = _multipart_with_part(
        "Content-Type: text/csv\n"
        'Content-Disposition: attachment; filename="export.csv"\n',
        payload="Y29sMSxjb2wyCg==",  # "col1,col2\n"
    )
    report = _analyze(tmp_path, raw)

    assert report["iocs"]["attachments"][0]["detected_type"] == ""
    assert not _checks(report) & {
        "attachment_type_mismatch", "attachment_signature_mismatch"
    }


def test_non_executable_signature_mismatch_is_a_softer_finding(tmp_path):
    raw = _multipart_with_part(
        "Content-Type: application/pdf\n"
        'Content-Disposition: attachment; filename="report.pdf"\n',
        payload="UEsDBBQAAAAIAA==",  # ZIP container claiming to be a PDF
    )
    findings = {f["check"]: f for f in _analyze(tmp_path, raw)["findings"]}

    assert findings["attachment_signature_mismatch"]["weight"] == 15
    assert findings["attachment_signature_mismatch"]["evidence"]["detected_type"] == "zip_container"


# --- SHA-256 for sandbox and reputation pivots ------------------------------

def test_attachment_sha256_is_reported(tmp_path):
    import hashlib

    raw = _multipart_with_part(
        "Content-Type: application/pdf\n"
        'Content-Disposition: attachment; filename="invoice.pdf"\n',
        payload=PDF_PAYLOAD_B64,
    )
    attachment = _analyze(tmp_path, raw)["iocs"]["attachments"][0]

    assert attachment["sha256"] == hashlib.sha256(b"%PDF-1.4\n").hexdigest()
    assert len(attachment["sha256"]) == 64


# --- a direct signal is never buried by a low score -------------------------

def test_direct_signal_is_never_likely_benign(tmp_path):
    raw = _multipart_with_part(
        'Content-Type: application/x-msdownload; name="invoice.pdf"\n'
        'Content-Disposition: attachment; filename="invoice.pdf"\n'
    )
    report = _analyze(tmp_path, raw)

    assert "attachment_type_mismatch" in _checks(report)
    assert report["risk_level"] == "LOW"  # 30 points, below the MEDIUM floor
    assert report["disposition"] == "suspicious_escalate"
    assert report["triage"]["priority"] == "P2"
