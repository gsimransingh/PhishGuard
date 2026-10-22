"""Regression tests for confirmed detection gaps (code review 2026-10-22).

Each test describes the CORRECT behaviour and is marked
``xfail(strict=True)`` because PhishGuard does not do it yet. When a fix
lands, the test starts passing, strict mode turns that XPASS into a failure,
and the marker must be removed in the same change. That keeps this file an
honest, executable list of the "Known detection gaps" in the README.
"""

import pytest

from phishguard.analyzer import analyze
from phishguard.email_parser import parse_eml
from phishguard.url_analyzer import analyze_url

HEADERS = (
    "From: {sender}\n"
    "To: analyst@example.com\n"
    "Subject: Invoice\n"
    "Date: Wed, 29 Jul 2026 09:20:00 +0000\n"
    "Message-ID: <gap@example.test>\n"
    "{extra}"
    "MIME-Version: 1.0\n"
)
MZ_PAYLOAD_B64 = "TVqQAAMAAAAEAAAA"  # first bytes of a Windows PE file ("MZ")


def _analyze(tmp_path, raw: str) -> dict:
    path = tmp_path / "gap.eml"
    path.write_text(raw, encoding="utf-8")
    return analyze(parse_eml(str(path)), str(path))


def _multipart_with_part(part_headers: str) -> str:
    return (
        HEADERS.format(sender="billing@sender.example", extra="")
        + 'Content-Type: multipart/mixed; boundary="b"\n\n'
        + "--b\nContent-Type: text/plain\n\nSee attached.\n"
        + f"--b\n{part_headers}Content-Transfer-Encoding: base64\n\n{MZ_PAYLOAD_B64}\n--b--\n"
    )


def _checks(report: dict) -> set[str]:
    return {finding["check"] for finding in report["findings"]}


gap = pytest.mark.xfail(strict=True, reason="Known detection gap; see README")


# --- P0: phishing that currently comes back likely_benign ------------------

@gap
def test_inline_disposition_attachment_is_extracted(tmp_path):
    raw = _multipart_with_part(
        'Content-Type: application/octet-stream; name="invoice.exe"\n'
        'Content-Disposition: inline; filename="invoice.exe"\n'
    )
    assert "risky_attachment_extension" in _checks(_analyze(tmp_path, raw))


@gap
def test_attachment_without_disposition_is_extracted(tmp_path):
    raw = _multipart_with_part('Content-Type: application/octet-stream; name="invoice.exe"\n')
    assert "risky_attachment_extension" in _checks(_analyze(tmp_path, raw))


@gap
def test_executable_bytes_behind_document_name_are_flagged(tmp_path):
    raw = _multipart_with_part(
        "Content-Type: application/octet-stream\n"
        'Content-Disposition: attachment; filename="invoice.pdf"\n'
    )
    assert "attachment_type_mismatch" in _checks(_analyze(tmp_path, raw))


@gap
def test_attachment_sha256_is_reported(tmp_path):
    raw = _multipart_with_part(
        "Content-Type: application/pdf\n"
        'Content-Disposition: attachment; filename="invoice.pdf"\n'
    )
    attachment = _analyze(tmp_path, raw)["iocs"]["attachments"][0]
    assert len(attachment.get("sha256", "")) == 64


@gap
def test_direct_signal_is_never_likely_benign(tmp_path):
    raw = _multipart_with_part(
        'Content-Type: application/x-msdownload; name="invoice.pdf"\n'
        'Content-Disposition: attachment; filename="invoice.pdf"\n'
    )
    report = _analyze(tmp_path, raw)
    assert "attachment_type_mismatch" in _checks(report)
    assert report["disposition"] != "likely_benign"


# --- P1: evasions and false positives ---------------------------------------

@gap
def test_reply_to_mismatch_not_hidden_by_display_name(tmp_path):
    raw = HEADERS.format(
        sender='"support@paypal.com <support@paypal.com>" <attacker@evil.example>',
        extra="Reply-To: support@paypal.com\n",
    ) + "Content-Type: text/plain\n\nPlease reply.\n"
    assert "reply_to_mismatch" in _checks(_analyze(tmp_path, raw))


@gap
def test_backslash_url_is_analyzed_as_browser_host():
    # Browsers treat "\" as "/" in http(s) URLs, so this opens evil.example.
    assert analyze_url("http://evil.example\\@paypal.com/login")["hostname"] == "evil.example"


@gap
@pytest.mark.parametrize("hostname", [
    "login.microsoftonline.com",
    "outlook.office365.com",
    "s3.amazonaws.com",
    "fonts.googleapis.com",
    "steamcommunity.com",
    "www.purchase.com",
    "pineapple.com",
    "abc.com",
    "globe.com",
    "amazing.com",
])
def test_legitimate_domains_are_not_brand_squats(hostname):
    checks = {finding["check"] for finding in analyze_url(hostname)["findings"]}
    assert not checks & {"typosquatting", "combosquatting"}


# --- P2: detection gaps -----------------------------------------------------

@gap
def test_lookalike_sender_domain_is_flagged(tmp_path):
    raw = HEADERS.format(sender='"PayPal Security" <service@paypa1.com>', extra="") + (
        "Content-Type: text/plain\n\nYour account is locked. Reply with your password.\n"
    )
    assert _analyze(tmp_path, raw)["risk_score"] > 0


@gap
def test_html_form_action_url_is_extracted(tmp_path):
    raw = HEADERS.format(sender="billing@sender.example", extra="") + (
        'Content-Type: text/html\n\n'
        '<form action="https://paypa1-login.example/collect" method="post">'
        '<input name="password" type="password"></form>\n'
    )
    assert "https://paypa1-login.example/collect" in _analyze(tmp_path, raw)["iocs"]["urls"]
