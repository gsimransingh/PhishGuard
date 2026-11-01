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


def _analyze(tmp_path, raw: str) -> dict:
    path = tmp_path / "gap.eml"
    path.write_text(raw, encoding="utf-8")
    return analyze(parse_eml(str(path)), str(path))


def _checks(report: dict) -> set[str]:
    return {finding["check"] for finding in report["findings"]}


gap = pytest.mark.xfail(strict=True, reason="Known detection gap; see README")


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


# FIXED (brand-owned domain allowlist, length-scaled edit distance,
# word-boundary combosquat matching). Marker removed with the fix; the
# assertion stays as the regression test that keeps this gap shut.
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

# FIXED (the From header now runs through the brand engine under its own
# check ids). Marker removed with the fix; see tests/test_analyzer.py for the
# findings this produces.
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
