"""
Tests for phishguard/analyzer.py

Covers:
- analyze() against the four real sample .eml files, asserting risk_level
  and specific flags rather than brittle exact score numbers (score weights
  are expected to be tuned over time; risk_level and flag presence are the
  stable contract worth pinning down).
- The Reply-To display-name regression specifically (this was a real bug:
  comparing raw header strings instead of extracted addresses caused a
  false positive whenever From had a display name and Reply-To didn't).
- Hand-built parsed dicts for scoring paths that don't need a real .eml
  file (risky attachments, suspicious URL keywords).

DNS is stubbed for every test via the autouse `no_real_dns` fixture in
conftest.py — analyzer.py's DNS validation runs unconditionally regardless
of run_intel, so this suite always passes run_intel=False to additionally
skip the rate-limited AbuseIPDB/VirusTotal calls, and relies on the fixture
to keep DNS off the network too.
"""

from phishguard.analyzer import _extract_domain, _extract_email_address, analyze
from phishguard.email_parser import parse_eml


def _minimal_parsed(**overrides) -> dict:
    """
    A complete, valid parse_eml()-shaped dict with safe/neutral defaults for
    every field analyze() reads. Tests override only the fields relevant to
    what they're checking, instead of hand-building a partial dict and
    risking a KeyError on some field the test wasn't thinking about (this
    happened during initial suite writeup — see git history).
    """
    base = {
        "subject": "Test subject",
        "from": "sender@example.com",
        "reply_to": "",
        "to": "recipient@example.com",
        "date": "Mon, 1 Jan 2026 00:00:00 +0000",
        "message_id": "<test@example.com>",
        "spf": "pass",
        "dkim": "present",
        "dmarc": "pass",
        "urls": [],
        "ips": [],
        "attachments": [],
        "received_chain": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# analyze() against real sample emails
# ---------------------------------------------------------------------------

class TestAnalyzeSampleEmails:
    def test_legitimate_email_scores_low(self, legitimate_eml):
        parsed = parse_eml(legitimate_eml)
        report = analyze(parsed, legitimate_eml, run_intel=False)
        assert report["risk_level"] == "LOW"

    def test_phishing_test_email_scores_high(self, phishing_test_eml):
        parsed = parse_eml(phishing_test_eml)
        report = analyze(parsed, phishing_test_eml, run_intel=False)
        assert report["risk_level"] == "HIGH"
        assert "SPF check failed" in report["flags"]
        assert "DMARC check failed" in report["flags"]
        assert any("Reply-To mismatch" in f for f in report["flags"])

    def test_phishing_amazon_email_scores_high(self, phishing_amazon_eml):
        parsed = parse_eml(phishing_amazon_eml)
        report = analyze(parsed, phishing_amazon_eml, run_intel=False)
        assert report["risk_level"] == "HIGH"
        assert any("Reply-To mismatch" in f for f in report["flags"])

    def test_suspicious_email_raises_auth_flags(self, suspicious_eml):
        # Known, documented calibration issue (not silently "fixed" here):
        # suspicious_email.eml scores identically to obvious phishing because
        # auth header failures alone push it past the HIGH threshold. This
        # test only pins down that auth flags fire — it deliberately does
        # NOT assert an exact score, since that's the number under review,
        # not a settled contract.
        parsed = parse_eml(suspicious_eml)
        report = analyze(parsed, suspicious_eml, run_intel=False)
        assert any("SPF" in f for f in report["flags"])
        assert any("DMARC" in f for f in report["flags"])

    def test_report_structure_has_expected_top_level_keys(self, phishing_test_eml):
        # Guards against accidentally renaming/removing a key that the CLI
        # or report_generator.py depends on.
        parsed = parse_eml(phishing_test_eml)
        report = analyze(parsed, phishing_test_eml, run_intel=False)
        for key in (
            "tool", "version", "analyzed_at", "file", "risk_level",
            "risk_score", "flags", "email_metadata", "auth_headers",
            "dns_validation", "iocs", "threat_intel", "received_chain",
        ):
            assert key in report


# ---------------------------------------------------------------------------
# Reply-To mismatch — the display-name regression, tested directly
# ---------------------------------------------------------------------------

class TestReplyToMismatch:
    def test_display_name_difference_alone_is_not_a_mismatch(self):
        # This is the exact bug that was fixed: comparing raw header strings
        # flagged "GitHub <noreply@github.com>" vs "noreply@github.com" as a
        # mismatch even though it's the same address. Comparing extracted
        # addresses must treat these as equal.
        parsed = _minimal_parsed(
            **{"from": "GitHub <noreply@github.com>", "reply_to": "noreply@github.com"}
        )
        report = analyze(parsed, "test.eml", run_intel=False)
        assert not any("Reply-To mismatch" in f for f in report["flags"])

    def test_genuinely_different_address_is_flagged(self):
        parsed = _minimal_parsed(**{
            "from": "PayPal <billing@paypal.com>",
            "reply_to": "collect-funds@evil-domain.ru",
        })
        report = analyze(parsed, "test.eml", run_intel=False)
        assert any("Reply-To mismatch" in f for f in report["flags"])

    def test_no_reply_to_header_at_all_is_not_flagged(self):
        parsed = _minimal_parsed(**{"from": "someone@example.com", "reply_to": ""})
        report = analyze(parsed, "test.eml", run_intel=False)
        assert not any("Reply-To mismatch" in f for f in report["flags"])


class TestExtractEmailAddress:
    def test_extracts_from_display_name_format(self):
        assert _extract_email_address("GitHub <noreply@github.com>") == "noreply@github.com"

    def test_handles_bare_address(self):
        assert _extract_email_address("noreply@github.com") == "noreply@github.com"

    def test_lowercases_result(self):
        assert _extract_email_address("Name <User@Example.COM>") == "user@example.com"


class TestExtractDomain:
    def test_extracts_domain_from_display_name_format(self):
        assert _extract_domain("PayPal Billing <billing@paypal.com>") == "paypal.com"

    def test_extracts_domain_from_bare_address(self):
        assert _extract_domain("billing@paypal.com") == "paypal.com"

    def test_returns_empty_string_when_no_at_sign(self):
        assert _extract_domain("not an email address") == ""


# ---------------------------------------------------------------------------
# Scoring paths that don't need a real .eml file
# ---------------------------------------------------------------------------

class TestAttachmentScoring:
    def test_risky_extension_is_flagged(self):
        parsed = _minimal_parsed(attachments=[
            {"filename": "invoice.exe", "content_type": "application/octet-stream", "size_bytes": 1024}
        ])
        report = analyze(parsed, "test.eml", run_intel=False)
        assert any("Risky attachment" in f for f in report["flags"])

    def test_safe_extension_is_not_flagged(self):
        parsed = _minimal_parsed(attachments=[
            {"filename": "invoice.pdf", "content_type": "application/pdf", "size_bytes": 1024}
        ])
        report = analyze(parsed, "test.eml", run_intel=False)
        assert not any("Risky attachment" in f for f in report["flags"])


class TestSuspiciousUrlScoring:
    def test_suspicious_keyword_urls_are_flagged(self):
        parsed = _minimal_parsed(urls=["http://evil.ru/account/verify-login"])
        report = analyze(parsed, "test.eml", run_intel=False)
        assert any("Suspicious URLs" in f for f in report["flags"])

    def test_ordinary_url_is_not_flagged(self):
        parsed = _minimal_parsed(urls=["http://example.com/blog/post-1"])
        report = analyze(parsed, "test.eml", run_intel=False)
        assert not any("Suspicious URLs" in f for f in report["flags"])


class TestDnsNotFoundScoring:
    def test_missing_spf_dns_record_is_flagged(self, monkeypatch):
        # Overrides the autouse "found" stub from conftest for this one test
        # to exercise the "not_found" scoring path specifically.
        def _fake_spf_not_found(domain):
            return {"domain": domain, "status": "not_found", "record": "", "error": "No SPF TXT record found"}

        monkeypatch.setattr("phishguard.analyzer.validate_spf_dns", _fake_spf_not_found)

        parsed = _minimal_parsed()
        report = analyze(parsed, "test.eml", run_intel=False)
        assert any("No SPF DNS record found" in f for f in report["flags"])
