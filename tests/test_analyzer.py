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

DNS is stubbed for enrichment tests via the autouse `no_real_dns` fixture in
conftest.py. Offline analysis must not call DNS, AbuseIPDB, VirusTotal, RDAP,
or TLS services.

TestCliEndToEnd runs the CLI in offline mode as a real subprocess to catch
wiring bugs unit tests cannot see, while remaining network-independent.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

from phishguard.analyzer import _extract_domain, _extract_email_address, analyze
from phishguard.email_parser import parse_eml
from phishguard import __version__

PROJECT_ROOT = Path(__file__).parent.parent


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
        "authentication_results": [],
        "html_links": [],
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

class TestCriticalRiskTier:
    """
    CRITICAL (150+) is deliberately hard to reach with header/structure
    failures alone — it's meant to require stacking a header-failure
    baseline with something more concrete, like a risky attachment or
    (with intel on) a confirmed-malicious IP/URL. See the reasoning in
    analyzer.py's risk-level comment.
    """

    def test_headers_alone_do_not_reach_critical(self, phishing_test_eml):
        # phishing_test.eml scores 115 from headers/URLs alone — high, but
        # not critical. Confirms the threshold isn't trivially reached.
        parsed = parse_eml(phishing_test_eml)
        report = analyze(parsed, phishing_test_eml, run_intel=False, auth_source="trusted_gateway")
        assert report["risk_level"] == "HIGH"
        assert report["risk_score"] < 150

    def test_header_failures_plus_risky_attachment_reaches_critical(self):
        # Stack a full header-failure baseline with a risky attachment
        # (no threat intel needed) to cross the 150 threshold.
        parsed = _minimal_parsed(
            **{
                "from": "PayPal <billing@paypal.com>",
                "reply_to": "collect-funds@evil-domain.ru",
                "spf": "fail", "dkim": "", "dmarc": "fail",
                "urls": [
                    "http://evil.ru/account/verify-login",
                    "http://evil.ru/secure/update-password",
                    "http://evil.ru/confirm/account-details",
                ],
                "attachments": [{"filename": "invoice.exe", "content_type": "application/octet-stream", "size_bytes": 1024}],
            }
        )
        report = analyze(parsed, "test.eml", run_intel=False, auth_source="trusted_gateway")
        assert report["risk_score"] >= 150
        assert report["risk_level"] == "CRITICAL"


class TestAnalyzeSampleEmails:
    def test_legitimate_email_scores_low(self, legitimate_eml):
        parsed = parse_eml(legitimate_eml)
        report = analyze(parsed, legitimate_eml, run_intel=False)
        assert report["risk_level"] == "LOW"

    def test_phishing_test_email_scores_high(self, phishing_test_eml):
        parsed = parse_eml(phishing_test_eml)
        report = analyze(parsed, phishing_test_eml, run_intel=False, auth_source="trusted_gateway")
        assert report["risk_level"] == "HIGH"
        assert "SPF check failed" in report["flags"]
        assert "DMARC check failed" in report["flags"]
        assert any("Reply-To mismatch" in f for f in report["flags"])

    def test_phishing_amazon_email_scores_high(self, phishing_amazon_eml):
        parsed = parse_eml(phishing_amazon_eml)
        report = analyze(parsed, phishing_amazon_eml, run_intel=False, auth_source="trusted_gateway")
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
        report = analyze(parsed, suspicious_eml, run_intel=False, auth_source="trusted_gateway")
        assert any("SPF" in f for f in report["flags"])
        assert any("DMARC" in f for f in report["flags"])

    def test_legitimate_html_email_scores_low(self, html_legitimate_eml):
        parsed = parse_eml(html_legitimate_eml)
        report = analyze(parsed, html_legitimate_eml, run_intel=False)

        assert report["risk_level"] == "LOW"
        assert not any("mismatch" in flag.lower() for flag in report["flags"])

    def test_html_phishing_mismatch_is_high_confidence(self, html_phishing_eml):
        parsed = parse_eml(html_phishing_eml)
        report = analyze(parsed, html_phishing_eml, run_intel=False)

        mismatch = next(
            finding for finding in report["findings"]
            if finding["id"] == "display_destination_mismatch"
        )
        assert mismatch["confidence"] == "high"
        assert mismatch["evidence"]["displayed_domain"] == "paypal.com"
        assert mismatch["evidence"]["destination_domain"] == "paypal-login.evil.example"
        assert report["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")

    def test_executable_mime_disguised_as_pdf_is_flagged(self, suspicious_attachment_eml):
        parsed = parse_eml(suspicious_attachment_eml)
        report = analyze(parsed, suspicious_attachment_eml, run_intel=False)

        assert any(
            finding["id"] == "attachment_type_mismatch"
            for finding in report["findings"]
        )

    def test_report_structure_has_expected_top_level_keys(self, phishing_test_eml):
        # Guards against accidentally renaming/removing a key that the CLI
        # or report_generator.py depends on.
        parsed = parse_eml(phishing_test_eml)
        report = analyze(parsed, phishing_test_eml, run_intel=False)
        for key in (
            "tool", "version", "analyzed_at", "file", "risk_level",
            "risk_score", "flags", "findings", "email_metadata", "auth_headers",
            "authentication_evidence",
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
        report = analyze(parsed, "test.eml", run_intel=False, auth_source="trusted_gateway")
        assert not any("Reply-To mismatch" in f for f in report["flags"])

    def test_genuinely_different_address_is_flagged(self):
        parsed = _minimal_parsed(**{
            "from": "PayPal <billing@paypal.com>",
            "reply_to": "collect-funds@evil-domain.ru",
        })
        report = analyze(parsed, "test.eml", run_intel=False, auth_source="trusted_gateway")
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

    def test_double_extension_is_flagged(self):
        parsed = _minimal_parsed(attachments=[{
            "filename": "invoice.pdf.exe",
            "content_type": "application/octet-stream",
            "size_bytes": 1024,
        }])
        report = analyze(parsed, "test.eml", run_intel=False)

        assert any(finding["id"] == "double_extension_attachment" for finding in report["findings"])

    def test_bidirectional_filename_control_is_flagged(self):
        parsed = _minimal_parsed(attachments=[{
            "filename": "invoice\u202efdp.exe",
            "content_type": "application/octet-stream",
            "size_bytes": 1024,
        }])
        report = analyze(parsed, "test.eml", run_intel=False)

        assert any(finding["id"] == "bidi_attachment_filename" for finding in report["findings"])


class TestAuthenticationInterpretation:
    def test_verified_dkim_failure_is_distinct_from_missing_signature(self):
        parsed = _minimal_parsed(
            dkim="v=1; d=example.com",
            authentication_results=[
                "mx.example; spf=pass; dkim=fail header.d=example.com; dmarc=pass"
            ],
        )
        report = analyze(parsed, "test.eml", run_intel=False, auth_source="trusted_gateway")

        assert report["authentication_evidence"]["dkim"]["status"] == "fail"
        assert "DKIM verification failed" in report["flags"]
        assert "DKIM signature missing" not in report["flags"]

    def test_signature_presence_is_reported_as_unverified_without_claiming_pass(self):
        report = analyze(_minimal_parsed(dkim="v=1; d=example.com"), "test.eml", run_intel=False)

        assert report["authentication_evidence"]["dkim"]["status"] == "present_unverified"


def test_every_structured_finding_is_explainable():
    parsed = _minimal_parsed(
        authentication_results=["mx.example; spf=fail; dkim=fail; dmarc=fail"],
        html_links=[{
            "displayed_text": "https://paypal.com",
            "href": "https://paypal-login.evil.example/verify",
        }],
        attachments=[{
            "filename": "invoice.pdf.exe",
            "content_type": "application/x-msdownload",
            "size_bytes": 1024,
        }],
    )

    report = analyze(parsed, "test.eml", run_intel=False)

    assert report["findings"]
    for finding in report["findings"]:
        assert finding["check"] == finding["id"]
        assert finding["id"]
        assert finding["message"]
        assert finding["confidence"] in ("low", "medium", "high")
        assert isinstance(finding["evidence"], dict)
        assert finding["false_positive_note"]
        assert finding["recommended_action"]

    assert report["schema_version"] == "1.0"
    assert report["authentication_evidence"]["source_context"] == "unknown_capture"


def test_authentication_source_context_is_explicitly_preserved():
    report = analyze(
        _minimal_parsed(authentication_results=["mx.example; spf=pass"]),
        "test.eml",
        run_intel=False,
        auth_source="trusted_gateway",
    )
    assert report["authentication_evidence"]["source_context"] == "trusted_gateway"


def test_untrusted_authentication_results_are_reported_but_not_scored():
    parsed = _minimal_parsed(
        authentication_results=["attacker.example; spf=fail; dkim=fail; dmarc=fail"]
    )
    report = analyze(parsed, "test.eml", run_intel=False, auth_source="unknown_capture")

    assert report["risk_score"] == 0
    assert report["flags"] == []
    assert report["authentication_evidence"]["spf"]["status"] == "fail"
    assert report["authentication_evidence"]["spf"]["score_status"] == "untrusted"


def test_repeated_findings_have_unique_instance_ids():
    parsed = _minimal_parsed(
        attachments=[
            {"filename": "first.exe", "content_type": "application/octet-stream", "size_bytes": 1},
            {"filename": "second.exe", "content_type": "application/octet-stream", "size_bytes": 1},
        ]
    )
    report = analyze(parsed, "test.eml", run_intel=False)
    findings = [f for f in report["findings"] if f["check"] == "risky_attachment_extension"]

    assert [finding["id"] for finding in findings] == [
        "risky_attachment_extension", "risky_attachment_extension#2"
    ]
    assert [finding["score_contribution"] for finding in findings] == [40, 0]
    assert [finding["evidence_count"] for finding in findings] == [1, 2]
    assert report["risk_score"] == 40


def test_default_cli_preserves_untrusted_auth_without_scoring_it(tmp_path, phishing_test_eml):
    output_path = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, "main.py", "-f", phishing_test_eml, "-n", "-o", "json", "--no-banner", "-O", str(output_path)],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["authentication_evidence"]["source_context"] == "unknown_capture"
    assert report["authentication_evidence"]["spf"]["score_status"] == "untrusted"


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
        report = analyze(parsed, "test.eml", run_intel=True)
        assert any("No SPF DNS record found" in f for f in report["flags"])


class TestOfflineMode:
    def test_offline_analysis_skips_dns_validation(self, monkeypatch):
        def _unexpected_dns_call(_domain):
            raise AssertionError("offline analysis must not perform DNS validation")

        monkeypatch.setattr("phishguard.analyzer.validate_spf_dns", _unexpected_dns_call)
        monkeypatch.setattr("phishguard.analyzer.validate_dmarc_dns", _unexpected_dns_call)

        report = analyze(_minimal_parsed(), "test.eml", run_intel=False)

        assert report["dns_validation"] == {"spf": None, "dmarc": None}


class TestCliEndToEnd:
    """
    Runs the actual CLI as a subprocess, the way a user would, rather than
    calling functions directly. This exists specifically because a real bug
    slipped past every other test in this suite: print_batch_summary()'s
    function signature line was accidentally deleted during an edit, but
    every unit test that exercised it called print_batch_summary() directly
    as an imported function, so the NameError inside run_batch()'s own
    reference to it never got exercised. Only running `python main.py -F ...`
    for real surfaced it. These tests close that gap by invoking the CLI
    exactly as the user does.
    """

    def test_single_file_analysis_runs_without_crashing(self, phishing_test_eml):
        result = subprocess.run(
            [sys.executable, "main.py", "-f", phishing_test_eml, "-n"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "Risk Level" in result.stdout

    def test_batch_analysis_runs_without_crashing(self, tmp_path, phishing_test_eml, legitimate_eml):
        # Copy two real sample files into a scratch folder so -F has
        # something to batch over, without touching the real samples/ dir.
        shutil.copy(phishing_test_eml, tmp_path / "phishing.eml")
        shutil.copy(legitimate_eml, tmp_path / "legit.eml")

        result = subprocess.run(
            [sys.executable, "main.py", "-F", str(tmp_path), "-n"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "Batch Analysis Summary" in result.stdout
        assert "CRITICAL:" in result.stdout  # would have caught the missing-def bug directly

    def test_url_analysis_runs_without_crashing(self):
        result = subprocess.run(
            [sys.executable, "main.py", "-u", "paypa1.com", "-n"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "URL Analysis Report" in result.stdout

    def test_csv_export_runs_without_crashing(self, tmp_path, phishing_test_eml):
        shutil.copy(phishing_test_eml, tmp_path / "phishing.eml")
        csv_path = tmp_path / "out.csv"

        result = subprocess.run(
            [sys.executable, "main.py", "-F", str(tmp_path), "-n", "--csv", str(csv_path)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert csv_path.exists()

    def test_banner_appears_on_stderr_in_text_mode(self, phishing_test_eml):
        result = subprocess.run(
            [sys.executable, "main.py", "-f", phishing_test_eml, "-n"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert f"v{__version__}" in result.stderr

    def test_no_banner_flag_suppresses_it(self, phishing_test_eml):
        result = subprocess.run(
            [sys.executable, "main.py", "-f", phishing_test_eml, "-n", "--no-banner"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert f"v{__version__}" not in result.stderr

    def test_json_output_stdout_is_never_polluted_by_banner(self, phishing_test_eml):
        # The one rule that actually matters for the banner feature: it must
        # never touch stdout, or it breaks `... -o json | jq .` for anyone
        # scripting against this tool. The banner still goes to stderr even
        # in json mode's underlying print_banner() function, but main()
        # must gate the call so it's never invoked at all for json/html/cef.
        result = subprocess.run(
            [sys.executable, "main.py", "-f", phishing_test_eml, "-n", "-o", "json", "--color", "always"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        json.loads(result.stdout)  # raises if stdout isn't pure, parseable JSON
        assert f"v{__version__}" not in result.stdout
        assert f"v{__version__}" not in result.stderr  # banner skipped entirely for json mode
        assert "\033[" not in result.stdout
