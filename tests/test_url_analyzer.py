"""
Tests for phishguard/url_analyzer.py

Covers each check function in isolation, the analyze_url() orchestration,
and regression tests for two real bugs caught by hand-testing before this
suite existed:

1. The combosquat check had no minimum brand-length guard (only typosquat
   did), so a short brand name like "att" would false-positive on any domain
   containing "att" as a substring (e.g. "attackers-domain.com").
2. A domain combining a leetspeak substitution AND extra words in the same
   label (e.g. "paypa1-secure-login.ru") falls through both the typosquat
   check (whole-label edit distance too large) and the combosquat check
   (exact brand spelling isn't present due to the "1"). This is a documented
   known limitation, not something these tests pretend is fixed — the test
   for it asserts the current (gap) behavior so a future change to close
   this gap is a deliberate, visible decision, not an accidental regression.

RDAP/network calls are mocked locally in the tests that need them; nothing
in this file makes a real HTTP request.
"""

import socket
import ssl
from unittest.mock import MagicMock, Mock, patch

from phishguard.url_analyzer import (
    _levenshtein,
    _registrable_domain,
    analyze_url,
    check_domain_registration,
    check_punycode_homograph,
    check_ssl_certificate,
    check_typosquatting,
    check_url_structure,
)


def _days_between_years(start_year: int, end_year: int) -> int:
    """Exact day count between Jan 1 of two years, accounting for leap years."""
    from datetime import datetime, timezone
    start = datetime(start_year, 1, 1, tzinfo=timezone.utc)
    end = datetime(end_year, 1, 1, tzinfo=timezone.utc)
    return (end - start).days


# ---------------------------------------------------------------------------
# _levenshtein() — unit tests
# ---------------------------------------------------------------------------

class TestLevenshtein:
    def test_identical_strings_have_zero_distance(self):
        assert _levenshtein("paypal", "paypal") == 0

    def test_single_character_substitution(self):
        assert _levenshtein("paypa1", "paypal") == 1

    def test_single_character_insertion(self):
        assert _levenshtein("paypal", "paypall") == 1

    def test_completely_different_strings(self):
        assert _levenshtein("paypal", "xyz") > 3

    def test_empty_string_distance_equals_other_length(self):
        assert _levenshtein("", "paypal") == 6
        assert _levenshtein("paypal", "") == 6


# ---------------------------------------------------------------------------
# _registrable_domain() — documents the known naive-parsing limitation
# ---------------------------------------------------------------------------

class TestRegistrableDomain:
    def test_simple_two_label_domain(self):
        assert _registrable_domain("paypal.com") == "paypal.com"

    def test_subdomain_reduces_to_last_two_labels(self):
        assert _registrable_domain("login.paypal.com") == "paypal.com"

    def test_known_limitation_multipart_tld_is_mis_parsed(self):
        # Documented in the module docstring: this naive split treats the
        # public suffix "co.uk" as if it were the registrable domain, which
        # is wrong. Asserting the current (wrong) behavior on purpose so a
        # future fix to use a public-suffix-list is a visible, intentional
        # change rather than a silent behavior shift nobody notices.
        assert _registrable_domain("example.co.uk") == "co.uk"


# ---------------------------------------------------------------------------
# check_url_structure()
# ---------------------------------------------------------------------------

class TestCheckUrlStructure:
    def test_ip_as_hostname_is_flagged(self):
        findings = check_url_structure("http://192.168.1.50/login")
        checks = [f["check"] for f in findings]
        assert "ip_as_hostname" in checks

    def test_at_symbol_trick_is_flagged(self):
        findings = check_url_structure("http://user@evil.com/login")
        checks = [f["check"] for f in findings]
        assert "at_symbol_trick" in checks

    def test_excessive_subdomains_flagged(self):
        findings = check_url_structure("http://a.b.c.d.e.example.com/login")
        checks = [f["check"] for f in findings]
        assert "excessive_subdomains" in checks

    def test_suspicious_tld_flagged(self):
        findings = check_url_structure("http://free-prize.top")
        checks = [f["check"] for f in findings]
        assert "suspicious_tld" in checks

    def test_nonstandard_port_flagged(self):
        findings = check_url_structure("http://example.com:8080/login")
        checks = [f["check"] for f in findings]
        assert "nonstandard_port" in checks

    def test_clean_ordinary_url_raises_no_flags(self):
        findings = check_url_structure("https://www.python.org/downloads")
        assert findings == []

    def test_every_finding_has_a_false_positive_note(self):
        # Enforce the project's own design principle: every finding must be
        # explainable, not a bare "flagged: true".
        findings = check_url_structure("http://user@192.168.1.1:8080/login")
        assert len(findings) >= 3
        for f in findings:
            assert f["false_positive_note"]
            assert f["confidence"] in ("low", "medium", "high")


# ---------------------------------------------------------------------------
# check_punycode_homograph()
# ---------------------------------------------------------------------------

class TestCheckPunycodeHomograph:
    def test_punycode_prefix_is_flagged(self):
        findings = check_punycode_homograph("xn--pypal-4ve.com")
        assert any(f["check"] == "punycode_domain" for f in findings)

    def test_ordinary_ascii_domain_not_flagged(self):
        assert check_punycode_homograph("paypal.com") == []


# ---------------------------------------------------------------------------
# check_typosquatting() — typosquat, combosquat, and the two regressions
# ---------------------------------------------------------------------------

class TestCheckTyposquatting:
    def test_typosquat_single_char_swap_detected(self):
        findings = check_typosquatting("paypa1.com", brands=["paypal"])
        checks = [f["check"] for f in findings]
        assert "typosquatting" in checks

    def test_combosquat_brand_as_substring_detected(self):
        findings = check_typosquatting("paypal-secure-login.ru", brands=["paypal"])
        checks = [f["check"] for f in findings]
        assert "combosquatting" in checks

    def test_real_brand_domain_not_flagged(self):
        assert check_typosquatting("paypal.com", brands=["paypal"]) == []

    def test_unrelated_domain_not_flagged(self):
        assert check_typosquatting("python.org", brands=["paypal", "amazon"]) == []

    def test_regression_short_brand_name_no_false_positive(self):
        # Bug found during manual testing: before the length guard existed,
        # a short brand like "att" matched as a substring of ordinary words.
        findings = check_typosquatting("attackers-test-domain.com", brands=["att"])
        assert findings == []

    def test_regression_leetspeak_plus_extra_words_is_a_known_gap(self):
        # Documented known limitation: combining a character substitution
        # AND extra words in the same label defeats both checks at once.
        # This asserts the CURRENT gap exists, so if someone later improves
        # the matching to catch this, they'll see this test fail and update
        # it deliberately, instead of the gap silently reappearing unnoticed.
        findings = check_typosquatting("paypa1-secure-login.ru", brands=["paypal"])
        assert findings == []

    def test_default_brand_list_loads_when_none_given(self):
        # No brands= argument -> should load phishguard/data/known_brands.json
        # rather than crash or return nothing for a well-known brand.
        findings = check_typosquatting("paypa1.com")
        assert any(f["check"] == "typosquatting" for f in findings)


# ---------------------------------------------------------------------------
# check_domain_registration() — RDAP parsing, fully mocked
# ---------------------------------------------------------------------------

class TestCheckDomainRegistration:
    @patch("phishguard.url_analyzer.requests.get")
    def test_parses_registrar_creation_and_expiry(self, mock_get):
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                ],
                "entities": [
                    {"roles": ["registrar"], "vcardArray": [
                        "vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc."]]
                    ]},
                ],
                "status": ["active"],
            },
        )
        result = check_domain_registration("example.com")
        assert result["status"] == "found"
        assert result["registrar"] == "Example Registrar Inc."
        assert result["registration_period_days"] == _days_between_years(2020, 2030)

    @patch("phishguard.url_analyzer.requests.get")
    def test_detects_abuse_related_status_codes(self, mock_get):
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {
                "events": [{"eventAction": "registration", "eventDate": "2026-06-01T00:00:00Z"}],
                "entities": [],
                "status": ["clientHold", "active"],
            },
        )
        result = check_domain_registration("suspicious-domain.com")
        assert "clienthold" in {s.lower() for s in result["domain_status"]}

    @patch("phishguard.url_analyzer.requests.get")
    def test_missing_registration_date_returns_no_data_status(self, mock_get):
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"events": [], "entities": [], "status": []},
        )
        result = check_domain_registration("privacy-protected-domain.com")
        assert result["status"] == "no_data"
        assert result["error"] is not None

    @patch("phishguard.url_analyzer.requests.get")
    def test_non_200_response_does_not_raise(self, mock_get):
        mock_get.return_value = Mock(status_code=403, json=lambda: {})
        result = check_domain_registration("blocked-lookup.com")
        assert result["status"] == "unavailable"
        assert result["age_days"] is None

    @patch("phishguard.url_analyzer.requests.get")
    def test_network_error_does_not_raise(self, mock_get):
        import requests
        mock_get.side_effect = requests.RequestException("connection refused")
        result = check_domain_registration("unreachable.com")
        assert result["status"] == "error"
        assert "connection refused" in result["error"]

    def test_registrar_name_alone_never_adds_a_finding(self):
        # Design decision under test: registrar identity is informational
        # only and must never be scored on its own. There is no
        # "registrar_reputation" or similarly named check anywhere in the
        # module — this test exists so that check can't be quietly added
        # back in without a deliberate, visible decision to do so.
        import phishguard.url_analyzer as ua
        source = open(ua.__file__).read()
        assert '"check": "registrar_reputation"' not in source
        assert '"check": "registrar_name"' not in source


# ---------------------------------------------------------------------------
# check_ssl_certificate() — TLS handshake fully mocked, no real network
# ---------------------------------------------------------------------------

def _mock_context_manager(return_value):
    """Build a MagicMock that behaves as a context manager yielding return_value,
    matching how socket.create_connection() and ssl wrap_socket() are used
    ('with X() as y:') in check_ssl_certificate."""
    cm = MagicMock()
    cm.__enter__ = Mock(return_value=return_value)
    cm.__exit__ = Mock(return_value=False)
    return cm


class TestCheckSslCertificate:
    @patch("phishguard.url_analyzer.ssl.create_default_context")
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_verified_certificate_is_parsed(self, mock_connect, mock_ctx):
        mock_sock = MagicMock()
        mock_connect.return_value = _mock_context_manager(mock_sock)

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "notBefore": "Jun  1 00:00:00 2020 GMT",
            "notAfter": "Aug 30 00:00:00 2030 GMT",
        }
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = _mock_context_manager(mock_ssock)
        mock_ctx.return_value = mock_context

        result = check_ssl_certificate("example.com")
        assert result["status"] == "verified"
        assert result["issuer"] == "Let's Encrypt"
        assert result["days_since_issued"] is not None
        assert result["days_since_issued"] > 1000  # issued in 2020, definitely not "fresh"

    @patch("phishguard.url_analyzer.ssl.create_default_context")
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_verification_failure_is_caught_not_raised(self, mock_connect, mock_ctx):
        mock_connect.return_value = _mock_context_manager(MagicMock())

        mock_context = MagicMock()
        mock_context.wrap_socket.side_effect = ssl.SSLCertVerificationError("self-signed certificate")
        mock_ctx.return_value = mock_context

        result = check_ssl_certificate("self-signed.example.com")
        assert result["status"] == "verification_failed"
        assert "self-signed" in result["error"]

    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_connection_failure_is_caught_not_raised(self, mock_connect):
        mock_connect.side_effect = socket.timeout("timed out")

        result = check_ssl_certificate("unreachable.example.com")
        assert result["status"] == "unavailable"
        assert result["issuer"] is None

    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_dns_failure_is_caught_not_raised(self, mock_connect):
        mock_connect.side_effect = socket.gaierror("Name or service not known")

        result = check_ssl_certificate("does-not-resolve.example.com")
        assert result["status"] == "unavailable"


# ---------------------------------------------------------------------------
# analyze_url() — full orchestration
# ---------------------------------------------------------------------------

class TestAnalyzeUrl:
    def test_offline_mode_skips_domain_registration(self):
        result = analyze_url("paypa1.com", run_intel=False)
        assert result["domain_registration"] is None

    def test_offline_mode_skips_ssl_certificate(self):
        result = analyze_url("paypa1.com", run_intel=False)
        assert result["ssl_certificate"] is None

    def test_bare_domain_without_scheme_is_handled(self):
        result = analyze_url("paypa1.com", run_intel=False)
        assert result["hostname"] == "paypa1.com"

    def test_typosquat_domain_scores_medium_or_higher(self):
        result = analyze_url("paypa1.com", run_intel=False)
        assert result["risk_level"] in ("MEDIUM", "HIGH")
        assert result["risk_score"] > 0

    def test_clean_legitimate_domain_scores_low(self):
        result = analyze_url("https://www.python.org", run_intel=False)
        assert result["risk_level"] == "LOW"
        assert result["findings"] == []

    def test_garbage_input_does_not_raise(self):
        # Should degrade gracefully to "no findings", not crash.
        result = analyze_url("not a url at all", run_intel=False)
        assert result["risk_level"] == "LOW"

    @patch("phishguard.url_analyzer.socket.create_connection")
    @patch("phishguard.url_analyzer.requests.get")
    def test_young_domain_with_short_registration_period_is_flagged(self, mock_get, mock_connect):
        from datetime import datetime, timedelta, timezone
        mock_connect.side_effect = socket.timeout("TLS intentionally skipped in this RDAP test")
        created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        expires = (datetime.now(timezone.utc) + timedelta(days=355)).isoformat()
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {
                "events": [
                    {"eventAction": "registration", "eventDate": created},
                    {"eventAction": "expiration", "eventDate": expires},
                ],
                "entities": [],
                "status": [],
            },
        )
        result = analyze_url("brand-new-throwaway-domain.com", run_intel=True)
        checks = [f["check"] for f in result["findings"]]
        assert "young_domain" in checks
        assert "short_registration_period" in checks

    @patch("phishguard.url_analyzer.socket.create_connection")
    @patch("phishguard.url_analyzer.requests.get")
    def test_stacked_findings_reach_critical_tier(self, mock_rdap, mock_connect):
        # CRITICAL (150+) requires stacking multiple independent signals —
        # structure red flags, a brand combosquat, AND a corroborating RDAP
        # signal, not just one bad check. Mocks both network calls (RDAP +
        # the SSL handshake) so this stays fast and deterministic; the SSL
        # check is mocked to simply fail to connect (contributes 0 score),
        # keeping the test focused on the RDAP-driven signals.
        from datetime import datetime, timedelta, timezone
        mock_connect.side_effect = socket.timeout("simulated: no ssl check needed for this test")

        created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        expires = (datetime.now(timezone.utc) + timedelta(days=355)).isoformat()
        mock_rdap.return_value = Mock(
            status_code=200,
            json=lambda: {
                "events": [
                    {"eventAction": "registration", "eventDate": created},
                    {"eventAction": "expiration", "eventDate": expires},
                ],
                "entities": [],
                "status": ["clientHold"],
            },
        )

        url = "http://user@a.b.c.paypal-verify.tk:8080/login"
        result = analyze_url(url, run_intel=True)

        assert result["risk_score"] >= 150
        assert result["risk_level"] == "CRITICAL"
