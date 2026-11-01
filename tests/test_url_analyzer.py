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

import pytest

from phishguard import cli
from phishguard.url_analyzer import (
    InvalidURLError,
    _allowed_edit_distance,
    _levenshtein,
    brand_owned_domains,
    registrable_domain,
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
# registrable_domain() — public-suffix-aware parsing
# ---------------------------------------------------------------------------

class TestRegistrableDomain:
    def test_simple_two_label_domain(self):
        assert registrable_domain("paypal.com") == "paypal.com"

    def test_subdomain_reduces_to_registrable_domain(self):
        assert registrable_domain("login.paypal.com") == "paypal.com"

    def test_multipart_public_suffix_is_parsed_correctly(self):
        assert registrable_domain("example.co.uk") == "example.co.uk"
        assert registrable_domain("login.example.co.uk") == "example.co.uk"


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

    @patch("phishguard.url_analyzer.requests.get")
    def test_malformed_rdap_date_returns_structured_error(self, mock_get):
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"events": [{"eventAction": "registration", "eventDate": "not-a-date"}]},
        )
        result = check_domain_registration("malformed.example")
        assert result["status"] == "error"
        assert result["age_days"] is None

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
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_non_public_ip_literal_is_blocked_before_connection(self, mock_connect):
        result = check_ssl_certificate("127.0.0.1")

        assert result["status"] == "blocked"
        mock_connect.assert_not_called()

    @patch("phishguard.url_analyzer.socket.getaddrinfo")
    @patch("phishguard.url_analyzer.ssl.create_default_context")
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_verified_certificate_is_parsed(self, mock_connect, mock_ctx, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
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

    @patch("phishguard.url_analyzer.socket.getaddrinfo")
    @patch("phishguard.url_analyzer.ssl.create_default_context")
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_verification_failure_is_caught_not_raised(self, mock_connect, mock_ctx, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        mock_connect.return_value = _mock_context_manager(MagicMock())

        mock_context = MagicMock()
        mock_context.wrap_socket.side_effect = ssl.SSLCertVerificationError("self-signed certificate")
        mock_ctx.return_value = mock_context

        result = check_ssl_certificate("self-signed.example.com")
        assert result["status"] == "verification_failed"
        assert "self-signed" in result["error"]

    @patch("phishguard.url_analyzer.socket.getaddrinfo")
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_connection_failure_is_caught_not_raised(self, mock_connect, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        mock_connect.side_effect = socket.timeout("timed out")

        result = check_ssl_certificate("unreachable.example.com")
        assert result["status"] == "unavailable"
        assert result["issuer"] is None

    @patch("phishguard.url_analyzer.socket.getaddrinfo")
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_dns_failure_is_caught_not_raised(self, mock_connect, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")

        result = check_ssl_certificate("does-not-resolve.example.com")
        assert result["status"] == "unavailable"
        mock_connect.assert_not_called()

    @patch("phishguard.url_analyzer.socket.getaddrinfo")
    @patch("phishguard.url_analyzer.socket.create_connection")
    def test_hostname_resolving_to_private_address_is_blocked(self, mock_connect, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        result = check_ssl_certificate("internal.example.com")

        assert result["status"] == "blocked"
        mock_connect.assert_not_called()


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
        assert result["schema_version"] == "1.0"

    def test_findings_have_normalized_fields(self):
        result = analyze_url("paypa1.com", run_intel=False)
        assert result["findings"]
        for finding in result["findings"]:
            assert finding["id"] == finding["check"]
            assert finding["message"] == finding["finding"]
            assert isinstance(finding["evidence"], dict)
            assert finding["recommended_action"]

    @patch("phishguard.url_analyzer.check_ssl_certificate")
    @patch("phishguard.url_analyzer.check_domain_registration")
    def test_tls_enrichment_uses_explicit_url_port(self, mock_rdap, mock_tls):
        mock_rdap.return_value = {"status": "not_found", "domain_status": []}
        mock_tls.return_value = {"status": "unavailable", "error": "test"}

        analyze_url("https://example.com:8443/login", run_intel=True)

        mock_tls.assert_called_once_with("example.com", 8443)

    @pytest.mark.parametrize("url", [
        "https://",
        "https://example.com:abc/",
        "https://example.com:70000/",
        "not a url at all",
        "",
        "ftp://example.com/file",
    ])
    def test_invalid_url_is_rejected(self, url):
        with pytest.raises(InvalidURLError):
            analyze_url(url, run_intel=False)

    def test_invalid_port_is_rejected_by_structure_check(self):
        with pytest.raises(InvalidURLError):
            check_url_structure("https://example.com:abc/")

    def test_cli_reports_invalid_url_without_traceback(self, capsys):
        args = MagicMock(
            url="https://example.com:abc/",
            enrich=False,
            output="text",
            color="never",
            save_output=None,
        )

        with pytest.raises(SystemExit) as exit_info:
            cli.run_url(args)

        assert exit_info.value.code == 2
        captured = capsys.readouterr()
        assert "[ERROR] Input rejected:" in captured.err
        assert "Traceback" not in captured.err

    @patch("phishguard.url_analyzer.socket.getaddrinfo")
    @patch("phishguard.url_analyzer.socket.create_connection")
    @patch("phishguard.url_analyzer.requests.get")
    def test_young_domain_with_short_registration_period_is_flagged(self, mock_get, mock_connect, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
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

    @patch("phishguard.url_analyzer.socket.getaddrinfo")
    @patch("phishguard.url_analyzer.socket.create_connection")
    @patch("phishguard.url_analyzer.requests.get")
    def test_stacked_findings_reach_critical_tier(self, mock_rdap, mock_connect, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
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


# ---------------------------------------------------------------------------
# Brand matching rules: the owned-domain allowlist, length-scaled edit
# distance, and word-boundary combosquat matching (0.8 "analyst trust")
# ---------------------------------------------------------------------------

class TestBrandOwnedDomains:
    """A brand check must not fire on a domain that brand's owner operates."""

    def test_brand_list_maps_every_brand_to_owned_domains(self):
        brands = brand_owned_domains()

        assert brands, "known_brands.json produced no brands"
        assert "paypal" in brands
        assert "paypal.com" in brands["paypal"]
        assert all(isinstance(domains, frozenset) for domains in brands.values())

    def test_brands_sharing_an_owner_share_its_domains(self):
        # Microsoft owns Outlook and Office 365, so mail for one arriving from
        # another's domain is not impersonation. This is why
        # outlook.office365.com is not reported.
        brands = brand_owned_domains()

        assert brands["outlook"] == brands["microsoft"] == brands["office365"]
        assert "office365.com" in brands["outlook"]

    def test_owned_domain_suppresses_only_its_own_brand(self):
        # amazonaws.com is Amazon's, so "amazonaws" is not an Amazon squat —
        # but a PayPal phishing page hosted on it is still a PayPal squat.
        # Suppressing every brand on a brand-operated hosting domain would
        # turn the allowlist into a bypass for the most-abused hosts there are.
        assert check_typosquatting("s3.amazonaws.com") == []

        checks = [f["check"] for f in check_typosquatting("paypal-login.s3.amazonaws.com")]
        assert "combosquatting" in checks

    def test_corrupt_brand_file_falls_back_without_crashing(self):
        # Fail-safe, not fail-silent: a missing or corrupted config must not
        # take a scan down, and the fallback carries owned domains of its own
        # so the failure mode is a shorter brand list, never an allowlist
        # bypass on the brands it does still cover.
        from phishguard.url_analyzer import _load_known_brands

        _load_known_brands.cache_clear()
        try:
            with patch("phishguard.url_analyzer.open", side_effect=FileNotFoundError):
                brands = brand_owned_domains()
        finally:
            _load_known_brands.cache_clear()  # don't leave the stub cached

        assert "paypal" in brands
        assert "paypal.com" in brands["paypal"]

    def test_a_brand_list_without_domains_still_matches(self):
        # The bare-list form used by most tests has no owned domains, so
        # nothing is allowlisted and the matching rules are tested alone.
        checks = [f["check"] for f in check_typosquatting("paypal-verify.ru", brands=["paypal"])]
        assert "combosquatting" in checks


class TestBrandWordBoundaryMatching:
    """A brand buried inside a longer word is not a combosquat."""

    @pytest.mark.parametrize("hostname", [
        "www.purchase.com",   # contains "chase"
        "pineapple.com",      # contains "apple"
        "purchases.example",
    ])
    def test_brand_inside_a_word_is_not_matched(self, hostname):
        assert check_typosquatting(hostname) == []

    @pytest.mark.parametrize("hostname", [
        "paypal-secure-login.ru",     # brand is its own token
        "secure-paypal-login.com",    # brand is a token in the middle
        "paypalsecure.com",           # brand at the start of a glued label
        "securepaypal.com",           # brand at the end of a glued label
        "paypal.verify-account.ru",   # brand as a subdomain
    ])
    def test_brand_at_a_word_boundary_is_matched(self, hostname):
        checks = [f["check"] for f in check_typosquatting(hostname, brands=["paypal"])]
        assert "combosquatting" in checks

    def test_short_brand_is_not_matched_at_the_end_of_a_word(self):
        # "chase" and "apple" are short enough that an accidental word ending
        # is likely, so a suffix match needs a longer brand name.
        assert check_typosquatting("mypurchase.example", brands=["chase"]) == []
        assert check_typosquatting("mysecurechase.example", brands=["chase"]) == []

    def test_brand_operated_tld_is_not_read_as_impersonation(self):
        # The public suffix is dropped before labels are compared, so a brand
        # TLD does not make every host under it an impersonation of itself.
        assert check_typosquatting("support.apple", brands=["apple"]) == []


class TestBrandEditDistanceScaling:
    """Edit distance is only meaningful relative to the length of the word."""

    @pytest.mark.parametrize("hostname,brand", [
        ("abc.com", "hsbc"),       # 2 edits on a 4-character brand
        ("globe.com", "adobe"),    # 2 edits on a 5-character brand
        ("amazing.com", "amazon"), # 2 edits on a 6-character brand
        ("ups.com", "usps"),       # 1 edit, but on a 3-character label
    ])
    def test_short_labels_are_not_typosquats(self, hostname, brand):
        assert check_typosquatting(hostname, brands=[brand]) == []

    @pytest.mark.parametrize("hostname,brand", [
        ("paypa1.com", "paypal"),        # 1 edit
        ("ebey.com", "ebay"),            # 1 edit on a 4-character brand
        ("rnicrosoft.com", "microsoft"), # 2 edits, but on a 9-character brand
    ])
    def test_deliberate_lookalikes_are_still_typosquats(self, hostname, brand):
        checks = [f["check"] for f in check_typosquatting(hostname, brands=[brand])]
        assert "typosquatting" in checks

    def test_allowed_distance_scales_with_the_shorter_string(self):
        assert _allowed_edit_distance("hsbc", "abc") == 0
        assert _allowed_edit_distance("adobe", "globe") == 1
        assert _allowed_edit_distance("microsoft", "rnicrosoft") == 2


class TestRegistrableDomainUnknownSuffix:
    """An unrecognised public suffix must not fail open for the attacker."""

    def test_unknown_suffix_falls_back_to_the_last_two_labels(self):
        # The bundled snapshot is a point-in-time copy, so a TLD delegated
        # after it was cut lands here. Returning the whole hostname made
        # callers read the leftmost label as the registrable one.
        assert registrable_domain("paypal.com.evil.example") == "evil.example"
        assert registrable_domain("evil.example") == "evil.example"

    def test_known_suffix_is_unaffected(self):
        assert registrable_domain("paypal.com.evil.ru") == "evil.ru"
        assert registrable_domain("login.example.co.uk") == "example.co.uk"

    def test_single_label_and_ip_literals_are_returned_unchanged(self):
        assert registrable_domain("localhost") == "localhost"
        assert registrable_domain("192.168.1.1") == "192.168.1.1"

    def test_brand_under_an_unknown_suffix_is_no_longer_skipped(self):
        # The regression this fallback exists for: with the whole hostname as
        # the registrable domain, "paypal" was the main label, so the check
        # treated it as the real PayPal and returned nothing at all.
        checks = [f["check"] for f in check_typosquatting("paypal.com.evil.example")]
        assert "combosquatting" in checks
