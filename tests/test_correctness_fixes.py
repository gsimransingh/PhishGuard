"""Regression tests for correctness bugs A1-A7 (code review 2026-10-22).

Each test was written to fail against the pre-fix code and pass after it.
"""

from phishguard.email_parser import _extract_urls


# --- A1: URLs keep trailing punctuation -------------------------------------

def test_a1_trailing_sentence_punctuation_is_not_part_of_url():
    text = "Log in (https://paypal.com/login). Or https://evil.example/x, today! See https://a.example/b;"
    assert _extract_urls(text) == [
        "https://paypal.com/login",
        "https://evil.example/x",
        "https://a.example/b",
    ]


def test_a1_balanced_parentheses_inside_url_are_kept():
    text = "Docs: https://en.wikipedia.org/wiki/Phishing_(security)."
    assert _extract_urls(text) == ["https://en.wikipedia.org/wiki/Phishing_(security)"]


# --- A2: malformed RDAP reply crashes --enrich ------------------------------

class _FakeRDAPResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _offline_tls(monkeypatch):
    monkeypatch.setattr(
        "phishguard.url_analyzer.check_ssl_certificate",
        lambda hostname, port=443: {
            "hostname": hostname, "status": "unavailable", "issuer": None,
            "not_before": None, "not_after": None, "days_since_issued": None,
            "error": "stubbed",
        },
    )


def test_a2_non_string_rdap_status_does_not_crash_enrichment(monkeypatch):
    from phishguard.url_analyzer import analyze_url

    payload = {
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
        "status": [1, None, {"x": 1}, "clientHold"],
    }
    monkeypatch.setattr("phishguard.url_analyzer.requests.get", lambda *a, **k: _FakeRDAPResponse(payload))
    _offline_tls(monkeypatch)

    report = analyze_url("example.com", run_intel=True)

    assert report["domain_registration"]["domain_status"] == ["clientHold"]
    assert "registrar_restriction" in {finding["check"] for finding in report["findings"]}


def test_a2_non_list_rdap_status_is_ignored(monkeypatch):
    from phishguard.url_analyzer import analyze_url

    payload = {
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
        "status": "clientHold",
    }
    monkeypatch.setattr("phishguard.url_analyzer.requests.get", lambda *a, **k: _FakeRDAPResponse(payload))
    _offline_tls(monkeypatch)

    report = analyze_url("example.com", run_intel=True)

    assert report["domain_registration"]["domain_status"] == []


# --- A3: DMARC sp defaults to "none" instead of inheriting p -----------------

def test_a3_missing_sp_inherits_p():
    from phishguard.dns_validator import _parse_dmarc_policy

    assert _parse_dmarc_policy("v=DMARC1; p=reject")["subdomain_policy"] == "reject"


def test_a3_explicit_sp_is_kept():
    from phishguard.dns_validator import _parse_dmarc_policy

    assert _parse_dmarc_policy("v=DMARC1; p=reject; sp=none")["subdomain_policy"] == "none"


# --- A4: multi-string TXT records are truncated -----------------------------

class _FakeTXT:
    def __init__(self, *chunks: bytes):
        self.strings = chunks


def _fake_resolver(monkeypatch, answers: dict):
    import dns.resolver

    def _resolve(name, rtype, **_kwargs):
        if name in answers:
            return answers[name]
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", _resolve)


def test_a4_spf_record_split_across_strings_is_joined(monkeypatch):
    from phishguard.dns_validator import validate_spf_dns

    _fake_resolver(monkeypatch, {
        "example.com": [_FakeTXT(b"v=spf1 include:_spf.google.com ", b"include:mailgun.org -all")],
    })

    result = validate_spf_dns("example.com")

    assert result["record"] == "v=spf1 include:_spf.google.com include:mailgun.org -all"


def test_a4_dmarc_record_split_across_strings_is_joined(monkeypatch):
    from phishguard.dns_validator import validate_dmarc_dns

    _fake_resolver(monkeypatch, {
        "_dmarc.example.com": [_FakeTXT(b"v=DMARC1; p=quarantine; ", b"sp=reject; rua=mailto:d@example.com")],
    })

    result = validate_dmarc_dns("example.com")

    assert result["policy"]["subdomain_policy"] == "reject"
    assert result["policy"]["report_uri"] == "mailto:d@example.com"
