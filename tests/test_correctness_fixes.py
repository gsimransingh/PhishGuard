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
