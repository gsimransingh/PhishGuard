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


# --- A5: terminal output lets C1 and bidi controls through -------------------

def test_a5_bidi_override_is_escaped():
    from phishguard.cli import _safe_terminal_text

    # U+202E RIGHT-TO-LEFT OVERRIDE would make "moc.live" render as "evil.com".
    assert _safe_terminal_text("moc.‮live‬") == "moc.\\u202elive\\u202c"


def test_a5_c1_control_is_escaped():
    from phishguard.cli import _safe_terminal_text

    # U+009B is the 8-bit CSI, which some terminals treat like ESC [.
    assert _safe_terminal_text("x\x9b31my") == "x\\x9b31my"


def test_a5_zero_width_characters_are_visible():
    from phishguard.cli import _safe_terminal_text

    assert _safe_terminal_text("pay​pal") == "pay\\u200bpal"


def test_a5_ordinary_unicode_is_unchanged():
    from phishguard.cli import _safe_terminal_text

    assert _safe_terminal_text("Ünïcødé – ok") == "Ünïcødé – ok"


# --- A6: batch mode silently ignores -o -----------------------------------

import json
import shutil
import sys
from pathlib import Path

import pytest

SAMPLES = Path(__file__).parent.parent / "samples"


def _batch_folder(tmp_path):
    for name in ("legitimate_email.eml", "phishing_test.eml"):
        shutil.copy(SAMPLES / name, tmp_path / name)
    return tmp_path


def _run_cli(monkeypatch, *argv):
    from phishguard import cli

    monkeypatch.setattr(sys, "argv", ["phishguard", "--no-banner", "--no-color", *argv])
    cli.main()


def test_a6_batch_json_outputs_a_json_array_on_stdout(tmp_path, monkeypatch, capsys):
    _run_cli(monkeypatch, "-F", str(_batch_folder(tmp_path)), "-o", "json", "-V")

    captured = capsys.readouterr()
    reports = json.loads(captured.out)  # stdout must be pure JSON, even with -V
    assert [report["file"] for report in reports] == ["legitimate_email.eml", "phishing_test.eml"]
    assert all("risk_level" in report for report in reports)
    assert "Batch Analysis Summary" in captured.err


def test_a6_batch_json_saves_json_with_save_output(tmp_path, monkeypatch, capsys):
    out_file = tmp_path / "out" / "batch.json"
    out_file.parent.mkdir()
    _run_cli(monkeypatch, "-F", str(_batch_folder(tmp_path)), "-o", "json", "-O", str(out_file))

    capsys.readouterr()
    assert len(json.loads(out_file.read_text(encoding="utf-8"))) == 2


def test_a6_batch_cef_outputs_one_event_per_email(tmp_path, monkeypatch, capsys):
    _run_cli(monkeypatch, "-F", str(_batch_folder(tmp_path)), "-o", "cef")

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert all(line.startswith("CEF:0|PhishGuard|") for line in lines)


def test_a6_batch_html_is_rejected_explicitly(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit) as exit_info:
        _run_cli(monkeypatch, "-F", str(_batch_folder(tmp_path)), "-o", "html")

    captured = capsys.readouterr()
    assert exit_info.value.code == 1
    assert captured.out == ""
    assert "not supported for batch" in captured.err


# --- A7: raw tracebacks for unreadable input or unwritable output ----------

def test_a7_unreadable_email_gives_clean_error(monkeypatch, capsys):
    from phishguard import cli

    def _denied(_path):
        raise PermissionError(13, "Permission denied", "locked.eml")

    monkeypatch.setattr(cli, "parse_eml", _denied)
    with pytest.raises(SystemExit) as exit_info:
        _run_cli(monkeypatch, "-f", str(SAMPLES / "legitimate_email.eml"))

    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert "[ERROR] Could not read" in err
    assert "Traceback" not in err


def test_a7_unwritable_save_path_gives_clean_error(tmp_path, monkeypatch, capsys):
    target = tmp_path / "missing-dir" / "out.json"
    with pytest.raises(SystemExit) as exit_info:
        _run_cli(monkeypatch, "-f", str(SAMPLES / "legitimate_email.eml"), "-o", "json", "-O", str(target))

    assert exit_info.value.code == 1
    assert "[ERROR] Could not write output" in capsys.readouterr().err


def test_a7_unwritable_batch_save_path_gives_clean_error(tmp_path, monkeypatch, capsys):
    target = tmp_path / "missing-dir" / "summary.txt"
    with pytest.raises(SystemExit) as exit_info:
        _run_cli(monkeypatch, "-F", str(_batch_folder(tmp_path)), "-O", str(target))

    assert exit_info.value.code == 1
    assert "[ERROR] Could not write output" in capsys.readouterr().err
