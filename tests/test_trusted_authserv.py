"""--trusted-authserv-id: trust only our own Authentication-Results (RFC 8601 section 5)."""

import sys
from argparse import Namespace

import pytest

from phishguard import cli
from phishguard.analyzer import _authserv_id, analyze
from phishguard.email_parser import parse_eml

OUR_MX = "mx.example.com"


def _report(tmp_path, auth_headers: list[str], extra: str = "", **kwargs) -> dict:
    raw = "".join(f"Authentication-Results: {value}\n" for value in auth_headers) + (
        f"{extra}"
        "From: billing@sender.example\nTo: analyst@example.com\nSubject: Invoice\n"
        "Date: Wed, 29 Jul 2026 09:20:00 +0000\nMessage-ID: <t@example.test>\n"
        "Content-Type: text/plain\n\nPlease pay.\n"
    )
    path = tmp_path / "msg.eml"
    path.write_text(raw, encoding="utf-8")
    return analyze(parse_eml(str(path)), str(path), **kwargs)


def _checks(report: dict) -> set[str]:
    return {finding["check"] for finding in report["findings"]}


FAILS = f"{OUR_MX}; spf=fail smtp.mailfrom=sender.example; dkim=fail; dmarc=fail header.from=sender.example"
FORGED_PASS = f"{OUR_MX}; spf=pass; dkim=pass; dmarc=pass"


def test_own_header_failures_are_scored(tmp_path):
    report = _report(tmp_path, [FAILS], trusted_authserv_ids=(OUR_MX,))

    assert {"spf_failure", "dkim_failure", "dmarc_failure"} <= _checks(report)
    assert report["authentication_evidence"]["matched_authserv_id"] == OUR_MX
    assert report["authentication_evidence"]["source_context"] == "trusted_authserv_id"


def test_forged_pass_below_our_header_is_ignored(tmp_path):
    # Our gateway prepends its header above anything the sender wrote.
    report = _report(tmp_path, [FAILS, FORGED_PASS], trusted_authserv_ids=(OUR_MX,))

    assert "dmarc_failure" in _checks(report)


def test_sender_written_header_from_other_host_is_ignored(tmp_path):
    report = _report(
        tmp_path,
        ["attacker.example; spf=pass; dkim=pass; dmarc=pass", FAILS],
        trusted_authserv_ids=(OUR_MX,),
    )

    assert "dmarc_failure" in _checks(report)


def test_no_matching_header_scores_nothing_and_explains_why(tmp_path):
    report = _report(
        tmp_path,
        ["other.example; spf=fail; dkim=fail; dmarc=fail"],
        extra="Received-SPF: fail\n",
        trusted_authserv_ids=(OUR_MX,),
    )

    assert not _checks(report) & {"spf_failure", "dkim_failure", "dmarc_failure", "spf_missing", "dkim_missing", "dmarc_missing"}
    evidence = report["authentication_evidence"]
    assert evidence["matched_authserv_id"] is None
    assert "not scored" in evidence["caution"]


def test_without_configuration_behaviour_is_unchanged(tmp_path):
    report = _report(tmp_path, [FAILS])

    assert not _checks(report) & {"spf_failure", "dkim_failure", "dmarc_failure"}
    assert report["authentication_evidence"]["source_context"] == "unknown_capture"


@pytest.mark.parametrize("header, expected", [
    ("mx.example.com; spf=pass", "mx.example.com"),
    ("mx.example.com 1; spf=pass", "mx.example.com"),
    ("MX.Example.COM.; spf=pass", "mx.example.com"),
    ("  mx.example.com ;spf=pass", "mx.example.com"),
    ("", ""),
])
def test_authserv_id_parsing(header, expected):
    assert _authserv_id(header) == expected


def test_configured_ids_are_case_and_dot_insensitive(tmp_path):
    report = _report(tmp_path, [FAILS], trusted_authserv_ids=("MX.EXAMPLE.COM.",))

    assert "dmarc_failure" in _checks(report)


def test_cli_flag_is_repeatable_and_reaches_analysis(tmp_path, monkeypatch, capsys):
    import json

    from phishguard import cli

    path = tmp_path / "msg.eml"
    _report(tmp_path, [FAILS])  # writes msg.eml
    monkeypatch.setattr(sys, "argv", [
        "phishguard", "--no-banner", "-f", str(path), "-o", "json",
        "--trusted-authserv-id", "backup-mx.example.com",
        "--trusted-authserv-id", OUR_MX,
    ])
    cli.main()

    report = json.loads(capsys.readouterr().out)
    assert report["authentication_evidence"]["trusted_authserv_ids"] == ["backup-mx.example.com", OUR_MX]
    assert report["authentication_evidence"]["matched_authserv_id"] == OUR_MX


# --- PR4: persistent configuration and the unconfigured warning ------------



@pytest.mark.parametrize("flag, env, expected", [
    (None, "", ()),
    (None, "mx.example.com", ("mx.example.com",)),
    (None, " mx.example.com , backup.example.com ,, ", ("mx.example.com", "backup.example.com")),
    (["cli.example.com"], "mx.example.com", ("cli.example.com",)),  # flag overrides env
])
def test_trusted_ids_resolve_from_flag_then_environment(monkeypatch, flag, env, expected):
    monkeypatch.setenv(cli.TRUSTED_AUTHSERV_IDS_ENV, env)
    assert cli._resolve_trusted_authserv_ids(Namespace(trusted_authserv_id=flag)) == expected


def _run_single(monkeypatch, tmp_path, *extra):
    path = tmp_path / "msg.eml"
    _report(tmp_path, [FAILS])  # writes msg.eml
    monkeypatch.setattr(sys, "argv", ["phishguard", "--no-banner", "--no-color", "-f", str(path), *extra])
    cli.main()


def test_unconfigured_run_warns_and_report_says_scoring_is_off(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv(cli.TRUSTED_AUTHSERV_IDS_ENV, raising=False)
    _run_single(monkeypatch, tmp_path)

    captured = capsys.readouterr()
    assert "not scored" in captured.err
    assert "Auth score : OFF (not configured" in captured.out


def test_environment_configuration_scores_and_silences_warning(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv(cli.TRUSTED_AUTHSERV_IDS_ENV, OUR_MX)
    _run_single(monkeypatch, tmp_path, "-o", "json")

    captured = capsys.readouterr()
    assert "not scored" not in captured.err
    report = __import__("json").loads(captured.out)
    assert report["authentication_evidence"]["scoring_mode"] == "trusted_authserv_id"
    assert "dmarc_failure" in {finding["check"] for finding in report["findings"]}


@pytest.mark.parametrize("kwargs, headers, expected", [
    ({}, [FAILS], "disabled"),
    ({"auth_source": "trusted_gateway"}, [FAILS], "trusted_gateway"),
    ({"trusted_authserv_ids": (OUR_MX,)}, [FAILS], "trusted_authserv_id"),
    ({"trusted_authserv_ids": (OUR_MX,)}, ["other.example; spf=fail"], "trusted_authserv_id_no_match"),
])
def test_scoring_mode_is_reported(tmp_path, kwargs, headers, expected):
    assert _report(tmp_path, headers, **kwargs)["authentication_evidence"]["scoring_mode"] == expected


def test_html_report_states_authentication_scoring(tmp_path):
    from phishguard.report_generator import generate_html_report

    html = generate_html_report(_report(tmp_path, [FAILS]))

    assert "Authentication scoring:</strong> disabled" in html
    assert "NOT scored" in html
