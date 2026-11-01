"""--trusted-authserv-id: believe a 'pass' only from our own receiving servers.

RFC 8601 section 5. Anyone can write an Authentication-Results header, so a
``pass`` is worth nothing until we know which server wrote it. A recorded
*failure* is different: forging one against yourself gains an attacker
nothing, so failures score with or without this configuration. These tests
pin both halves of that asymmetry, because it is easy to "fix" one by
breaking the other.
"""

import sys

import pytest

from phishguard.analyzer import _authserv_id, analyze
from phishguard.email_parser import parse_eml

OUR_MX = "mx.example.com"

FAILS = f"{OUR_MX}; spf=fail smtp.mailfrom=sender.example; dkim=fail; dmarc=fail header.from=sender.example"
FORGED_PASS = f"{OUR_MX}; spf=pass; dkim=pass; dmarc=pass"
AUTH_CHECKS = {"spf_failure", "dkim_failure", "dmarc_failure"}


def _write(tmp_path, auth_headers: list[str], extra: str = "") -> str:
    raw = "".join(f"Authentication-Results: {value}\n" for value in auth_headers) + (
        f"{extra}"
        "From: billing@sender.example\nTo: analyst@example.com\nSubject: Invoice\n"
        "Date: Wed, 29 Jul 2026 09:20:00 +0000\nMessage-ID: <t@example.test>\n"
        "Content-Type: text/plain\n\nPlease pay.\n"
    )
    path = tmp_path / "msg.eml"
    path.write_text(raw, encoding="utf-8")
    return str(path)


def _report(tmp_path, auth_headers: list[str], extra: str = "", **kwargs) -> dict:
    path = _write(tmp_path, auth_headers, extra)
    return analyze(parse_eml(path), path, **kwargs)


def _checks(report: dict) -> set[str]:
    return {finding["check"] for finding in report["findings"]}


# --- believing a result from our own server ----------------------------------

def test_own_header_failures_are_scored(tmp_path):
    report = _report(tmp_path, [FAILS], trusted_authserv_ids=(OUR_MX,))

    assert AUTH_CHECKS <= _checks(report)
    evidence = report["authentication_evidence"]
    assert evidence["matched_authserv_id"] == OUR_MX
    assert evidence["scoring_mode"] == "verified_authserv_id"
    assert evidence["source_context"] == "trusted_authserv_id"
    assert evidence["dmarc"]["scored_because"] == "verified_own_authserv_id"


def test_forged_pass_below_our_header_is_ignored(tmp_path):
    """Our gateway prepends its header above anything the sender wrote."""
    report = _report(tmp_path, [FAILS, FORGED_PASS], trusted_authserv_ids=(OUR_MX,))

    assert "dmarc_failure" in _checks(report)


def test_sender_written_header_from_another_host_is_ignored(tmp_path):
    report = _report(
        tmp_path,
        ["attacker.example; spf=pass; dkim=pass; dmarc=pass", FAILS],
        trusted_authserv_ids=(OUR_MX,),
    )

    assert "dmarc_failure" in _checks(report)


def test_configured_ids_are_case_and_dot_insensitive(tmp_path):
    report = _report(tmp_path, [FAILS], trusted_authserv_ids=("MX.EXAMPLE.COM.",))

    assert "dmarc_failure" in _checks(report)


# --- what configuration does NOT change -------------------------------------

def test_no_matching_header_still_scores_recorded_failures(tmp_path):
    """Configuring ids must not create a silent miss.

    A failure recorded by some other host is still self-authenticating, so it
    scores. What we withhold is belief in a *pass*, not sight of a failure.
    """
    report = _report(
        tmp_path,
        ["other.example; spf=fail; dkim=fail; dmarc=fail"],
        trusted_authserv_ids=(OUR_MX,),
    )

    assert AUTH_CHECKS <= _checks(report)
    evidence = report["authentication_evidence"]
    assert evidence["matched_authserv_id"] is None
    assert evidence["scoring_mode"] == "authserv_id_no_match"
    assert evidence["dmarc"]["scored_because"] == "recorded_failure"


def test_without_configuration_recorded_failures_still_score(tmp_path):
    report = _report(tmp_path, [FAILS])

    assert AUTH_CHECKS <= _checks(report)
    evidence = report["authentication_evidence"]
    assert evidence["scoring_mode"] == "failures_only"
    assert evidence["source_context"] == "unknown_capture"


@pytest.mark.parametrize("auth_kwargs", [
    {},
    {"trusted_authserv_ids": (OUR_MX,)},
])
def test_a_pass_from_an_unnamed_host_is_never_believed(tmp_path, auth_kwargs):
    report = _report(
        tmp_path,
        ["attacker.example; spf=pass; dkim=pass; dmarc=pass"],
        **auth_kwargs,
    )

    assert not _checks(report) & AUTH_CHECKS
    assert report["risk_score"] == 0
    assert report["authentication_evidence"]["spf"]["score_status"] == "untrusted"


# --- provenance and relay context are orthogonal -----------------------------

def _mailing_list_report(tmp_path, **kwargs) -> dict:
    return _report(
        tmp_path,
        [f"{OUR_MX}; spf=pass; dkim=fail (body hash did not verify); dmarc=fail"],
        extra=(
            "List-Id: Community discussion <dev-list.example.com>\n"
            "List-Unsubscribe: <https://example.com/lists/dev/unsubscribe>\n"
        ),
        **kwargs,
    )


def test_verifying_who_wrote_the_header_does_not_cancel_relay_softening(tmp_path):
    """A mailing list breaks DKIM whoever recorded the break.

    Knowing our own server wrote the header makes the failure *certain*, not
    *sinister*. Treating a matched authserv-id as a reason to score at full
    weight escalated both mailing-list fixtures (FPR 0% -> 8%) the first time
    this was wired up, so the two concepts stay separate here.
    """
    configured = _mailing_list_report(tmp_path, trusted_authserv_ids=(OUR_MX,))
    unconfigured = _mailing_list_report(tmp_path)

    assert configured["risk_score"] == unconfigured["risk_score"]
    assert configured["disposition"] == "likely_benign"
    dkim = next(f for f in configured["findings"] if f["check"] == "dkim_failure")
    assert dkim["confidence"] == "low"
    assert "reduced weight" in dkim["false_positive_note"]


def test_analyst_declared_trusted_gateway_still_overrides_softening(tmp_path):
    """An explicit human judgement about the capture is a different signal."""
    softened = _mailing_list_report(tmp_path, trusted_authserv_ids=(OUR_MX,))
    declared = _mailing_list_report(tmp_path, auth_source="trusted_gateway")

    assert declared["risk_score"] > softened["risk_score"]


# --- the authserv-id parser --------------------------------------------------

@pytest.mark.parametrize("header, expected", [
    ("mx.example.com; spf=pass", "mx.example.com"),
    ("mx.example.com 1; spf=pass", "mx.example.com"),
    ("MX.Example.COM.; spf=pass", "mx.example.com"),
    ("  mx.example.com ;spf=pass", "mx.example.com"),
    ("mx.example.com", "mx.example.com"),
    ("", ""),
    (";", ""),
])
def test_authserv_id_parsing(header, expected):
    assert _authserv_id(header) == expected


def test_blank_configured_ids_are_discarded(tmp_path):
    """An empty environment variable must not look like a configured server."""
    report = _report(tmp_path, [FAILS], trusted_authserv_ids=("", "   "))

    assert report["authentication_evidence"]["scoring_mode"] == "failures_only"
    assert report["authentication_evidence"]["trusted_authserv_ids"] == []


# --- reaching the feature through the CLI ------------------------------------

def _run_cli(tmp_path, monkeypatch, capsys, argv_extra: list[str], env=None) -> dict:
    import json

    from phishguard import cli

    path = _write(tmp_path, [FAILS])
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", [
        "phishguard", "--no-banner", "-f", path, "-o", "json", *argv_extra,
    ])
    cli.main()
    return json.loads(capsys.readouterr().out)


def test_cli_flag_is_repeatable_and_reaches_analysis(tmp_path, monkeypatch, capsys):
    report = _run_cli(tmp_path, monkeypatch, capsys, [
        "--trusted-authserv-id", "backup-mx.example.com",
        "--trusted-authserv-id", OUR_MX,
    ])

    evidence = report["authentication_evidence"]
    assert evidence["trusted_authserv_ids"] == ["backup-mx.example.com", OUR_MX]
    assert evidence["matched_authserv_id"] == OUR_MX


def test_environment_variable_supplies_ids(tmp_path, monkeypatch, capsys):
    report = _run_cli(
        tmp_path, monkeypatch, capsys, [],
        env={"PHISHGUARD_TRUSTED_AUTHSERV_IDS": f"backup-mx.example.com, {OUR_MX}"},
    )

    assert report["authentication_evidence"]["matched_authserv_id"] == OUR_MX


def test_flag_overrides_the_environment_variable(tmp_path, monkeypatch, capsys):
    report = _run_cli(
        tmp_path, monkeypatch, capsys,
        ["--trusted-authserv-id", "other.only"],
        env={"PHISHGUARD_TRUSTED_AUTHSERV_IDS": OUR_MX},
    )

    evidence = report["authentication_evidence"]
    assert evidence["trusted_authserv_ids"] == ["other.only"]
    assert evidence["matched_authserv_id"] is None


def _stderr_of_cli_run(tmp_path, monkeypatch, capsys, argv_extra: list[str]) -> str:
    from phishguard import cli
    from phishguard.cli import TRUSTED_AUTHSERV_IDS_ENV

    monkeypatch.delenv(TRUSTED_AUTHSERV_IDS_ENV, raising=False)
    path = _write(tmp_path, [FAILS])
    monkeypatch.setattr(sys, "argv", [
        "phishguard", "--no-banner", "-f", path, "-o", "json", *argv_extra,
    ])
    cli.main()
    return capsys.readouterr().err


def test_unconfigured_run_warns_how_to_configure(tmp_path, monkeypatch, capsys):
    from phishguard.cli import TRUSTED_AUTHSERV_IDS_ENV

    stderr = _stderr_of_cli_run(tmp_path, monkeypatch, capsys, [])

    assert TRUSTED_AUTHSERV_IDS_ENV in stderr
    # The warning must not claim failures are unscored; they are.
    assert "failures are still scored" in stderr


def test_configured_run_does_not_warn(tmp_path, monkeypatch, capsys):
    stderr = _stderr_of_cli_run(
        tmp_path, monkeypatch, capsys, ["--trusted-authserv-id", OUR_MX]
    )

    assert "[!]" not in stderr
