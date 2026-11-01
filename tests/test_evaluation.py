"""Tests for the offline L1 evaluation harness."""

from pathlib import Path

from evaluation.run import evaluate_cases
from evaluation.synthetic_cases import build_synthetic_cases


def test_evaluation_reports_metrics_and_confusion_matrix():
    repo_root = Path(__file__).parent.parent
    cases = [
        {
            "id": "benign",
            "path": "samples/legitimate_email.eml",
            "category": "benign",
            "expected_disposition": "likely_benign",
            "auth_source": "unknown_capture",
        },
        {
            "id": "phishing",
            "path": "samples/phishing_test.eml",
            "category": "credential_phishing",
            "expected_disposition": "suspicious_escalate",
            "auth_source": "trusted_gateway",
        },
    ]

    report = evaluate_cases(repo_root, cases)

    assert report["dataset"]["cases"] == 2
    assert report["metrics"]["accuracy"] == 1.0
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["confusion_matrix"]["suspicious_escalate"]["suspicious_escalate"] == 1
    assert report["breakdowns"]["by_auth_source"]["trusted_gateway"]["cases"] == 1
    assert "dmarc_failure" in report["breakdowns"]["finding_rule_case_counts"]


def test_synthetic_corpus_is_backed_by_eml_files():
    repo_root = Path(__file__).parent.parent
    cases = build_synthetic_cases()

    assert len(cases) == 44
    assert all((repo_root / case["path"]).is_file() for case in cases)
    assert all(case["path"].endswith(".eml") for case in cases)
    assert {case["source_type"] for case in cases} == {"synthetic_generated_eml"}


# Ratchet for the headline metric. Raise these floors whenever a fix lands;
# never lower them to make a change pass. Measured 2026-11-01 on the 51-case
# corpus (7 fixtures + 44 synthetic) in default CLI mode, after the brand work
# added 6 cases: 3 lookalike-sender/brand-URL phishing cases and 3 legitimate
# Microsoft 365 / Amazon / Google notifications. Earlier floors were 10/21
# (48%), 20/21 (95%) and 23/23 (100%) on 45 cases.
#
# The floor is now 1.0, which does NOT mean detection is finished — it means
# this corpus has stopped discriminating. Three confirmed gaps are still open
# as strict xfails in tests/test_known_gaps.py (ten are documented in the
# README), and none of those three has a case here. A saturated corpus is a
# reason to add harder cases (0.9: real sanitized captures), not a reason to
# claim accuracy.
#
# Keep this a recall floor and a false-positive ceiling, never an equality
# assertion on accuracy: that was the shape of the withdrawn 100% claim.
#
# The false-positive ceiling is only meaningful because the benign half of the
# corpus contains messages that legitimately fail authentication — forwarded
# mail (SPF breaks) and mailing-list mail (DKIM and DMARC break). Keep it that
# way: a benign set where nothing can fail authentication cannot measure the
# cost of scoring failures.
DEFAULT_MODE_RECALL_FLOOR = 1.0
DEFAULT_MODE_MAX_FALSE_POSITIVE_RATE = 0.0


def test_benign_corpus_can_produce_an_authentication_false_positive():
    """Guard the corpus property the false-positive ceiling depends on.

    Before this, every benign fixture carried spf=pass/dkim=pass/dmarc=pass,
    because the generator derived the auth headers from each case's
    ``auth_source`` label. "Is this phishing" and "does auth fail" were the
    same variable, so a 0% false-positive rate was structurally guaranteed
    rather than earned, and the cost of scoring failures was invisible.
    """
    import re

    repo_root = Path(__file__).parent.parent
    failing_benign = []
    for case in build_synthetic_cases():
        if case["expected_disposition"] != "likely_benign":
            continue
        raw = (repo_root / case["path"]).read_text(encoding="utf-8", errors="replace")
        header = re.search(r"^Authentication-Results:((?:.*\n)(?:[ \t].*\n)*)", raw, re.M)
        if header and re.search(r"=\s*(fail|softfail|permerror)", header.group(1)):
            failing_benign.append(case["id"])

    assert len(failing_benign) >= 4, (
        "the benign corpus must keep messages that legitimately fail "
        f"authentication; found only {failing_benign}"
    )


def test_default_cli_mode_does_not_regress():
    """Measure what an analyst gets with no flags, not the per-case labels.

    Per-case auth_source labels can leak the expected answer: if only phishing
    cases are marked trusted_gateway, auth failures score only on phishing.
    Forcing the CLI default for every case removes that leak.
    """
    import json

    from evaluation.run import DEFAULT_CLI_AUTH_SOURCE

    repo_root = Path(__file__).parent.parent
    cases = json.loads((repo_root / "evaluation" / "cases.json").read_text(encoding="utf-8"))
    cases += build_synthetic_cases()

    report = evaluate_cases(repo_root, cases, auth_source_override=DEFAULT_CLI_AUTH_SOURCE)

    assert {result["auth_source"] for result in report["results"]} == {DEFAULT_CLI_AUTH_SOURCE}
    assert report["metrics"]["recall"] >= DEFAULT_MODE_RECALL_FLOOR
    assert report["metrics"]["false_positive_rate"] <= DEFAULT_MODE_MAX_FALSE_POSITIVE_RATE
