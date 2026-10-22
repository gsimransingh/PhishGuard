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

    assert len(cases) == 34
    assert all((repo_root / case["path"]).is_file() for case in cases)
    assert all(case["path"].endswith(".eml") for case in cases)
    assert {case["source_type"] for case in cases} == {"synthetic_generated_eml"}


# Ratchet for the headline metric. Raise these floors whenever a fix lands;
# never lower them to make a change pass. Values measured 2026-10-22 on the
# 41-case corpus (7 fixtures + 34 synthetic) in default CLI mode.
DEFAULT_MODE_RECALL_FLOOR = 11 / 21  # 0.7 PR2 severity floor: was 10/21
DEFAULT_MODE_MAX_FALSE_POSITIVE_RATE = 0.0


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
