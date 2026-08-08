"""Tests for the offline L1 evaluation harness."""

from pathlib import Path

from evaluation.run import evaluate_cases


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
