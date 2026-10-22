"""Run a repeatable, offline evaluation of L1 triage dispositions."""

import argparse
import json
from collections import Counter
from pathlib import Path

from phishguard.analyzer import analyze
from phishguard.email_parser import parse_eml
from phishguard.triage import DISPOSITIONS


ESCALATING = {"suspicious_escalate", "malicious_escalate"}


DEFAULT_CLI_AUTH_SOURCE = "unknown_capture"


def evaluate_cases(
    repo_root: Path,
    cases: list[dict],
    auth_source_override: str | None = None,
) -> dict:
    """Score every case and compute disposition metrics.

    ``auth_source_override`` forces one provenance for every case. Use
    ``DEFAULT_CLI_AUTH_SOURCE`` to measure what an analyst gets when running
    the CLI without flags; per-case labels alone can leak the expected answer
    (e.g. if only phishing cases are marked ``trusted_gateway``).
    """
    results = []
    for case in cases:
        required = {"id", "category", "expected_disposition"}
        missing = required - case.keys()
        if missing:
            raise ValueError(f"Evaluation case {case.get('id', '<unknown>')} is missing: {sorted(missing)}")
        if case["expected_disposition"] not in DISPOSITIONS:
            raise ValueError(
                f"Evaluation case {case['id']} has invalid expected disposition: "
                f"{case['expected_disposition']}"
            )
        if "path" not in case and "parsed" not in case:
            raise ValueError(f"Evaluation case {case['id']} needs either path or parsed data")
        if "parsed" in case:
            path = repo_root / case.get("path", f"evaluation/{case['id']}")
            parsed = case["parsed"]
        else:
            path = repo_root / case["path"]
            if not path.is_file():
                raise FileNotFoundError(f"Evaluation sample does not exist: {path}")
            parsed = parse_eml(str(path))
        source_type = case.get(
            "source_type",
            "parsed_synthetic" if "parsed" in case else "checked_in_fixture",
        )
        auth_source = auth_source_override or case.get("auth_source", DEFAULT_CLI_AUTH_SOURCE)
        report = analyze(parsed, str(path), auth_source=auth_source)
        results.append({
            "id": case["id"],
            "category": case["category"],
            "expected_disposition": case["expected_disposition"],
            "predicted_disposition": report["disposition"],
            "risk_level": report["risk_level"],
            "risk_score": report["risk_score"],
            "auth_source": auth_source,
            "source_type": source_type,
            "finding_checks": sorted({finding["check"] for finding in report["findings"]}),
            "correct": report["disposition"] == case["expected_disposition"],
        })

    total = len(results)
    correct = sum(result["correct"] for result in results)
    expected_escalations = sum(result["expected_disposition"] in ESCALATING for result in results)
    predicted_escalations = sum(result["predicted_disposition"] in ESCALATING for result in results)
    true_positives = sum(
        result["expected_disposition"] in ESCALATING
        and result["predicted_disposition"] in ESCALATING
        for result in results
    )
    false_positives = sum(
        result["expected_disposition"] == "likely_benign"
        and result["predicted_disposition"] in ESCALATING
        for result in results
    )
    false_negatives = sum(
        result["expected_disposition"] in ESCALATING
        and result["predicted_disposition"] == "likely_benign"
        for result in results
    )
    confusion = {
        expected: {
            predicted: sum(
                result["expected_disposition"] == expected
                and result["predicted_disposition"] == predicted
                for result in results
            )
            for predicted in DISPOSITIONS
        }
        for expected in DISPOSITIONS
    }

    def grouped_metrics(key: str) -> dict:
        groups = {}
        for value in sorted({result[key] for result in results}):
            group = [result for result in results if result[key] == value]
            groups[value] = {
                "cases": len(group),
                "accuracy": sum(result["correct"] for result in group) / len(group),
                "expected_dispositions": dict(Counter(result["expected_disposition"] for result in group)),
                "predicted_dispositions": dict(Counter(result["predicted_disposition"] for result in group)),
            }
        return groups

    rule_case_counts = Counter(
        check for result in results for check in result["finding_checks"]
    )

    return {
        "contract": {
            "dispositions": list(DISPOSITIONS),
            "escalating_dispositions": sorted(ESCALATING),
        },
        "dataset": {"cases": total, "categories": dict(Counter(result["category"] for result in results))},
        "metrics": {
            "accuracy": correct / total if total else 0.0,
            "precision": true_positives / predicted_escalations if predicted_escalations else 0.0,
            "recall": true_positives / expected_escalations if expected_escalations else 0.0,
            "false_positive_rate": false_positives / sum(result["expected_disposition"] == "likely_benign" for result in results) if any(result["expected_disposition"] == "likely_benign" for result in results) else 0.0,
            "false_negative_rate": false_negatives / expected_escalations if expected_escalations else 0.0,
            "escalation_rate": predicted_escalations / total if total else 0.0,
            "insufficient_evidence_rate": sum(result["predicted_disposition"] == "insufficient_evidence" for result in results) / total if total else 0.0,
        },
        "confusion_matrix": confusion,
        "breakdowns": {
            "by_category": grouped_metrics("category"),
            "by_auth_source": grouped_metrics("auth_source"),
            "by_source_type": grouped_metrics("source_type"),
            "finding_rule_case_counts": dict(sorted(rule_case_counts.items())),
        },
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path(__file__).with_name("cases.json"))
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path")
    parser.add_argument(
        "--include-synthetic",
        action="store_true",
        help="Include deterministic generated .eml calibration fixtures",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a short human-readable summary instead of the full JSON report",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    cases = json.loads(args.dataset.read_text(encoding="utf-8"))
    if args.include_synthetic:
        from evaluation.synthetic_cases import build_synthetic_cases
        cases.extend(build_synthetic_cases())
    report = evaluate_cases(repo_root, cases)
    default_mode = evaluate_cases(repo_root, cases, auth_source_override=DEFAULT_CLI_AUTH_SOURCE)
    report["default_cli_mode"] = {
        "auth_source": DEFAULT_CLI_AUTH_SOURCE,
        "description": "Every case scored as the CLI scores it with no flags. This is the headline metric.",
        "metrics": default_mode["metrics"],
        "confusion_matrix": default_mode["confusion_matrix"],
        "misses": [
            {key: result[key] for key in ("id", "expected_disposition", "predicted_disposition", "risk_score")}
            for result in default_mode["results"]
            if not result["correct"]
        ],
    }
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if args.summary:
        _print_summary(report)
    else:
        print(rendered)


def _print_summary(report: dict) -> None:
    def line(label: str, metrics: dict) -> str:
        return (
            f"{label:<28} accuracy={metrics['accuracy']:.0%}  recall={metrics['recall']:.0%}  "
            f"precision={metrics['precision']:.0%}  FPR={metrics['false_positive_rate']:.0%}"
        )

    print(f"cases: {report['dataset']['cases']}")
    print(line("default CLI mode (headline)", report["default_cli_mode"]["metrics"]))
    print(line("per-case auth labels", report["metrics"]))
    for miss in report["default_cli_mode"]["misses"]:
        print(
            f"  miss: {miss['id']:<40} expected={miss['expected_disposition']:<20} "
            f"got={miss['predicted_disposition']} (score {miss['risk_score']})"
        )


if __name__ == "__main__":
    main()
