"""Generate deterministic, sanitized .eml fixtures for offline regression tests.

These messages are synthetic test data. They are deliberately based on
reserved/example domains and contain no personal or operational content.
They must not be described as real SOC evidence.
"""

import argparse
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from datetime import datetime, timezone


SYNTHETIC_DEFINITIONS = []

for index in range(1, 7):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_benign_{index:02d}",
        "category": "benign",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "benign",
        "subject": f"Team update {index}",
    })

for index, url in enumerate([
    "https://example.com/account/verify",
    "https://example.com/security/update",
    "https://example.com/login/confirm",
    "https://example.com/bank/notice",
    "https://example.com/password/reset",
], 1):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_keyword_url_{index:02d}",
        "category": "suspicious_link",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "keyword_url",
        "url": url,
    })

for index in range(1, 7):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_auth_failure_{index:02d}",
        "category": "authentication_anomaly",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "trusted_gateway",
        "kind": "auth_failure",
        "subject": f"Authentication anomaly {index}",
    })

for index in range(1, 4):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_reply_mismatch_{index:02d}",
        "category": "business_email_compromise",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "trusted_gateway",
        "kind": "reply_mismatch",
        "reply_to": f"payee{index}@external.example",
    })

for index in range(1, 4):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_display_mismatch_{index:02d}",
        "category": "credential_phishing",
        "expected_disposition": "malicious_escalate",
        "auth_source": "trusted_gateway",
        "kind": "display_mismatch",
    })

for index in range(1, 5):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_attachment_{index:02d}",
        "category": "malware_delivery",
        "expected_disposition": "malicious_escalate",
        "auth_source": "trusted_gateway",
        "kind": "attachment",
        "filename": f"invoice_{index}.pdf.exe",
    })


def _common_message(case: dict) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "updates@example.com"
    message["To"] = "analyst@example.test"
    message["Date"] = format_datetime(datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc))
    message["Message-ID"] = f"<{case['id']}@example.com>"
    message["Subject"] = case.get("subject", "Synthetic notification")
    message["Received"] = "from mx.example.com (203.0.113.10) by mx.example.test"

    if case["auth_source"] == "trusted_gateway":
        message["Received-SPF"] = "fail (mx.example.com: synthetic test failure)"
        message["DKIM-Signature"] = "v=1; d=example.com; s=synthetic;"
        message["Authentication-Results"] = (
            "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
        )
    else:
        message["Received-SPF"] = "pass"
        message["DKIM-Signature"] = "v=1; d=example.com; s=synthetic;"
        message["Authentication-Results"] = (
            "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
        )

    if case["kind"] == "reply_mismatch":
        message.replace_header("From", "Finance <billing@example.com>")
        message["Reply-To"] = case["reply_to"]

    return message


def build_message(case: dict) -> EmailMessage:
    message = _common_message(case)
    kind = case["kind"]

    if kind == "display_mismatch":
        message.set_content("Please review the account notice in your email client.")
        message.add_alternative(
            '<html><body><a href="https://paypal-login.evil.example/verify">'
            "https://paypal.com</a></body></html>",
            subtype="html",
        )
    elif kind == "keyword_url":
        message.set_content(f"Please review this notice: {case['url']}")
    elif kind == "attachment":
        message.set_content("Invoice attached for review.")
        message.add_attachment(
            b"synthetic attachment content",
            maintype="application",
            subtype="x-msdownload",
            filename=case["filename"],
        )
    elif kind == "auth_failure":
        message.set_content("This is a synthetic authentication-anomaly message.")
    elif kind == "reply_mismatch":
        message.set_content("Please confirm the payment details through an approved channel.")
    else:
        message.set_content("This is a synthetic benign message for parser regression testing.")

    return message


def generate(output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for case in SYNTHETIC_DEFINITIONS:
        path = output_dir / f"{case['id']}.eml"
        path.write_bytes(build_message(case).as_bytes())
        paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "samples" / "generated",
    )
    args = parser.parse_args()
    paths = generate(args.output_dir)
    print(f"Generated {len(paths)} synthetic .eml fixtures in {args.output_dir}")


if __name__ == "__main__":
    main()
