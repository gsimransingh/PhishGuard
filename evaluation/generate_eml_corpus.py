"""Generate deterministic, sanitized .eml fixtures for offline regression tests.

These messages are synthetic test data. They are deliberately based on
reserved/example domains and contain no personal or operational content.
They must not be described as real SOC evidence.

The brand_notification cases are the one exception to the reserved-domain
rule: they use real brand-owned sending domains, because what they test is
whether the brand-owned domain allowlist stops PhishGuard escalating ordinary
Microsoft 365, Amazon, and Google mail. The message bodies are still invented
and assert nothing about those companies.
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

for index in range(1, 3):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_forwarded_{index:02d}",
        "category": "benign_forwarded_mail",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "forwarded",
        "subject": f"Fwd: Team update {index}",
    })

SYNTHETIC_DEFINITIONS.extend([
    {
        "id": "synthetic_mailing_list_01",
        "category": "benign_mailing_list",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "mailing_list",
        "subject": "Community digest",
    },
    {
        "id": "synthetic_legitimate_password_reset_01",
        "category": "benign_account_flow",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "keyword_url",
        "subject": "Password reset requested",
        "url": "https://example.com/password/reset",
    },
    {
        "id": "synthetic_marketing_link_01",
        "category": "benign_marketing",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "keyword_url",
        "subject": "Monthly newsletter",
        "url": "https://example.com/campaign/summer?utm_source=mail",
    },
    {
        "id": "synthetic_missing_auth_01",
        "category": "unknown_authentication",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "missing_auth",
        "subject": "Message without preserved auth results",
    },
    # Brand impersonation of the SENDER, not of a link: nothing in these
    # messages is suspicious except the From header itself.
    {
        "id": "synthetic_lookalike_sender_01",
        "category": "credential_phishing",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "unknown_capture",
        "kind": "lookalike_sender",
        "subject": "Your account has been limited",
        "from": '"PayPal Security" <service@paypa1.example>',
    },
    {
        "id": "synthetic_lookalike_sender_02",
        "category": "credential_phishing",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "unknown_capture",
        "kind": "lookalike_sender",
        "subject": "Unusual sign-in activity",
        "from": '"Microsoft Account Team" <no-reply@microsoft-account-security.example>',
    },
    # A brand buried in the subdomains of a host under a TLD the bundled
    # public-suffix snapshot does not know. Before the registrable-domain
    # fallback was fixed, the leftmost label read as the real brand and this
    # scored nothing at all.
    {
        "id": "synthetic_unknown_suffix_brand_url_01",
        "category": "credential_phishing",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "unknown_capture",
        "kind": "brand_subdomain_url",
        "subject": "Confirm your account details",
        "from": '"PayPal Service" <service@billing.example>',
        "url": "https://paypal.com.verify-account.example/login",
    },
    # Ordinary brand mail that must stay out of the queue. These are the
    # false positives the 0.8 brand work exists to prevent.
    {
        "id": "synthetic_brand_notification_01",
        "category": "benign_brand_notification",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "brand_notification",
        "subject": "Message center major change update",
        "from": '"Microsoft 365 Message center" <o365mc@microsoft.com>',
        "links": [
            "https://admin.microsoft.com/adminportal/home",
            "https://login.microsoftonline.com/common/oauth2/authorize",
        ],
    },
    {
        "id": "synthetic_brand_notification_02",
        "category": "benign_brand_notification",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "brand_notification",
        "subject": "Your order has shipped",
        "from": '"Amazon.com" <ship-confirm@amazon.com>',
        "links": [
            "https://www.amazon.com/gp/css/order-history",
            "https://m.media-amazon.com/images/G/01/logo.png",
            "https://s3.amazonaws.com/receipts/order.pdf",
        ],
    },
    {
        "id": "synthetic_brand_notification_03",
        "category": "benign_brand_notification",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "brand_notification",
        "subject": "Security alert for your linked account",
        "from": '"Google" <no-reply@accounts.google.com>',
        "links": [
            "https://myaccount.google.com/notifications",
            "https://fonts.googleapis.com/css?family=Roboto",
            "https://ssl.gstatic.com/accounts/logo.png",
        ],
    },
    {
        "id": "synthetic_safe_attachment_01",
        "category": "benign_attachment",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "kind": "safe_attachment",
        "subject": "Invoice PDF",
        "filename": "invoice.pdf",
    },
])


def _common_message(case: dict) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "updates@example.com"
    message["To"] = "analyst@example.test"
    message["Date"] = format_datetime(datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc))
    message["Message-ID"] = f"<{case['id']}@example.com>"
    message["Subject"] = case.get("subject", "Synthetic notification")
    message["Received"] = "from mx.example.com (203.0.113.10) by mx.example.test"

    if case["kind"] == "missing_auth":
        pass
    elif case["auth_source"] == "trusted_gateway":
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

    if case.get("from"):
        message.replace_header("From", case["from"])

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
    elif kind == "safe_attachment":
        message.set_content("Invoice PDF attached for review.")
        message.add_attachment(
            b"synthetic PDF placeholder",
            maintype="application",
            subtype="pdf",
            filename=case["filename"],
        )
    elif kind == "lookalike_sender":
        message.set_content(
            "Your account has been limited. Confirm your details to restore access."
        )
    elif kind == "brand_subdomain_url":
        message.set_content(f"Confirm your account details here: {case['url']}")
    elif kind == "brand_notification":
        lines = ["This is an account notification.", ""] + list(case["links"])
        message.set_content("\n".join(lines) + "\n")
    elif kind == "auth_failure":
        message.set_content("This is a synthetic authentication-anomaly message.")
    elif kind == "reply_mismatch":
        message.set_content("Please confirm the payment details through an approved channel.")
    else:
        message.set_content("This is a synthetic benign message for parser regression testing.")

    if message.is_multipart():
        message.set_boundary(f"synthetic-{case['id']}")
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
