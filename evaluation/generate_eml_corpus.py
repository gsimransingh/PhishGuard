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


# Authentication profiles are chosen per case, independently of the
# ``auth_source`` provenance label. Deriving the headers from the label (every
# trusted_gateway case fails, every unknown_capture case passes) made "is this
# phishing" and "does authentication fail" the same variable, so no benign
# fixture could ever produce an authentication false positive — which is
# exactly the cost that has to be measurable before failures are scored.
AUTH_PROFILES: dict[str, dict | None] = {
    # Everything aligned: the ordinary case for legitimate direct mail.
    "pass": {"received_spf": "pass", "results": "spf=pass; dkim=pass; dmarc=pass"},
    # A spoof: nothing passes.
    "fail_all": {
        "received_spf": "fail (mx.example.com: synthetic test failure)",
        "results": "spf=fail; dkim=fail; dmarc=fail",
    },
    # Legitimate forwarding. The forwarding host is not in the original
    # domain's SPF record, so SPF breaks, but the body is unchanged so DKIM
    # survives and DMARC still passes on DKIM alignment. This is the most
    # common legitimate SPF failure there is.
    "forward_broken": {
        "received_spf": "fail (mx.relay.example: not authorized for example.com)",
        "results": "spf=fail; dkim=pass; dmarc=pass",
    },
    # The same thing with a softer qualifier (`~all` rather than `-all`).
    "forward_softfail": {
        "received_spf": "softfail (mx.relay.example: domain of transitioning sender)",
        "results": "spf=softfail; dkim=pass; dmarc=pass",
    },
    # A legitimate mailing list that appends a footer and rewrites the
    # subject. That edit invalidates the original DKIM signature, and with no
    # aligned identifier left, DMARC fails too. By authentication alone this
    # is indistinguishable from a spoof: the hard false-positive case.
    "list_broken": {
        "received_spf": "pass",
        "results": "spf=pass; dkim=fail (body hash did not verify); dmarc=fail",
    },
    # A small legitimate sender that publishes SPF but has never deployed
    # DKIM. Nothing failed; one mechanism is simply absent.
    "spf_only": {"received_spf": "pass", "results": "spf=pass; dmarc=pass", "no_dkim": True},
    # No authentication evidence preserved at all.
    "none": None,
}

# Real leading bytes, so the fixtures exercise file-signature detection rather
# than relying on the detector finding nothing. A benign .pdf fixture whose
# payload is not actually a PDF would quietly pass the signature check for the
# wrong reason, and stop being a benign case the moment the check improves.
PE_BYTES = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00synthetic PE stub"
PDF_BYTES = b"%PDF-1.4\n% synthetic PDF placeholder\n%%EOF\n"

SYNTHETIC_DEFINITIONS = []

for index in range(1, 7):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_benign_{index:02d}",
        "category": "benign",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "pass",
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
        "auth": "pass",
        "kind": "keyword_url",
        "url": url,
    })

for index in range(1, 7):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_auth_failure_{index:02d}",
        "category": "authentication_anomaly",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "trusted_gateway",
        "auth": "fail_all",
        "kind": "auth_failure",
        "subject": f"Authentication anomaly {index}",
    })

for index in range(1, 4):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_reply_mismatch_{index:02d}",
        "category": "business_email_compromise",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "trusted_gateway",
        "auth": "fail_all",
        "kind": "reply_mismatch",
        "reply_to": f"payee{index}@external.example",
    })

for index in range(1, 4):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_display_mismatch_{index:02d}",
        "category": "credential_phishing",
        "expected_disposition": "malicious_escalate",
        "auth_source": "trusted_gateway",
        "auth": "fail_all",
        "kind": "display_mismatch",
    })

for index in range(1, 5):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_attachment_{index:02d}",
        "category": "malware_delivery",
        "expected_disposition": "malicious_escalate",
        "auth_source": "trusted_gateway",
        "auth": "fail_all",
        "kind": "attachment",
        "filename": f"invoice_{index}.pdf.exe",
    })

for index, profile in enumerate(("forward_broken", "forward_softfail"), 1):
    SYNTHETIC_DEFINITIONS.append({
        "id": f"synthetic_forwarded_{index:02d}",
        "category": "benign_forwarded_mail",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": profile,
        "kind": "forwarded",
        "subject": f"Fwd: Team update {index}",
    })

SYNTHETIC_DEFINITIONS.extend([
    {
        "id": "synthetic_mailing_list_01",
        "category": "benign_mailing_list",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "list_broken",
        "kind": "mailing_list",
        "subject": "Community digest",
    },
    {
        "id": "synthetic_mailing_list_02",
        "category": "benign_mailing_list",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "list_broken",
        "kind": "mailing_list",
        "subject": "[dev-list] Re: release planning",
    },
    {
        # Was invisible: no Content-Disposition: attachment, so the payload
        # was never extracted and the message scored 0.
        "id": "synthetic_inline_executable_01",
        "category": "malware_delivery",
        # Not malicious_escalate: risky_attachment_extension is deliberately
        # not a direct malicious signal, because that set also covers .zip
        # and .rar, which arrive legitimately all the time.
        "expected_disposition": "suspicious_escalate",
        "auth_source": "unknown_capture",
        "auth": "fail_all",
        "kind": "inline_executable",
        "subject": "Invoice attached",
        "filename": "invoice.exe",
    },
    {
        # Was invisible: executable bytes behind a document name with a
        # generic MIME type, detectable only from the file signature.
        "id": "synthetic_disguised_executable_01",
        "category": "malware_delivery",
        "expected_disposition": "suspicious_escalate",
        "auth_source": "unknown_capture",
        "auth": "pass",
        "kind": "disguised_executable",
        "subject": "Requested document",
        "filename": "invoice.pdf",
    },
    {
        "id": "synthetic_benign_no_dkim_01",
        "category": "benign",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "spf_only",
        "kind": "benign",
        "subject": "Order confirmation",
    },
    {
        "id": "synthetic_legitimate_password_reset_01",
        "category": "benign_account_flow",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "pass",
        "kind": "keyword_url",
        "subject": "Password reset requested",
        "url": "https://example.com/password/reset",
    },
    {
        "id": "synthetic_marketing_link_01",
        "category": "benign_marketing",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "pass",
        "kind": "keyword_url",
        "subject": "Monthly newsletter",
        "url": "https://example.com/campaign/summer?utm_source=mail",
    },
    {
        "id": "synthetic_missing_auth_01",
        "category": "unknown_authentication",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "none",
        "kind": "missing_auth",
        "subject": "Message without preserved auth results",
    },
    {
        "id": "synthetic_safe_attachment_01",
        "category": "benign_attachment",
        "expected_disposition": "likely_benign",
        "auth_source": "unknown_capture",
        "auth": "pass",
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

    profile = AUTH_PROFILES[case["auth"]]
    if profile is not None:
        message["Received-SPF"] = profile["received_spf"]
        if not profile.get("no_dkim"):
            message["DKIM-Signature"] = "v=1; d=example.com; s=synthetic;"
        message["Authentication-Results"] = f"mx.example.com; {profile['results']}"

    if case["kind"] == "forwarded":
        # A forwarded message arrives via an extra relay hop that the original
        # domain never authorized, which is why its SPF result breaks.
        message["Received"] = (
            "from mx.relay.example (203.0.113.77) by mx.example.test"
        )
    elif case["kind"] == "mailing_list":
        # RFC 2919/2369 list headers: the structural evidence that an
        # intermediary is legitimately relaying and modifying this message.
        message["List-Id"] = "Community discussion <dev-list.example.com>"
        message["List-Unsubscribe"] = "<https://example.com/lists/dev/unsubscribe>"
        message["List-Post"] = "<mailto:dev-list@example.com>"
        message.replace_header("From", "Contributor <contributor@example.org>")

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
            PE_BYTES,
            maintype="application",
            subtype="x-msdownload",
            filename=case["filename"],
        )
    elif kind == "inline_executable":
        # Delivered with no Content-Disposition: attachment at all, which used
        # to make the payload invisible to the parser.
        message.set_content("Invoice attached for review.")
        message.add_attachment(
            PE_BYTES,
            maintype="application",
            subtype="octet-stream",
            filename=case["filename"],
            disposition="inline",
        )
    elif kind == "disguised_executable":
        # Executable bytes behind a document name and a generic MIME type:
        # only the file signature gives this away.
        message.set_content("Invoice attached for review.")
        message.add_attachment(
            PE_BYTES,
            maintype="application",
            subtype="octet-stream",
            filename=case["filename"],
        )
    elif kind == "safe_attachment":
        message.set_content("Invoice PDF attached for review.")
        message.add_attachment(
            PDF_BYTES,
            maintype="application",
            subtype="pdf",
            filename=case["filename"],
        )
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
