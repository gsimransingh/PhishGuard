"""Deterministic, sanitized variants for offline triage calibration.

These are intentionally parsed-message fixtures rather than real mail. They
exercise combinations of evidence without embedding personal or operational
data in the repository. Real sanitized .eml captures should be added before
using the resulting percentages as production accuracy claims.
"""


def _base(**overrides):
    parsed = {
        "subject": "Routine notification",
        "from": "updates@example.com",
        "reply_to": "updates@example.com",
        "to": "analyst@example.net",
        "date": "Mon, 10 Aug 2026 09:00:00 +0000",
        "message_id": "<synthetic@example.com>",
        "spf": "pass",
        "dkim": "v=1; d=example.com",
        "dmarc": "pass",
        "authentication_results": ["mx.example; spf=pass; dkim=pass; dmarc=pass"],
        "urls": [],
        "html_links": [],
        "ips": [],
        "attachments": [],
        "received_chain": [],
    }
    parsed.update(overrides)
    return parsed


def build_synthetic_cases():
    cases = []
    for index in range(1, 7):
        cases.append({
            "id": f"synthetic_benign_{index:02d}",
            "category": "benign",
            "expected_disposition": "likely_benign",
            "parsed": _base(subject=f"Team update {index}"),
        })

    for index, url in enumerate([
        "https://example.com/account/verify",
        "https://example.com/security/update",
        "https://example.com/login/confirm",
        "https://example.com/bank/notice",
        "https://example.com/password/reset",
    ], 1):
        cases.append({
            "id": f"synthetic_keyword_url_{index:02d}",
            "category": "suspicious_link",
            "expected_disposition": "likely_benign",
            "parsed": _base(urls=[url]),
        })

    for index in range(1, 7):
        cases.append({
            "id": f"synthetic_auth_failure_{index:02d}",
            "category": "authentication_anomaly",
            "expected_disposition": "suspicious_escalate",
            "auth_source": "trusted_gateway",
            "parsed": _base(
                subject=f"Authentication anomaly {index}",
                authentication_results=["mx.example; spf=fail; dkim=fail; dmarc=fail"],
                spf="fail", dkim="v=1; d=example.com", dmarc="fail",
            ),
        })

    for index in range(1, 4):
        cases.append({
            "id": f"synthetic_reply_mismatch_{index:02d}",
            "category": "business_email_compromise",
            "expected_disposition": "suspicious_escalate",
            "auth_source": "trusted_gateway",
            "parsed": _base(**{
                "from": "Finance <billing@example.com>",
                "reply_to": f"payee{index}@external.example",
                "authentication_results": ["mx.example; spf=fail; dkim=pass; dmarc=fail"],
                "spf": "fail", "dmarc": "fail",
            }),
        })

    for index in range(1, 4):
        cases.append({
            "id": f"synthetic_display_mismatch_{index:02d}",
            "category": "credential_phishing",
            "expected_disposition": "malicious_escalate",
            "auth_source": "trusted_gateway",
            "parsed": _base(
                subject="Urgent account verification",
                authentication_results=["mx.example; spf=fail; dkim=fail; dmarc=fail"],
                spf="fail", dmarc="fail",
                urls=["https://paypal-login.evil.example/verify"],
                html_links=[{
                    "displayed_text": "https://paypal.com",
                    "href": "https://paypal-login.evil.example/verify",
                }],
            ),
        })

    for index in range(1, 5):
        cases.append({
            "id": f"synthetic_attachment_{index:02d}",
            "category": "malware_delivery",
            "expected_disposition": "malicious_escalate",
            "auth_source": "trusted_gateway",
            "parsed": _base(
                subject="Invoice attached",
                authentication_results=["mx.example; spf=fail; dkim=fail; dmarc=fail"],
                spf="fail", dmarc="fail",
                attachments=[{
                    "filename": f"invoice_{index}.pdf.exe",
                    "content_type": "application/x-msdownload",
                    "size_bytes": 1024,
                }],
            ),
        })
    return cases
