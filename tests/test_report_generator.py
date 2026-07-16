"""Regression tests for report rendering safety and CEF field escaping."""

from phishguard.report_generator import generate_cef_log, generate_html_report


def _report_with_untrusted_content() -> dict:
    return {
        "tool": "PhishGuard",
        "version": "0.2.0",
        "analyzed_at": "2026-07-16T00:00:00Z",
        "file": "<report>.eml",
        "risk_level": "HIGH",
        "risk_score": 70,
        "flags": ["<script>alert('flag')</script>"],
        "email_metadata": {
            "subject": "<script>alert('subject')</script>",
            "from": "sender@example.test",
            "reply_to": "",
            "to": "recipient@example.test",
            "date": "today",
            "message_id": "<id@example.test>",
        },
        "auth_headers": {"spf": "pass", "dkim": "present", "dmarc": "pass"},
        "iocs": {
            "urls": ["https://example.test/?q=<tag>"],
            "ips": ["203.0.113.10"],
            "attachments": [{"filename": "<invoice>.pdf", "content_type": "application/pdf", "size_bytes": 1}],
        },
        "threat_intel": {"ip_checks": [], "url_checks": []},
    }


def test_html_report_escapes_untrusted_email_content():
    html = generate_html_report(_report_with_untrusted_content())

    assert "<script>alert('subject')</script>" not in html
    assert "&lt;script&gt;alert(&#x27;subject&#x27;)&lt;/script&gt;" in html
    assert "https://example.test/?q=&lt;tag&gt;" in html
    assert "&lt;invoice&gt;.pdf" in html


def test_cef_report_escapes_extension_delimiters_and_newlines():
    report = _report_with_untrusted_content()
    report["email_metadata"]["subject"] = "equals=value|pipe\nnext"
    report["flags"] = ["flag=value|pipe\nnext"]

    cef = generate_cef_log(report)

    assert "equals\\=value\\|pipe next" in cef
    assert "flag\\=value\\|pipe next" in cef
