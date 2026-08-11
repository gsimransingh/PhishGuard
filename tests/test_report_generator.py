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
        "findings": [{
            "id": "hostile_test",
            "message": "<script>alert('finding')</script>",
            "weight": 10,
            "confidence": "<b>high</b>",
            "evidence": {"value": "<img src=x onerror=alert(1)>"},
            "false_positive_note": "<iframe src=evil>",
            "recommended_action": "<a href=evil>click</a>",
        }],
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
    assert "<script>alert('finding')</script>" not in html
    assert "&lt;script&gt;alert(&#x27;finding&#x27;)&lt;/script&gt;" in html
    assert "&lt;a href=evil&gt;click&lt;/a&gt;" in html


def test_html_report_escapes_untrusted_enrichment_content():
    report = _report_with_untrusted_content()
    report["threat_intel"] = {
        "ip_checks": [{
            "ip": "<img src=x onerror=alert(1)>",
            "abuse_confidence_score": 1,
            "total_reports": 1,
            "isp": "<script>alert('isp')</script>",
            "is_tor": False,
        }],
        "url_checks": [{
            "url": "https://example.test/<script>alert(1)</script>",
            "malicious": 1,
            "suspicious": 0,
        }],
    }

    html = generate_html_report(report)

    assert "<img src=x onerror=alert(1)>" not in html
    assert "<script>alert('isp')</script>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;script&gt;alert(&#x27;isp&#x27;)&lt;/script&gt;" in html


def test_cef_report_escapes_extension_delimiters_and_newlines():
    report = _report_with_untrusted_content()
    report["email_metadata"]["subject"] = "equals=value|pipe\nnext"
    report["flags"] = ["flag=value|pipe\nnext"]

    cef = generate_cef_log(report)

    assert "equals\\=value\\|pipe next" in cef
    assert "flag\\=value\\|pipe next" in cef


def test_analyst_handoff_fields_render_in_html_and_cef():
    report = _report_with_untrusted_content()
    report["disposition"] = "suspicious_escalate"
    report["triage"] = {
        "priority": "P2",
        "confidence": "high",
        "evidence_status": "sufficient",
        "escalation_reason": "Reply-To mismatch",
        "recommended_actions": ["Verify the reply destination independently."],
    }

    html = generate_html_report(report)
    cef = generate_cef_log(report)

    assert "suspicious_escalate" in html
    assert "Reply-To mismatch" in html
    assert "cs2Label=Disposition cs2=suspicious_escalate" in cef
    assert "cs3Label=Priority cs3=P2" in cef
