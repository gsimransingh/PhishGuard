"""Security-baseline tests for privacy defaults, hostile input, and exports."""

import csv
from argparse import Namespace
from io import StringIO

import pytest

from phishguard.analyzer import analyze
from phishguard import cli
from phishguard.cli import _should_use_color, export_csv, print_batch_summary, print_text_report
from phishguard.email_parser import EmailLimitError, _extract_urls, parse_eml
from phishguard.security import (
    MAX_ATTACHMENTS,
    MAX_BODY_CHARS,
    MAX_BATCH_BYTES,
    MAX_BATCH_FILES,
    MAX_EMAIL_BYTES,
    MAX_ENRICHED_BATCH_FILES,
    MAX_HEADER_BYTES,
    MAX_MIME_PARTS,
    MAX_URLS,
)
from phishguard.url_analyzer import analyze_url


def _minimal_parsed() -> dict:
    return {
        "subject": "Test subject",
        "from": "sender@example.test",
        "reply_to": "",
        "to": "recipient@example.test",
        "date": "today",
        "message_id": "<test@example.test>",
        "spf": "pass",
        "dkim": "present",
        "dmarc": "pass",
        "urls": [],
        "ips": [],
        "attachments": [],
        "received_chain": [],
    }


def _multipart_message(part_count: int, attachment: bool = False) -> bytes:
    boundary = b"secure-boundary"
    parts = [
        b"MIME-Version: 1.0\r\n",
        b"Content-Type: multipart/mixed; boundary=secure-boundary\r\n\r\n",
    ]
    for index in range(part_count):
        parts.extend([
            b"--" + boundary + b"\r\n",
            b"Content-Type: text/plain; charset=utf-8\r\n",
            b"Content-Disposition: attachment; filename=item.txt\r\n\r\n" if attachment else b"\r\n",
            f"part-{index}\r\n".encode(),
        ])
    parts.append(b"--" + boundary + b"--\r\n")
    return b"".join(parts)


class TestPrivacyFirstDefaults:
    def test_email_analysis_defaults_to_offline(self, monkeypatch):
        def _unexpected_lookup(_domain):
            raise AssertionError("default analysis must stay offline")

        monkeypatch.setattr("phishguard.analyzer.validate_spf_dns", _unexpected_lookup)
        monkeypatch.setattr("phishguard.analyzer.validate_dmarc_dns", _unexpected_lookup)

        report = analyze(_minimal_parsed(), "test.eml")

        assert report["dns_validation"] == {"spf": None, "dmarc": None}

    def test_url_analysis_defaults_to_offline(self, monkeypatch):
        monkeypatch.setattr(
            "phishguard.url_analyzer.check_domain_registration",
            lambda _hostname: pytest.fail("default URL analysis must stay offline"),
        )
        monkeypatch.setattr(
            "phishguard.url_analyzer.check_ssl_certificate",
            lambda _hostname: pytest.fail("default URL analysis must stay offline"),
        )

        report = analyze_url("paypa1.com")

        assert report["domain_registration"] is None
        assert report["ssl_certificate"] is None


class TestInputLimits:
    def test_rejects_file_larger_than_limit_before_parsing(self, tmp_path, monkeypatch):
        message = tmp_path / "oversized.eml"
        message.write_bytes(b"Subject: harmless\r\n\r\nbody")
        monkeypatch.setattr("phishguard.email_parser.os.path.getsize", lambda _path: MAX_EMAIL_BYTES + 1)

        with pytest.raises(EmailLimitError, match="Email is"):
            parse_eml(str(message))

    def test_rejects_oversized_or_malformed_headers(self, tmp_path):
        message = tmp_path / "large-header.eml"
        message.write_bytes(b"X-Long: " + b"A" * (MAX_HEADER_BYTES + 1))

        with pytest.raises(EmailLimitError, match="headers exceed"):
            parse_eml(str(message))

    def test_rejects_too_many_mime_parts(self, tmp_path):
        message = tmp_path / "many-parts.eml"
        message.write_bytes(_multipart_message(MAX_MIME_PARTS))

        with pytest.raises(EmailLimitError, match="MIME parts"):
            parse_eml(str(message))

    def test_rejects_excessive_plain_text_body(self, tmp_path):
        message = tmp_path / "large-body.eml"
        message.write_bytes(b"Subject: large body\r\n\r\n" + b"A" * (MAX_BODY_CHARS + 1))

        with pytest.raises(EmailLimitError, match="plain-text body"):
            parse_eml(str(message))

    def test_rejects_too_many_attachments(self, tmp_path):
        message = tmp_path / "many-attachments.eml"
        message.write_bytes(_multipart_message(MAX_ATTACHMENTS + 1, attachment=True))

        with pytest.raises(EmailLimitError, match="attachments"):
            parse_eml(str(message))

    def test_rejects_too_many_unique_urls(self):
        urls = " ".join(f"https://example.test/{index}" for index in range(MAX_URLS + 1))

        with pytest.raises(EmailLimitError, match="unique URLs"):
            _extract_urls(urls)


class TestBatchLimits:
    def test_rejects_too_many_batch_files(self, tmp_path):
        for index in range(MAX_BATCH_FILES + 1):
            (tmp_path / f"email-{index}.eml").write_text("Subject: test\n\nbody", encoding="utf-8")

        with pytest.raises(SystemExit, match="2"):
            cli.run_batch(Namespace(folder=str(tmp_path), enrich=False))

    def test_rejects_oversized_batch_before_parsing(self, tmp_path, monkeypatch):
        (tmp_path / "email.eml").write_text("Subject: test\n\nbody", encoding="utf-8")
        monkeypatch.setattr(cli.os.path, "getsize", lambda _path: MAX_BATCH_BYTES + 1)

        with pytest.raises(SystemExit, match="2"):
            cli.run_batch(Namespace(folder=str(tmp_path), enrich=False))

    def test_rejects_large_enriched_batch(self, tmp_path):
        for index in range(MAX_ENRICHED_BATCH_FILES + 1):
            (tmp_path / f"email-{index}.eml").write_text("Subject: test\n\nbody", encoding="utf-8")

        with pytest.raises(SystemExit, match="2"):
            cli.run_batch(Namespace(folder=str(tmp_path), enrich=True))


def test_csv_export_neutralizes_spreadsheet_formulas(tmp_path):
    csv_path = tmp_path / "report.csv"
    export_csv([
        {
            "file": "=HYPERLINK(\"https://example.test\")",
            "risk_level": "HIGH",
            "risk_score": 70,
            "flags": ["@danger"],
            "iocs": {"urls": ["=cmd"], "ips": ["+1+1"], "attachments": []},
            "analyzed_at": "today",
        }
    ], str(csv_path))

    with csv_path.open(newline="", encoding="utf-8") as report_file:
        row = next(csv.DictReader(report_file))

    assert row["file"].startswith("'=")
    assert row["flags"].startswith("'@")
    assert row["urls"].startswith("'=")
    assert row["ips"].startswith("'+")


def test_text_report_neutralizes_control_characters():
    report = {
        "version": "0.2.0",
        "file": "message.eml",
        "analyzed_at": "today",
        "risk_level": "LOW",
        "risk_score": 0,
        "email_metadata": {
            "subject": "normal\x1b[2J\nforged",
            "from": "sender@example.test",
            "reply_to": "",
            "to": "recipient@example.test",
            "date": "today",
            "message_id": "<id@example.test>",
        },
        "auth_headers": {"spf": "pass", "dkim": "present", "dmarc": "pass"},
        "dns_validation": {"spf": None, "dmarc": None},
        "flags": [],
        "iocs": {"urls": [], "ips": [], "attachments": []},
        "threat_intel": {"ip_checks": [], "url_checks": []},
    }
    output = StringIO()

    print_text_report(report, out=output)

    assert "\x1b" not in output.getvalue()
    assert "\\x1b[2J\\nforged" in output.getvalue()


class _InteractiveBuffer(StringIO):
    def isatty(self) -> bool:
        return True


def _report_with_risk(level: str) -> dict:
    return {
        "version": "0.3.1",
        "file": "message.eml",
        "analyzed_at": "today",
        "risk_level": level,
        "risk_score": 70,
        "email_metadata": {
            "subject": "test",
            "from": "sender@example.test",
            "reply_to": "",
            "to": "recipient@example.test",
            "date": "today",
            "message_id": "<id@example.test>",
        },
        "auth_headers": {"spf": "pass", "dkim": "present", "dmarc": "pass"},
        "dns_validation": {"spf": None, "dmarc": None},
        "flags": [],
        "iocs": {"urls": [], "ips": [], "attachments": []},
        "threat_intel": {"ip_checks": [], "url_checks": []},
    }


@pytest.mark.parametrize(("level", "escape"), [
    ("LOW", "\033[32m"),
    ("MEDIUM", "\033[38;5;220m"),
    ("HIGH", "\033[38;5;208m"),
    ("CRITICAL", "\033[1;31m"),
])
def test_text_risk_levels_use_expected_terminal_colors(level, escape):
    terminal = StringIO()

    saved_content = print_text_report(_report_with_risk(level), out=terminal, color=True)

    assert escape in terminal.getvalue()
    assert "\033[0m" in terminal.getvalue()
    assert "\033[" not in saved_content


def test_batch_summary_colors_terminal_only():
    terminal = StringIO()

    saved_content = print_batch_summary([_report_with_risk("HIGH")], out=terminal, color=True)

    assert "\033[38;5;208mHIGH" in terminal.getvalue()
    assert "\033[" not in saved_content


def test_color_mode_respects_tty_and_no_color_environment(monkeypatch):
    terminal = _InteractiveBuffer()
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")

    assert _should_use_color("auto", terminal) is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert _should_use_color("auto", terminal) is False
    assert _should_use_color("always", terminal) is True
    assert _should_use_color("never", terminal) is False
