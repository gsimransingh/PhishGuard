"""
Tests for phishguard/email_parser.py

Covers:
- parse_eml() against the real sample .eml files (integration-style, uses
  actual disk files rather than hand-built email.message.Message objects,
  so a real parsing regression can't hide behind a hand-crafted fixture)
- Each extraction helper in isolation with hand-built input, including the
  RFC 1918 boundary cases for _is_private_ip that are easy to get subtly
  wrong (172.16.0.0/12 specifically, since only 172.16-172.31 is private,
  not the whole 172.x.x.x range)
"""

import pytest

from phishguard.email_parser import (
    _extract_html_links,
    _extract_ips,
    _extract_urls,
    _is_private_ip,
    parse_eml,
)
from phishguard.security import EmailLimitError, MAX_URLS


# ---------------------------------------------------------------------------
# parse_eml() — integration tests against real sample files
# ---------------------------------------------------------------------------

class TestParseEml:
    def test_extracts_basic_headers(self, phishing_test_eml):
        parsed = parse_eml(phishing_test_eml)
        assert parsed["from"] == "PayPal Billing <billing@paypal.com>"
        assert parsed["reply_to"] == "collect-funds@evil-domain.ru"
        assert "URGENT" in parsed["subject"]

    def test_extracts_urls_from_body(self, phishing_test_eml):
        parsed = parse_eml(phishing_test_eml)
        assert len(parsed["urls"]) == 2
        assert all(u.startswith("http://") for u in parsed["urls"])
        assert any("paypal-account-verify" in u for u in parsed["urls"])

    def test_extracts_public_ip_from_headers(self, phishing_test_eml):
        parsed = parse_eml(phishing_test_eml)
        assert "185.220.101.47" in parsed["ips"]

    def test_excludes_private_ip_from_received_chain(self, phishing_test_eml):
        # phishing_test.eml's Received chain includes "localhost [127.0.0.1]"
        # alongside the real public sender IP — the loopback address must
        # not leak into the IOC list.
        parsed = parse_eml(phishing_test_eml)
        assert "127.0.0.1" not in parsed["ips"]

    def test_legitimate_email_urls_are_all_github(self, legitimate_eml):
        # legitimate_email.eml is a real GitHub PR-merged notification and
        # does contain URLs (links back to github.com) — this is actually a
        # more useful sample than an email with zero URLs, since it verifies
        # ordinary legitimate links aren't themselves treated as IOCs of
        # concern by the extraction step (scoring is analyzer.py's job, not
        # email_parser.py's — this test only covers extraction).
        parsed = parse_eml(legitimate_eml)
        assert len(parsed["urls"]) == 2
        assert all("github.com" in u for u in parsed["urls"])

    def test_no_attachments_in_plain_text_sample(self, phishing_test_eml):
        parsed = parse_eml(phishing_test_eml)
        assert parsed["attachments"] == []

    def test_auth_headers_present_for_failing_sample(self, phishing_test_eml):
        parsed = parse_eml(phishing_test_eml)
        assert "fail" in parsed["spf"].lower()
        assert "fail" in parsed["dmarc"].lower()
        assert parsed["dkim"] == ""  # no DKIM-Signature header in this sample

    def test_extracts_urls_and_visible_text_from_html_only_email(self, html_legitimate_eml):
        parsed = parse_eml(html_legitimate_eml)

        assert parsed["body_text"] == ""
        assert len(parsed["html_links"]) == 2
        assert parsed["html_links"][0]["displayed_text"] == "https://example.com/account/summary"
        assert parsed["urls"] == [
            "https://www.example.com/account/summary",
            "https://www.example.com/help",
        ]

    def test_does_not_extract_script_or_image_sources(self, html_phishing_eml):
        parsed = parse_eml(html_phishing_eml)

        assert parsed["urls"] == ["https://paypal-login.evil.example/verify/account"]
        assert all("ignored.evil.example" not in url for url in parsed["urls"])
        assert all("tracker.evil.example" not in url for url in parsed["urls"])


# ---------------------------------------------------------------------------
# _extract_urls() — unit tests
# ---------------------------------------------------------------------------

class TestExtractUrls:
    def test_finds_single_url(self):
        text = "Click here: https://example.com/reset-password to continue."
        assert _extract_urls(text) == ["https://example.com/reset-password"]

    def test_finds_multiple_urls(self):
        text = "Two links: http://a.com/x and https://b.com/y here."
        urls = _extract_urls(text)
        assert set(urls) == {"http://a.com/x", "https://b.com/y"}

    def test_deduplicates_repeated_urls(self):
        text = "Same link twice: http://example.com http://example.com"
        assert _extract_urls(text) == ["http://example.com"]

    def test_preserves_url_appearance_order(self):
        text = "First https://first.example then https://second.example then https://first.example"
        assert _extract_urls(text) == ["https://first.example", "https://second.example"]

    def test_no_urls_returns_empty_list(self):
        assert _extract_urls("There are no links in this sentence at all.") == []

    def test_url_stops_at_angle_bracket(self):
        # A URL wrapped in <...> (common in raw email headers) shouldn't
        # swallow the closing bracket into the extracted URL.
        text = "See <http://example.com/path> for details."
        assert _extract_urls(text) == ["http://example.com/path"]


class TestExtractHtmlLinks:
    def test_extracts_only_http_anchor_destinations(self):
        html = (
            '<a href="https://example.com/reset"><strong>Reset</strong> account</a>'
            '<a href="javascript:alert(1)">bad</a>'
            '<img src="https://example.com/pixel">'
        )

        assert _extract_html_links(html) == [{
            "href": "https://example.com/reset",
            "displayed_text": "Reset account",
        }]

    def test_malformed_unclosed_anchor_is_recovered(self):
        links = _extract_html_links('<a href="https://example.com">Example')

        assert links == [{"href": "https://example.com", "displayed_text": "Example"}]

    def test_rejects_excessive_html_anchors_during_parsing(self):
        html = "".join(
            f'<a href="https://example.test/{index}">{index}</a>'
            for index in range(MAX_URLS + 1)
        )

        with pytest.raises(EmailLimitError, match="HTML links"):
            _extract_html_links(html)


# ---------------------------------------------------------------------------
# _is_private_ip() — RFC 1918 boundary tests
# ---------------------------------------------------------------------------

class TestIsPrivateIp:
    def test_loopback_is_private(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_10_range_is_private(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_192_168_range_is_private(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_172_16_31_range_is_private(self):
        # The whole point of the regex guard: only 172.16.x.x through
        # 172.31.x.x is private. This is the boundary that's easy to get
        # wrong with a naive startswith("172.") check.
        assert _is_private_ip("172.16.0.0") is True
        assert _is_private_ip("172.31.255.255") is True
        assert _is_private_ip("172.20.5.5") is True

    def test_172_outside_16_31_is_public(self):
        assert _is_private_ip("172.15.255.255") is False
        assert _is_private_ip("172.32.0.0") is False

    def test_public_ip_is_not_private(self):
        assert _is_private_ip("185.220.101.47") is False
        assert _is_private_ip("8.8.8.8") is False


# ---------------------------------------------------------------------------
# _extract_ips() — integration of extraction + private-IP filtering
# ---------------------------------------------------------------------------

class TestExtractIps:
    def test_filters_out_private_ips(self):
        text = "Received from 127.0.0.1 and 10.0.0.5 and 185.220.101.47"
        ips = _extract_ips(text)
        assert ips == ["185.220.101.47"]

    def test_returns_empty_list_when_only_private_ips_present(self):
        text = "Internal hop: 192.168.1.1 then 10.0.0.1"
        assert _extract_ips(text) == []

    def test_no_ips_in_text_returns_empty_list(self):
        assert _extract_ips("No IP addresses mentioned here.") == []

    def test_preserves_ip_appearance_order(self):
        text = "185.220.101.47 then 8.8.8.8 then 185.220.101.47"
        assert _extract_ips(text) == ["185.220.101.47", "8.8.8.8"]
