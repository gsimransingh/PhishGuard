"""Tests for phishguard/dns_validator.py (no live DNS; resolver is mocked)."""

import dns.resolver
import pytest

from phishguard.dns_validator import validate_dmarc_dns


class _Rdata:
    def __init__(self, text):
        self.strings = [text.encode()]


@pytest.fixture
def fake_dns(monkeypatch):
    """Install a resolver that answers from a dict; returns the query log."""
    queried = []

    def install(records):
        def _resolve(name, rtype, **_kwargs):
            queried.append(name)
            if name in records:
                return [_Rdata(records[name])]
            raise dns.resolver.NXDOMAIN()

        monkeypatch.setattr(dns.resolver, "resolve", _resolve)
        return queried

    return install


class TestDmarcOrganizationalFallback:
    def test_subdomain_without_record_inherits_organizational_policy(self, fake_dns):
        queried = fake_dns({"_dmarc.example.com": "v=DMARC1; p=reject"})
        result = validate_dmarc_dns("mail.example.com")
        assert queried == ["_dmarc.mail.example.com", "_dmarc.example.com"]
        assert result["status"] == "found"
        assert result["policy"]["policy"] == "reject"
        assert result["dmarc_domain"] == "_dmarc.example.com"
        assert result["inherited_from_organizational_domain"] is True

    def test_exact_domain_record_wins_and_no_fallback_query(self, fake_dns):
        queried = fake_dns({
            "_dmarc.mail.example.com": "v=DMARC1; p=quarantine",
            "_dmarc.example.com": "v=DMARC1; p=reject",
        })
        result = validate_dmarc_dns("mail.example.com")
        assert queried == ["_dmarc.mail.example.com"]
        assert result["policy"]["policy"] == "quarantine"
        assert result["inherited_from_organizational_domain"] is False

    def test_no_record_anywhere_is_not_found(self, fake_dns):
        queried = fake_dns({})
        result = validate_dmarc_dns("mail.example.com")
        assert queried == ["_dmarc.mail.example.com", "_dmarc.example.com"]
        assert result["status"] == "not_found"

    def test_registrable_domain_is_not_queried_twice(self, fake_dns):
        queried = fake_dns({})
        validate_dmarc_dns("example.com")
        assert queried == ["_dmarc.example.com"]

    def test_multi_label_public_suffix_uses_correct_organizational_domain(self, fake_dns):
        queried = fake_dns({})
        validate_dmarc_dns("mail.shop.example.co.uk")
        assert queried[-1] == "_dmarc.example.co.uk"

    def test_timeout_on_exact_lookup_is_an_error_not_a_missing_record(self, monkeypatch):
        queried = []

        def _resolve(name, rtype, **_kwargs):
            queried.append(name)
            raise dns.resolver.Timeout()

        monkeypatch.setattr(dns.resolver, "resolve", _resolve)
        result = validate_dmarc_dns("mail.example.com")
        assert result["status"] == "error"
        assert queried == ["_dmarc.mail.example.com"]
