"""
Shared pytest fixtures for the PhishGuard test suite.

Network isolation
------------------
Tests must never depend on live network access — that would make the suite
slow, flaky, and unusable offline or in CI. This file patches the
network-touching functions with deterministic stubs by default.

When tests enable external enrichment, the DNS validators are stubbed by
default. Offline analysis (run_intel=False) must not call them at all.

Tests that want AbuseIPDB/VirusTotal or RDAP behavior specifically patch
those functions locally inside the test itself, since not every test needs
them and it's clearer to see the mock right next to the assertion using it.
"""

import os

import pytest

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def sample_path(filename: str) -> str:
    return os.path.join(SAMPLES_DIR, filename)


# ---------------------------------------------------------------------------
# Sample .eml file paths
# ---------------------------------------------------------------------------

@pytest.fixture
def legitimate_eml() -> str:
    return sample_path("legitimate_email.eml")


@pytest.fixture
def phishing_test_eml() -> str:
    return sample_path("phishing_test.eml")


@pytest.fixture
def phishing_amazon_eml() -> str:
    return sample_path("phishing_amazon.eml")


@pytest.fixture
def suspicious_eml() -> str:
    return sample_path("suspicious_email.eml")


# ---------------------------------------------------------------------------
# Network isolation
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_real_dns(monkeypatch):
    """
    Every test gets a stubbed DNS validator by default (SPF/DMARC both
    "found", both a healthy-looking policy), so nobody accidentally writes
    an enrichment test that hits live DNS. A test that specifically wants
    the "not_found" scoring path can override either stub in its body.
    """
    def _fake_spf(domain):
        return {"domain": domain, "status": "found", "record": "v=spf1 -all", "error": None}

    def _fake_dmarc(domain):
        return {
            "domain": domain,
            "dmarc_domain": f"_dmarc.{domain}",
            "status": "found",
            "record": "v=DMARC1; p=reject",
            "policy": {"policy": "reject", "subdomain_policy": "reject", "report_uri": "", "pct": "100"},
            "error": None,
        }

    monkeypatch.setattr("phishguard.analyzer.validate_spf_dns", _fake_spf)
    monkeypatch.setattr("phishguard.analyzer.validate_dmarc_dns", _fake_dmarc)
