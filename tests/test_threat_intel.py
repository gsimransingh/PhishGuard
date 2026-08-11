"""Offline regression tests for optional VirusTotal behavior."""

from unittest.mock import Mock, patch

from phishguard.threat_intel import check_ip_abuseipdb, check_url_virustotal


def _not_found_response():
    return Mock(status_code=404, json=lambda: {})


@patch("phishguard.threat_intel.requests.post")
@patch("phishguard.threat_intel.requests.get")
def test_unknown_url_is_lookup_only_by_default(mock_get, mock_post):
    mock_get.return_value = _not_found_response()

    result = check_url_virustotal("https://unknown.example", api_key="test-key")

    assert result["status"] == "not_found"
    mock_post.assert_not_called()


@patch("phishguard.threat_intel.requests.post")
@patch("phishguard.threat_intel.requests.get")
def test_unknown_url_submission_requires_explicit_opt_in(mock_get, mock_post):
    mock_get.return_value = _not_found_response()
    mock_post.return_value = Mock(status_code=200, json=lambda: {"data": {"id": "analysis-1"}})

    result = check_url_virustotal(
        "https://unknown.example",
        api_key="test-key",
        submit_unknown=True,
    )

    assert result["status"] == "submitted_for_analysis"
    mock_post.assert_called_once()


@patch("phishguard.threat_intel.requests.get")
def test_malformed_virustotal_payload_returns_structured_error(mock_get):
    mock_get.return_value = Mock(status_code=200, json=lambda: [])

    result = check_url_virustotal("https://unknown.example", api_key="test-key")

    assert result["status"] == "skipped"
    assert "not a JSON object" in result["error"]


@patch("phishguard.threat_intel.requests.get")
def test_malformed_abuseipdb_payload_returns_structured_error(mock_get):
    mock_get.return_value = Mock(status_code=200, json=lambda: [])

    result = check_ip_abuseipdb("8.8.8.8", api_key="test-key")

    assert result["status"] == "skipped"
    assert "not a JSON object" in result["error"]


@patch("phishguard.threat_intel.requests.get")
def test_non_numeric_service_counters_are_safe(mock_get):
    mock_get.return_value = Mock(
        status_code=200,
        json=lambda: {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": "not-a-number",
                        "suspicious": None,
                        "harmless": "3",
                        "undetected": -4,
                    }
                }
            }
        },
    )

    result = check_url_virustotal("https://unknown.example", api_key="test-key")

    assert result["malicious"] == 0
    assert result["suspicious"] == 0
    assert result["harmless"] == 3
    assert result["undetected"] == 0
