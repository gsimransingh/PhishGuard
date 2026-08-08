"""Offline regression tests for optional VirusTotal behavior."""

from unittest.mock import Mock, patch

from phishguard.threat_intel import check_url_virustotal


def _not_found_response():
    return Mock(status_code=404, json=lambda: {})


@patch("phishguard.threat_intel.requests.post")
@patch("phishguard.threat_intel.requests.get")
def test_unknown_url_is_lookup_only_by_default(mock_get, mock_post):
    mock_get.return_value = _not_found_response()

    result = check_url_virustotal("https://unknown.example")

    assert result["status"] == "not_found"
    mock_post.assert_not_called()


@patch("phishguard.threat_intel.requests.post")
@patch("phishguard.threat_intel.requests.get")
def test_unknown_url_submission_requires_explicit_opt_in(mock_get, mock_post):
    mock_get.return_value = _not_found_response()
    mock_post.return_value = Mock(status_code=200, json=lambda: {"data": {"id": "analysis-1"}})

    result = check_url_virustotal("https://unknown.example", submit_unknown=True)

    assert result["status"] == "submitted_for_analysis"
    mock_post.assert_called_once()
