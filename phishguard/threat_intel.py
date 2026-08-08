import os
import time
from typing import Optional
import requests

# ---------------------------------------------------------------------------
# AbuseIPDB - IP Reputation Check
# https://www.abuseipdb.com/api
# Free tier: 1000 checks/day
# Set your key as environment variable: ABUSEIPDB_API_KEY
# ---------------------------------------------------------------------------

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"


def check_ip_abuseipdb(ip: str, api_key: Optional[str] = None) -> dict:
    """
    Query AbuseIPDB for reputation data on a given IP address.
    Returns a dict with abuse confidence score, country, ISP, and total reports.
    Falls back to a stub result if no API key is provided.
    """
    key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return _stub_result("abuseipdb", ip, "No API key set (ABUSEIPDB_API_KEY)")

    headers = {
        "Accept": "application/json",
        "Key": key,
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True,
    }

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError("AbuseIPDB response was not a JSON object")
        data = payload.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("AbuseIPDB response data was not an object")
        return {
            "source":                 "AbuseIPDB",
            "ip":                     ip,
            "abuse_confidence_score": _as_nonnegative_int(data.get("abuseConfidenceScore", 0)),
            "country_code":           data.get("countryCode", ""),
            "isp":                    data.get("isp", ""),
            "domain":                 data.get("domain", ""),
            "total_reports":          _as_nonnegative_int(data.get("totalReports", 0)),
            "last_reported":          data.get("lastReportedAt", ""),
            "is_tor":                 data.get("isTor", False),
            "error":                  None,
        }
    except (requests.RequestException, ValueError, TypeError, AttributeError) as e:
        return _stub_result("abuseipdb", ip, str(e))


def check_ips(ip_list: list[str], api_key: Optional[str] = None) -> list[dict]:
    """
    Run AbuseIPDB checks on a list of IPs.
    Adds a 1-second delay between requests to respect rate limits.
    """
    results = []
    key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
    for index, ip in enumerate(ip_list):
        results.append(check_ip_abuseipdb(ip, key))
        if key and index < len(ip_list) - 1:
            time.sleep(1)
    return results


# ---------------------------------------------------------------------------
# VirusTotal - URL / Domain Reputation Check
# https://developers.virustotal.com/reference
# Free tier: 4 lookups/min, 500/day
# Set your key as environment variable: VIRUSTOTAL_API_KEY
# ---------------------------------------------------------------------------

def check_url_virustotal(
    url: str,
    api_key: Optional[str] = None,
    submit_unknown: bool = False,
) -> dict:
    """
    Submit a URL to VirusTotal for reputation analysis.
    Returns detection stats (malicious, suspicious, clean engine counts).
    """
    import base64
    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return _stub_result("virustotal", url, "No API key set (VIRUSTOTAL_API_KEY)")

    headers = {"x-apikey": key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        if resp.status_code == 404 and submit_unknown:
            submit = requests.post(
                VIRUSTOTAL_URL_SCAN,
                headers=headers,
                data={"url": url},
                timeout=15
            )
            submit.raise_for_status()
            return {
                "source":     "VirusTotal",
                "url":        url,
                "status":     "submitted_for_analysis",
                "malicious":  0,
                "suspicious": 0,
                "harmless":   0,
                "undetected": 0,
                "error":      None,
            }
        if resp.status_code == 404:
            return {
                "source": "VirusTotal",
                "url": url,
                "status": "not_found",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "error": None,
            }
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError("VirusTotal response was not a JSON object")
        data = payload.get("data", {})
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}
        if not isinstance(stats, dict):
            raise ValueError("VirusTotal analysis stats were not an object")
        return {
            "source":     "VirusTotal",
            "url":        url,
            "status":     "analysed",
            "malicious":  _as_nonnegative_int(stats.get("malicious", 0)),
            "suspicious": _as_nonnegative_int(stats.get("suspicious", 0)),
            "harmless":   _as_nonnegative_int(stats.get("harmless", 0)),
            "undetected": _as_nonnegative_int(stats.get("undetected", 0)),
            "error":      None,
        }
    except (requests.RequestException, ValueError, TypeError, AttributeError) as e:
        return _stub_result("virustotal", url, str(e))


def check_urls(
    url_list: list[str],
    api_key: Optional[str] = None,
    submit_unknown: bool = False,
) -> list[dict]:
    """
    Run VirusTotal checks on a list of URLs.
    Adds a 15-second delay between requests to respect free tier rate limits.
    """
    results = []
    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    for index, url in enumerate(url_list):
        results.append(check_url_virustotal(url, key, submit_unknown=submit_unknown))
        if key and index < len(url_list) - 1:
            time.sleep(15)
    return results


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _as_nonnegative_int(value: object) -> int:
    """Normalize untrusted service counters before they reach scoring logic."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0

def _stub_result(source: str, indicator: str, error_msg: str) -> dict:
    """Return a stub result when no API key is available or a request fails."""
    return {
        "source":    source,
        "indicator": indicator,
        "status":    "skipped",
        "error":     error_msg,
    }
