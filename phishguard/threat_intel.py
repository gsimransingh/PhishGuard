import os
import time
import requests

# ---------------------------------------------------------------------------
# AbuseIPDB - IP Reputation Check
# https://www.abuseipdb.com/api
# Free tier: 1000 checks/day
# Set your key as environment variable: ABUSEIPDB_API_KEY
# ---------------------------------------------------------------------------

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"


def check_ip_abuseipdb(ip: str, api_key: str = None) -> dict:
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
        data = resp.json().get("data", {})
        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", ""),
            "is_tor": data.get("isTor", False),
            "error": None,
        }
    except requests.RequestException as e:
        return _stub_result("abuseipdb", ip, str(e))


def check_ips(ip_list: list, api_key: str = None) -> list:
    """
    Run AbuseIPDB checks on a list of IPs.
    Adds a 1-second delay between requests to respect rate limits.
    """
    results = []
    for ip in ip_list:
        result = check_ip_abuseipdb(ip, api_key)
        results.append(result)
        time.sleep(1)  # rate limiting
    return results


# ---------------------------------------------------------------------------
# VirusTotal - URL / Domain Reputation Check
# https://developers.virustotal.com/reference
# Free tier: 4 lookups/min, 500/day
# Set your key as environment variable: VIRUSTOTAL_API_KEY
# ---------------------------------------------------------------------------

def check_url_virustotal(url: str, api_key: str = None) -> dict:
    """
    Submit a URL to VirusTotal for reputation analysis.
    Returns detection stats (malicious, suspicious, clean engine counts).
    """
    import base64
    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return _stub_result("virustotal", url, "No API key set (VIRUSTOTAL_API_KEY)")

    headers = {"x-apikey": key}

    # VirusTotal v3 uses URL-safe base64 encoded URL as ID
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        if resp.status_code == 404:
            # URL not in VT database yet — submit it
            submit = requests.post(
                VIRUSTOTAL_URL_SCAN,
                headers=headers,
                data={"url": url},
                timeout=15
            )
            submit.raise_for_status()
            return {
                "source": "VirusTotal",
                "url": url,
                "status": "submitted_for_analysis",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "error": None,
            }
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "source": "VirusTotal",
            "url": url,
            "status": "analysed",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "error": None,
        }
    except requests.RequestException as e:
        return _stub_result("virustotal", url, str(e))


def check_urls(url_list: list, api_key: str = None) -> list:
    """
    Run VirusTotal checks on a list of URLs.
    Adds a 15-second delay between requests to respect free tier rate limits.
    """
    results = []
    for url in url_list:
        result = check_url_virustotal(url, api_key)
        results.append(result)
        time.sleep(15)  # VT free tier: 4 req/min
    return results


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _stub_result(source: str, indicator: str, error_msg: str) -> dict:
    """Return a stub result when no API key is available or a request fails."""
    return {
        "source": source,
        "indicator": indicator,
        "status": "skipped",
        "error": error_msg,
    }
