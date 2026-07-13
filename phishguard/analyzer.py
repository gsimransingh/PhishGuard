"""
PhishGuard Analyzer
Core analysis engine. Builds a structured risk report from parsed email data.
This module is intentionally decoupled from the CLI so it can be imported
by a web API, browser extension, or any other interface in the future.
"""

import os
import re
import sys
from datetime import datetime, timezone
from typing import Optional

from phishguard.threat_intel import check_ips, check_urls
from phishguard.dns_validator import validate_spf_dns, validate_dmarc_dns


def analyze(parsed: dict, file_path: str, run_intel: bool = True) -> dict:
    """
    Build a structured alert report from parsed email data.

    Args:
        parsed:     Output from email_parser.parse_eml()
        file_path:  Path to the original .eml file (used for display only)
        run_intel:  If True, enrich IPs and URLs with live threat intel

    Returns:
        A fully structured report dict ready for text/JSON/HTML/CEF output.
    """
    flags: list[str] = []
    score: int = 0

    # --- SPF / DKIM / DMARC header checks ---
    spf: str = parsed.get("spf", "").lower()
    dkim: str = parsed.get("dkim", "")
    dmarc: str = parsed.get("dmarc", "").lower()

    if "fail" in spf or "softfail" in spf:
        flags.append("SPF check failed")
        score += 30
    elif not spf:
        flags.append("SPF header missing")
        score += 15

    if not dkim:
        flags.append("DKIM signature missing")
        score += 20

    if "fail" in dmarc:
        flags.append("DMARC check failed")
        score += 25
    elif not dmarc:
        flags.append("DMARC result missing")
        score += 10

    # --- Reply-To mismatch ---
    # Compare extracted email addresses, not raw header strings. Comparing
    # raw strings caused a false positive on any legitimate email where the
    # From header includes a display name (e.g. "GitHub <noreply@github.com>")
    # but the Reply-To header doesn't (e.g. "noreply@github.com") — same
    # address, different string, previously flagged as a mismatch.
    sender: str = parsed.get("from", "")
    reply_to: str = parsed.get("reply_to", "")
    if reply_to and _extract_email_address(reply_to) != _extract_email_address(sender):
        flags.append(f"Reply-To mismatch: sender={sender}, reply_to={reply_to}")
        score += 20

    # --- Suspicious URLs ---
    urls: list[str] = parsed.get("urls", [])
    suspicious_keywords = ["login", "verify", "secure", "account", "update", "confirm", "password", "bank"]
    sus_urls = [u for u in urls if any(kw in u.lower() for kw in suspicious_keywords)]
    if sus_urls:
        flags.append(f"Suspicious URLs found: {sus_urls}")
        score += min(len(sus_urls) * 10, 30)

    # --- Attachments ---
    attachments: list[dict] = parsed.get("attachments", [])
    risky_exts = [".exe", ".js", ".vbs", ".bat", ".ps1", ".docm", ".xlsm", ".zip"]
    for att in attachments:
        fname = att.get("filename", "").lower()
        if any(fname.endswith(ext) for ext in risky_exts):
            flags.append(f"Risky attachment: {att['filename']}")
            score += 40

    # --- Live DNS validation ---
    dns_results: dict[str, Optional[dict]] = {"spf": None, "dmarc": None}
    sender_domain = _extract_domain(sender)
    if sender_domain:
        dns_results["spf"] = validate_spf_dns(sender_domain)
        dns_results["dmarc"] = validate_dmarc_dns(sender_domain)
        if dns_results["spf"] and dns_results["spf"].get("status") == "not_found":
            flags.append(f"No SPF DNS record found for domain: {sender_domain}")
            score += 10
        if dns_results["dmarc"] and dns_results["dmarc"].get("status") == "not_found":
            flags.append(f"No DMARC DNS record found for domain: {sender_domain}")
            score += 10

    # --- Threat Intel enrichment ---
    intel_ips: list[dict] = []
    intel_urls: list[dict] = []
    if run_intel:
        print("[*] Running threat intel lookups (this may take a moment)...", file=sys.stderr)
        if parsed.get("ips"):
            intel_ips = check_ips(parsed["ips"])
            for r in intel_ips:
                if r.get("abuse_confidence_score", 0) >= 50:
                    flags.append(f"High-abuse IP detected: {r['ip']} (score: {r['abuse_confidence_score']}, {r.get('isp', '')})")
                    score += 35
                elif r.get("abuse_confidence_score", 0) > 0:
                    flags.append(f"Reported IP: {r['ip']} (AbuseIPDB score: {r['abuse_confidence_score']})")
                    score += 15
        if urls:
            intel_urls = check_urls(urls[:3])
            for r in intel_urls:
                if r.get("malicious", 0) > 0:
                    flags.append(f"Malicious URL detected by VirusTotal: {r.get('url', r.get('indicator', ''))} ({r['malicious']} engines)")
                    score += 40

    # --- Risk level ---
    # CRITICAL (150+) means both the email's own auth/structure checks
    # failed AND an external signal (threat intel or a risky attachment)
    # corroborated it — not just a higher header-failure score. See the
    # module-level scoring table in README.md for the reasoning.
    if score >= 150:
        risk_level = "CRITICAL"
    elif score >= 70:
        risk_level = "HIGH"
    elif score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "tool":        "PhishGuard",
        "version":     "0.2.0",
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "file":        os.path.basename(file_path),
        "risk_level":  risk_level,
        "risk_score":  score,
        "flags":       flags,
        "email_metadata": {
            "subject":    parsed["subject"],
            "from":       parsed["from"],
            "reply_to":   parsed["reply_to"],
            "to":         parsed["to"],
            "date":       parsed["date"],
            "message_id": parsed["message_id"],
        },
        "auth_headers": {
            "spf":   parsed["spf"],
            "dkim":  "present" if parsed["dkim"] else "missing",
            "dmarc": parsed["dmarc"],
        },
        "dns_validation": dns_results,
        "iocs": {
            "urls":        parsed["urls"],
            "ips":         parsed["ips"],
            "attachments": parsed["attachments"],
        },
        "threat_intel": {
            "ip_checks":  intel_ips,
            "url_checks": intel_urls,
        },
        "received_chain": parsed["received_chain"],
    }


def _extract_domain(from_header: str) -> str:
    """Extract domain from a From: header like 'Name <user@domain.com>'."""
    match = re.search(r'@([\w.-]+)', from_header)
    return match.group(1) if match else ""


def _extract_email_address(header_value: str) -> str:
    """
    Extract the bare, lowercased email address from a header value.
    Handles both 'Name <user@domain.com>' and plain 'user@domain.com' forms,
    so comparisons between headers (e.g. From vs Reply-To) aren't thrown off
    by the presence or absence of a display name.
    """
    match = re.search(r'<([^<>]+)>', header_value)
    address = match.group(1) if match else header_value
    return address.strip().lower()