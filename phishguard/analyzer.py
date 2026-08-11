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
from urllib.parse import urlparse

from phishguard.threat_intel import check_ips, check_urls
from phishguard.dns_validator import validate_spf_dns, validate_dmarc_dns
from phishguard.url_analyzer import analyze_url, registrable_domain
from phishguard.triage import disposition_for_findings
from phishguard import __version__
from phishguard.security import MAX_IP_ENRICHMENTS, MAX_URL_ENRICHMENTS


def analyze(
    parsed: dict,
    file_path: str,
    run_intel: bool = False,
    submit_unknown_urls: bool = False,
    auth_source: str = "unknown_capture",
) -> dict:
    """
    Build a structured alert report from parsed email data.

    Args:
        parsed:     Output from email_parser.parse_eml()
        file_path:  Path to the original .eml file (used for display only)
        run_intel:  If True, perform external DNS and threat-intelligence
                    enrichment. Defaults to False for fully offline analysis.

    Returns:
        A fully structured report dict ready for text/JSON/HTML/CEF output.
    """
    findings: list[dict] = []
    flags: list[str] = []
    score: int = 0
    finding_counts: dict[str, int] = {}

    def add_finding(
        finding_id: str,
        message: str,
        weight: int,
        confidence: str,
        evidence: dict,
        false_positive_note: str,
        recommended_action: str,
    ) -> None:
        nonlocal score
        finding_counts[finding_id] = finding_counts.get(finding_id, 0) + 1
        occurrence = finding_counts[finding_id]
        instance_id = finding_id if occurrence == 1 else f"{finding_id}#{occurrence}"
        score_contribution = weight if occurrence == 1 else 0
        findings.append({
            "id": instance_id,
            "check": finding_id,
            "message": message,
            "weight": weight,
            "score_contribution": score_contribution,
            "evidence_count": occurrence,
            "confidence": confidence,
            "evidence": evidence,
            "false_positive_note": false_positive_note,
            "recommended_action": recommended_action,
        })
        flags.append(message)
        score += score_contribution

    # --- SPF / DKIM / DMARC interpretation ---
    auth_trusted = auth_source == "trusted_gateway"
    auth_evidence = _interpret_authentication(parsed, trusted=auth_trusted)
    spf_status = auth_evidence["spf"]["score_status"]
    dkim_status = auth_evidence["dkim"]["score_status"]
    dmarc_status = auth_evidence["dmarc"]["score_status"]

    if spf_status in ("fail", "softfail", "permerror"):
        add_finding(
            "spf_failure", "SPF check failed", 30, "medium",
            {"status": spf_status, "source": auth_evidence["spf"]["source"]},
            "Forwarding and mailing-list infrastructure can legitimately break SPF.",
            "Validate the trusted receiving server's Authentication-Results header and sender alignment.",
        )
    elif spf_status == "missing":
        add_finding(
            "spf_missing", "SPF header missing", 15, "low",
            {"status": spf_status},
            "Some receiving systems do not preserve SPF results.",
            "Check the message's trusted Authentication-Results header or perform approved DNS validation.",
        )

    if dkim_status in ("fail", "permerror"):
        add_finding(
            "dkim_failure", "DKIM verification failed", 25, "medium",
            {"status": dkim_status, "source": auth_evidence["dkim"]["source"]},
            "Messages can be modified in transit by legitimate gateways or mailing lists.",
            "Validate the trusted receiver's DKIM result and signing-domain alignment.",
        )
    elif dkim_status == "missing":
        add_finding(
            "dkim_missing", "DKIM signature missing", 20, "low",
            {"status": dkim_status},
            "DKIM is not universally deployed and its absence is not proof of spoofing.",
            "Compare this absence with SPF, DMARC, sender history, and message content.",
        )

    if dmarc_status in ("fail", "permerror"):
        add_finding(
            "dmarc_failure", "DMARC check failed", 25, "high",
            {"status": dmarc_status, "source": auth_evidence["dmarc"]["source"]},
            "Forwarding or receiver-specific evaluation can occasionally produce legitimate failures.",
            "Confirm the trusted receiver's DMARC result and inspect SPF/DKIM alignment.",
        )
    elif dmarc_status == "missing":
        add_finding(
            "dmarc_missing", "DMARC result missing", 10, "low",
            {"status": dmarc_status},
            "The receiving system may not record DMARC results.",
            "Check trusted gateway logs or perform approved domain-policy validation.",
        )

    # --- Reply-To mismatch ---
    # Compare extracted email addresses, not raw header strings. Comparing
    # raw strings caused a false positive on any legitimate email where the
    # From header includes a display name (e.g. "GitHub <noreply@github.com>")
    # but the Reply-To header doesn't (e.g. "noreply@github.com") — same
    # address, different string, previously flagged as a mismatch.
    sender: str = parsed.get("from", "")
    reply_to: str = parsed.get("reply_to", "")
    if reply_to and _extract_email_address(reply_to) != _extract_email_address(sender):
        add_finding(
            "reply_to_mismatch",
            f"Reply-To mismatch: sender={sender}, reply_to={reply_to}",
            20, "medium",
            {"from": sender, "reply_to": reply_to},
            "Legitimate services sometimes route replies through a separate support or ticketing domain.",
            "Verify the Reply-To domain and intended reply workflow through a trusted channel.",
        )

    # --- Suspicious URLs ---
    urls: list[str] = parsed.get("urls", [])
    url_analysis: list[dict] = []
    suspicious_keywords = ["login", "verify", "secure", "account", "update", "confirm", "password", "bank"]
    sus_urls = [u for u in urls if any(kw in u.lower() for kw in suspicious_keywords)]
    if sus_urls:
        add_finding(
            "suspicious_url_keywords",
            f"Suspicious URLs found: {sus_urls}",
            min(len(sus_urls) * 10, 30), "low",
            {"urls": sus_urls},
            "Legitimate authentication and account-management pages often contain these words.",
            "Inspect destination domains and compare them with the claimed sender.",
        )

    # Reuse the standalone URL engine for every URL found in an email.  Keep
    # this structural/brand analysis offline even when email enrichment is
    # enabled; reputation, DNS, and TLS checks remain in their existing
    # explicit enrichment paths below.
    for url in dict.fromkeys(urls):
        try:
            url_report = analyze_url(url, run_intel=False)
        except ValueError:
            url_analysis.append({"url": url, "error": "invalid_url"})
            continue
        url_analysis.append({
            "url": url,
            "hostname": url_report["hostname"],
            "risk_level": url_report["risk_level"],
            "findings": [finding["check"] for finding in url_report["findings"]],
        })
        for url_finding in url_report["findings"]:
            add_finding(
                url_finding["check"],
                url_finding.get("message", url_finding.get("finding", "URL finding")),
                url_finding.get("weight", 0),
                url_finding.get("confidence", "low"),
                {"url": url, **url_finding.get("evidence", {})},
                url_finding.get("false_positive_note", "Validate this URL finding independently."),
                url_finding.get("recommended_action", "Do not open the URL; validate the destination independently."),
            )

    for mismatch in _find_display_destination_mismatches(parsed.get("html_links", [])):
        add_finding(
            "display_destination_mismatch",
            (
                "Displayed link destination mismatch: "
                f"{mismatch['displayed_text']} points to {mismatch['href']}"
            ),
            35, "high", mismatch,
            "Legitimate security gateways and marketing platforms sometimes rewrite destinations.",
            "Do not open the link; verify the displayed and destination domains independently.",
        )

    # --- Attachments ---
    attachments: list[dict] = parsed.get("attachments", [])
    for att in attachments:
        for attachment_finding in _attachment_findings(att):
            add_finding(**attachment_finding)

    # --- External DNS validation ---
    dns_results: dict[str, Optional[dict]] = {"spf": None, "dmarc": None}
    sender_domain = _extract_domain(sender)
    if run_intel and sender_domain:
        dns_results["spf"] = validate_spf_dns(sender_domain)
        dns_results["dmarc"] = validate_dmarc_dns(sender_domain)
        if dns_results["spf"] and dns_results["spf"].get("status") == "not_found":
            add_finding(
                "spf_dns_missing",
                f"No SPF DNS record found for domain: {sender_domain}",
                10, "low", {"domain": sender_domain},
                "Some legitimate domains do not publish SPF.",
                "Confirm the sender domain and organizational mail policy.",
            )
        if dns_results["dmarc"] and dns_results["dmarc"].get("status") == "not_found":
            add_finding(
                "dmarc_dns_missing",
                f"No DMARC DNS record found for domain: {sender_domain}",
                10, "low", {"domain": sender_domain},
                "DMARC deployment is not universal.",
                "Confirm the sender domain and evaluate other authentication evidence.",
            )

    # --- Threat Intel enrichment ---
    intel_ips: list[dict] = []
    intel_urls: list[dict] = []
    if run_intel:
        print("[*] Running threat intel lookups (this may take a moment)...", file=sys.stderr)
        if parsed.get("ips"):
            if len(parsed["ips"]) > MAX_IP_ENRICHMENTS:
                add_finding(
                    "ip_enrichment_limited",
                    f"External enrichment limited to the first {MAX_IP_ENRICHMENTS} IP indicators.",
                    0, "high", {"total": len(parsed["ips"]), "limit": MAX_IP_ENRICHMENTS},
                    "This is an intentional safety limit, not a malicious indicator.",
                    "Review remaining indicators manually if organizational policy permits.",
                )
            intel_ips = check_ips(parsed["ips"][:MAX_IP_ENRICHMENTS])
            for r in intel_ips:
                if r.get("abuse_confidence_score", 0) >= 50:
                    add_finding(
                        "high_abuse_ip",
                        f"High-abuse IP detected: {r['ip']} (score: {r['abuse_confidence_score']}, {r.get('isp', '')})",
                        35, "medium", r,
                        "Shared hosting, VPNs, and relays can inherit reports from other users.",
                        "Correlate the IP with trusted mail headers and current threat intelligence.",
                    )
                elif r.get("abuse_confidence_score", 0) > 0:
                    add_finding(
                        "reported_ip",
                        f"Reported IP: {r['ip']} (AbuseIPDB score: {r['abuse_confidence_score']})",
                        15, "low", r,
                        "Low-confidence reports may be stale or relate to another tenant.",
                        "Correlate the IP with other message and infrastructure evidence.",
                    )
        if urls:
            if len(urls) > MAX_URL_ENRICHMENTS:
                add_finding(
                    "url_enrichment_limited",
                    f"External enrichment limited to the first {MAX_URL_ENRICHMENTS} URL indicators.",
                    0, "high", {"total": len(urls), "limit": MAX_URL_ENRICHMENTS},
                    "This is an intentional safety limit, not a malicious indicator.",
                    "Review remaining indicators manually if organizational policy permits.",
                )
            intel_urls = check_urls(
                urls[:MAX_URL_ENRICHMENTS],
                submit_unknown=submit_unknown_urls,
            )
            for r in intel_urls:
                if r.get("malicious", 0) > 0:
                    add_finding(
                        "malicious_url_reputation",
                        f"Malicious URL detected by VirusTotal: {r.get('url', r.get('indicator', ''))} ({r['malicious']} engines)",
                        40, "high", r,
                        "Reputation results can be stale, disputed, or refer to previously hosted content.",
                        "Validate the current indicator through approved investigation procedures.",
                    )

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

    evidence_sufficient = any(
        parsed.get(field)
        for field in ("subject", "from", "to", "date", "body_text", "body_html", "urls", "attachments", "authentication_results")
    )
    disposition = disposition_for_findings(
        risk_level,
        findings,
        evidence_sufficient=evidence_sufficient,
    )
    return {
        "tool":        "PhishGuard",
        "schema_version": "1.0",
        "version":     __version__,
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "file":        os.path.basename(file_path),
        "risk_level":  risk_level,
        "disposition": disposition,
        "triage": _build_triage_summary(disposition, findings, evidence_sufficient),
        "risk_score":  score,
        "flags":       flags,
        "findings":    findings,
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
        "authentication_evidence": {**auth_evidence, "source_context": auth_source},
        "dns_validation": dns_results,
        "iocs": {
            "urls":        parsed["urls"],
            "ips":         parsed["ips"],
            "attachments": parsed["attachments"],
            "html_links":   parsed.get("html_links", []),
        },
        "url_analysis": url_analysis,
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


def _build_triage_summary(
    disposition: str,
    findings: list[dict],
    evidence_sufficient: bool = True,
) -> dict:
    """Build a compact, consistent handoff summary for an L1 analyst."""
    priority = {
        "malicious_escalate": "P1",
        "suspicious_escalate": "P2",
        "insufficient_evidence": "P3",
        "likely_benign": "P4",
    }[disposition]
    confidence_order = {"low": 1, "medium": 2, "high": 3}
    confidence = max(
        (finding.get("confidence", "low") for finding in findings),
        key=lambda value: confidence_order.get(value, 0),
        default="low",
    )
    actions = list(dict.fromkeys(
        finding.get("recommended_action", "Review the evidence.")
        for finding in findings
        if finding.get("recommended_action")
    ))
    reason = next(
        (finding.get("message", "") for finding in sorted(
            findings,
            key=lambda finding: (
                confidence_order.get(finding.get("confidence", "low"), 0),
                finding.get("score_contribution", 0),
            ),
            reverse=True,
        ) if finding.get("message")),
        "No strong detection evidence was recorded.",
    )
    return {
        "priority": priority,
        "confidence": confidence,
        "evidence_status": "sufficient" if evidence_sufficient else "insufficient",
        "escalation_reason": reason,
        "recommended_actions": actions[:5],
    }


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


def _interpret_authentication(parsed: dict, trusted: bool = False) -> dict:
    """Interpret authentication results and gate scoring on trusted provenance."""
    authentication_headers = parsed.get("authentication_results") or []
    closest_result = str(authentication_headers[0]) if authentication_headers else str(parsed.get("dmarc", ""))

    def result_for(mechanism: str) -> tuple[str, str]:
        match = re.search(
            rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)",
            closest_result,
            re.IGNORECASE,
        )
        if match:
            return match.group(1).lower(), "Authentication-Results"
        return "", ""

    spf_status, spf_source = result_for("spf")
    if not spf_status:
        received_spf = str(parsed.get("spf", "")).strip()
        match = re.match(
            r"(pass|fail|softfail|neutral|none|temperror|permerror)",
            received_spf,
            re.IGNORECASE,
        )
        if match:
            spf_status, spf_source = match.group(1).lower(), "Received-SPF"

    dkim_status, dkim_source = result_for("dkim")
    if not dkim_status:
        dkim_status = "present_unverified" if parsed.get("dkim") else "missing"
        dkim_source = "DKIM-Signature" if parsed.get("dkim") else ""

    dmarc_status, dmarc_source = result_for("dmarc")

    def evidence(status: str, source: str, meaning: str) -> dict:
        return {
            "status": status,
            "score_status": status if trusted else "untrusted",
            "source": source,
            "trusted": trusted,
            "meaning": meaning,
        }

    return {
        "spf": evidence(
            spf_status or "missing", spf_source,
            "Sender-policy evaluation recorded by the receiving system.",
        ),
        "dkim": evidence(
            dkim_status, dkim_source,
            (
                "present_unverified means a signature exists but PhishGuard did not "
                "cryptographically verify it."
            ),
        ),
        "dmarc": evidence(
            dmarc_status or "missing", dmarc_source,
            "Domain-alignment evaluation recorded by the receiving system.",
        ),
        "caution": (
            "Authentication-Results is trusted only when added by the analyst's "
            "known receiving infrastructure; PhishGuard cannot establish that trust boundary."
        ),
    }


def _normalized_comparison_domain(value: str) -> str:
    """Return a conservative domain key for visible-link comparisons."""
    candidate = value.strip().strip("<>()[]{}.,;:'\"")
    if not candidate or any(character.isspace() for character in candidate):
        return ""
    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?", candidate, re.IGNORECASE):
            return ""
        candidate = "http://" + candidate
    try:
        hostname = (urlparse(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return registrable_domain(hostname)


def _find_display_destination_mismatches(html_links: list[dict]) -> list[dict]:
    """Find anchors whose URL-like visible domain differs from the destination."""
    mismatches: list[dict] = []
    for link in html_links:
        displayed_text = str(link.get("displayed_text", "")).strip()
        href = str(link.get("href", "")).strip()
        displayed_domain = _normalized_comparison_domain(displayed_text)
        destination_domain = _normalized_comparison_domain(href)
        if displayed_domain and destination_domain and displayed_domain != destination_domain:
            mismatches.append({
                "displayed_text": displayed_text,
                "href": href,
                "displayed_domain": displayed_domain,
                "destination_domain": destination_domain,
            })
    return mismatches


_RISKY_ATTACHMENT_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".docm", ".exe", ".hta", ".img", ".iso",
    ".jar", ".js", ".lnk", ".msi", ".ps1", ".rar", ".scr", ".vbs",
    ".xlsm", ".zip", ".7z",
}
_BIDI_FILENAME_CHARACTERS = {"\u202a", "\u202b", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
_EXECUTABLE_CONTENT_TYPES = {
    "application/x-dosexec", "application/x-msdownload",
    "application/x-msdos-program", "application/x-executable",
}


def _attachment_findings(attachment: dict) -> list[dict]:
    """Return explainable filename and content-type findings for an attachment."""
    filename = str(attachment.get("filename", ""))
    lowered = filename.lower().rstrip(" .")
    content_type = str(attachment.get("content_type", "")).lower()
    findings: list[dict] = []

    final_extension = os.path.splitext(lowered)[1]
    if final_extension in _RISKY_ATTACHMENT_EXTENSIONS:
        findings.append({
            "finding_id": "risky_attachment_extension",
            "message": f"Risky attachment: {filename}",
            "weight": 40,
            "confidence": "medium",
            "evidence": {"filename": filename, "extension": final_extension, "content_type": content_type},
            "false_positive_note": "Administrators and developers may legitimately exchange scripts or archives.",
            "recommended_action": "Do not open it directly; inspect it only in an approved attachment-analysis environment.",
        })

    filename_parts = lowered.split(".")
    if len(filename_parts) >= 3 and f".{filename_parts[-1]}" in _RISKY_ATTACHMENT_EXTENSIONS:
        findings.append({
            "finding_id": "double_extension_attachment",
            "message": f"Attachment uses a deceptive double extension: {filename}",
            "weight": 20,
            "confidence": "high",
            "evidence": {"filename": filename},
            "false_positive_note": "Versioned or generated filenames can contain several periods.",
            "recommended_action": "Verify the final extension and actual file type before handling the attachment.",
        })

    if any(character in filename for character in _BIDI_FILENAME_CHARACTERS):
        findings.append({
            "finding_id": "bidi_attachment_filename",
            "message": f"Attachment filename contains bidirectional text controls: {filename}",
            "weight": 25,
            "confidence": "high",
            "evidence": {"filename": filename},
            "false_positive_note": "Bidirectional controls can occur in legitimate right-to-left filenames.",
            "recommended_action": "Inspect the raw filename and actual file type in an approved environment.",
        })

    if content_type in _EXECUTABLE_CONTENT_TYPES and final_extension not in _RISKY_ATTACHMENT_EXTENSIONS:
        findings.append({
            "finding_id": "attachment_type_mismatch",
            "message": f"Attachment type does not match its filename: {filename} ({content_type})",
            "weight": 30,
            "confidence": "high",
            "evidence": {"filename": filename, "extension": final_extension, "content_type": content_type},
            "false_positive_note": "Some mail clients assign inaccurate generic MIME types.",
            "recommended_action": "Verify the file signature in an approved sandbox before opening it.",
        })

    return findings
