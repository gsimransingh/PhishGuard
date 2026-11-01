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
from email.utils import getaddresses
from typing import Optional
from urllib.parse import urlparse

from phishguard.email_parser import EXECUTABLE_SIGNATURES, EXPECTED_SIGNATURES
from phishguard.threat_intel import check_ips, check_urls
from phishguard.dns_validator import validate_spf_dns, validate_dmarc_dns
from phishguard.url_analyzer import (
    analyze_url,
    brand_owned_domains,
    check_typosquatting,
    registrable_domain,
)
from phishguard.triage import disposition_for_findings
from phishguard import __version__
from phishguard.security import MAX_IP_ENRICHMENTS, MAX_URL_ENRICHMENTS


def analyze(
    parsed: dict,
    file_path: str,
    run_intel: bool = False,
    submit_unknown_urls: bool = False,
    auth_source: str = "unknown_capture",
    trusted_authserv_ids: tuple[str, ...] = (),
) -> dict:
    """
    Build a structured alert report from parsed email data.

    Args:
        parsed:     Output from email_parser.parse_eml()
        file_path:  Path to the original .eml file (used for display only)
        run_intel:  If True, perform external DNS and threat-intelligence
                    enrichment. Defaults to False for fully offline analysis.
        trusted_authserv_ids: Hostnames your own receiving servers write as the
                    authserv-id in Authentication-Results (e.g. "mx.example.com").
                    When given, a result counts as verified only if it came from
                    one of them (RFC 8601 section 5). This governs whether a
                    `pass` is believed; recorded failures score either way.

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
    auth_evidence = _interpret_authentication(
        parsed,
        trusted=auth_source == "trusted_gateway",
        trusted_authserv_ids=trusted_authserv_ids,
    )
    spf_status = auth_evidence["spf"]["score_status"]
    dkim_status = auth_evidence["dkim"]["score_status"]
    dmarc_status = auth_evidence["dmarc"]["score_status"]

    # A mailing list or resending relay breaks authentication as a side effect
    # of doing its job, so a failure on such a message is weaker evidence. The
    # finding stays visible either way; only its weight and confidence drop.
    #
    # This asks a different question from provenance, and the two must not be
    # conflated. Verifying *who wrote* the header (a matched authserv-id) tells
    # us the failure is real; it says nothing about whether a list caused it, so
    # it must not cancel the softening — doing so escalates legitimate list
    # traffic the moment an analyst configures their own servers. Only the
    # analyst explicitly vouching for the capture overrides it, because that is
    # a human saying "I know what this message is".
    relay_indicators = auth_evidence["spf"]["relay_context"]
    soften_auth = bool(relay_indicators) and auth_source != "trusted_gateway"

    def auth_weight(base: int) -> int:
        return base // 2 if soften_auth else base

    def auth_confidence(base: str) -> str:
        return "low" if soften_auth else base

    def auth_note(base: str) -> str:
        if not soften_auth:
            return base
        return (
            f"{base} This message carries {', '.join(relay_indicators)}, so the "
            "failure was scored at reduced weight."
        )

    if spf_status in _RECORDED_AUTH_FAILURES:
        add_finding(
            "spf_failure", "SPF check failed",
            auth_weight(30), auth_confidence("medium"),
            {"status": spf_status, "source": auth_evidence["spf"]["source"],
             "relay_context": relay_indicators},
            auth_note("Forwarding and mailing-list infrastructure can legitimately break SPF."),
            "Validate the trusted receiving server's Authentication-Results header and sender alignment.",
        )
    elif spf_status == "missing":
        add_finding(
            "spf_missing", "SPF header missing", 15, "low",
            {"status": spf_status},
            "Some receiving systems do not preserve SPF results.",
            "Check the message's trusted Authentication-Results header or perform approved DNS validation.",
        )

    if dkim_status in _RECORDED_AUTH_FAILURES:
        add_finding(
            "dkim_failure", "DKIM verification failed",
            auth_weight(25), auth_confidence("medium"),
            {"status": dkim_status, "source": auth_evidence["dkim"]["source"],
             "relay_context": relay_indicators},
            auth_note("Messages can be modified in transit by legitimate gateways or mailing lists."),
            "Validate the trusted receiver's DKIM result and signing-domain alignment.",
        )
    elif dkim_status == "missing":
        add_finding(
            "dkim_missing", "DKIM signature missing", 20, "low",
            {"status": dkim_status},
            "DKIM is not universally deployed and its absence is not proof of spoofing.",
            "Compare this absence with SPF, DMARC, sender history, and message content.",
        )

    if dmarc_status in _RECORDED_AUTH_FAILURES:
        add_finding(
            "dmarc_failure", "DMARC check failed",
            auth_weight(25), auth_confidence("high"),
            {"status": dmarc_status, "source": auth_evidence["dmarc"]["source"],
             "relay_context": relay_indicators},
            auth_note("Forwarding or receiver-specific evaluation can occasionally produce legitimate failures."),
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

    # --- Sender identity: lookalike From domain and brand-spoofed display name
    # The URL engine's brand checks were only ever pointed at links in the
    # body, so a message from a lookalike domain with no links at all scored
    # nothing. The From header is the identity the recipient is asked to
    # trust, so it gets its own check ids: an analyst reading the report has
    # to be able to tell a lookalike SENDER from a lookalike LINK.
    sender_domain = _extract_domain(sender)
    if sender_domain:
        for brand_finding in check_typosquatting(sender_domain):
            add_finding(
                _SENDER_BRAND_CHECK_IDS[brand_finding["check"]],
                f"Sender domain {sender_domain}: {brand_finding['finding']}",
                _SENDER_BRAND_WEIGHTS[brand_finding["check"]],
                brand_finding["confidence"],
                {"sender_domain": sender_domain, "from": sender},
                brand_finding["false_positive_note"],
                "Confirm the sending domain against the brand's published domains "
                "through a trusted channel before acting on the message.",
            )

    for spoof in _display_name_brand_spoofs(sender, sender_domain):
        add_finding(
            "display_name_brand_spoof",
            (
                f"From display name claims brand '{spoof['brand']}' but the message "
                f"was sent from {spoof['sender_domain']}, which that brand does not own"
            ),
            30, "medium", spoof,
            "Resellers, MSPs, internal IT, and email service providers legitimately "
            "send brand-named mail from their own domains; a brand domain missing "
            "from known_brands.json produces this finding too.",
            "Compare the display name with the sending domain and verify the "
            "relationship through a trusted channel.",
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
            0, "low",
            {"urls": sus_urls},
            "Legitimate authentication and account-management pages often contain these words; this signal is informational until corroborated.",
            "Inspect destination domains and compare them with the claimed sender. Escalate based on stronger corroborating evidence.",
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
        "authentication_evidence": {
            **auth_evidence,
            "source_context": (
                "trusted_authserv_id" if auth_evidence["matched_authserv_id"] else auth_source
            ),
        },
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


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)

# Brand findings about the From header get their own ids so a report never
# leaves an analyst guessing whether the lookalike was the sender or a link.
_SENDER_BRAND_CHECK_IDS = {
    "typosquatting": "sender_domain_typosquatting",
    "combosquatting": "sender_domain_combosquatting",
}
# Weighted a little above the URL equivalents (35/30): a link can be a
# tracking redirect, a quoted third-party URL, or something the sender never
# chose, while the From domain is the identity the message asserts for itself
# and is the one an attacker had to register.
_SENDER_BRAND_WEIGHTS = {"typosquatting": 40, "combosquatting": 35}

# Below 4 characters a brand name matches ordinary words in a display name
# ("ups", "att") far too readily to be worth scoring.
_MIN_DISPLAY_NAME_BRAND_LENGTH = 4


def _extract_domain(from_header: str) -> str:
    """
    Return the lowercased domain of the real sender address, or "".

    Uses the RFC 5322 address parser rather than a regex over the raw header:
    an attacker controls the display name, so '"billing@paypal.com"
    <attacker@evil.ru>' must resolve to evil.ru, not paypal.com. Several
    addresses in one header are ambiguous, so no domain is returned and the
    DNS checks are skipped rather than run against a guess.
    """
    addresses = [addr for _, addr in getaddresses([from_header]) if addr]
    if len(addresses) != 1 or "@" not in addresses[0]:
        return ""
    domain = addresses[0].rsplit("@", 1)[1].strip().lower().rstrip(".")
    return domain if _DOMAIN_RE.match(domain) else ""


def _extract_display_name(from_header: str) -> str:
    """Return the display name of the single sender address, or ""."""
    addresses = getaddresses([from_header])
    if len(addresses) != 1:
        return ""
    return addresses[0][0].strip()


def _display_name_brand_spoofs(from_header: str, sender_domain: str) -> list[dict]:
    """Find a brand named in the From display name that the sender does not own.

    '"PayPal Security" <attacker@evil.example>' is brand impersonation even
    though the domain is not a lookalike at all: mail clients show the display
    name, the attacker picks it freely, and nothing in the address has to
    match it. Needs a resolvable sender domain — with an ambiguous From header
    there is nothing to compare against, so the check is skipped rather than
    run against a guess.

    Returns at most one spoof: "Microsoft Outlook" names two brands with the
    same owner and is one piece of evidence, not two.
    """
    if not sender_domain:
        return []
    display_name = _extract_display_name(from_header)
    if not display_name:
        return []

    tokens = {token for token in re.split(r"[^a-z0-9]+", display_name.lower()) if token}
    registrable = registrable_domain(sender_domain).lower()
    main_label = registrable.split(".")[0]

    for brand, owned_domains in brand_owned_domains().items():
        if len(brand) < _MIN_DISPLAY_NAME_BRAND_LENGTH or brand not in tokens:
            continue
        if main_label == brand or registrable in owned_domains:
            continue  # the sender really is that brand
        return [{
            "brand": brand,
            "display_name": display_name,
            "sender_domain": sender_domain,
            "sender_registrable_domain": registrable,
        }]
    return []


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


# Results that represent a failure the receiving system actually recorded.
# These are scored whatever the provenance of the header, because the threat
# model is asymmetric: an attacker who forges an Authentication-Results header
# writes "pass" to evade a filter. Forging "dmarc=fail" against yourself has
# no attack value. So a recorded failure is self-authenticating evidence,
# while a recorded pass is only worth as much as the server that stamped it.
#
# "missing", "none", "neutral", "temperror" and "present_unverified" are
# deliberately NOT in this set: they describe absent or inconclusive
# evidence, which an attacker CAN manufacture simply by stripping a header.
_RECORDED_AUTH_FAILURES = frozenset({"fail", "softfail", "permerror"})

# RFC 2919 / RFC 2369 list headers and RFC 5322 resent headers. Their presence
# is structural evidence that an intermediary legitimately relayed — and likely
# modified — this message, which is the documented false-positive class for
# authentication failures: a mailing list that appends a footer invalidates the
# original DKIM signature and takes DMARC down with it.
_RELAY_CONTEXT_HEADERS = (
    "list_id", "list_post", "list_unsubscribe", "resent_from",
)


def _relay_context(parsed: dict) -> list[str]:
    """Return the relay indicators present, which soften auth-failure scoring."""
    return [name for name in _RELAY_CONTEXT_HEADERS if parsed.get(name)]


def _authserv_id(header_value: object) -> str:
    """Return the authserv-id of an Authentication-Results header.

    RFC 8601: the header starts with the authserv-id, optionally followed by a
    version number, then ';'. "mx.example.com 1; spf=pass" -> "mx.example.com".
    """
    head = str(header_value).split(";", 1)[0].strip()
    return head.split()[0].lower().rstrip(".") if head else ""


def _interpret_authentication(
    parsed: dict,
    trusted: bool = False,
    trusted_authserv_ids: tuple[str, ...] = (),
) -> dict:
    """Interpret authentication results and decide what may be scored.

    Scoring is allowed for a result when either its provenance is verified, or
    the result is a failure the receiver recorded — see
    ``_RECORDED_AUTH_FAILURES`` for why those two cases differ.

    Provenance is verified in one of two ways. ``--auth-source
    trusted_gateway`` is the analyst vouching for the whole capture. Naming
    receiving servers in ``trusted_authserv_ids`` is narrower and stronger:
    anyone can write an Authentication-Results header, so we look for the
    topmost one carrying an authserv-id we were told to expect. A gateway adds
    its header above whatever the sender supplied, so the topmost match is our
    own server's verdict and anything below it is hearsay.

    When ids are configured but none matches, nothing is verified — but the
    headers are still *read*, because a recorded failure is self-authenticating
    whoever wrote it. Forging ``dmarc=fail`` against yourself achieves nothing,
    so dropping those results would reintroduce a silent miss. Configuring ids
    therefore changes whether a ``pass`` is believed, never whether a failure
    is seen.
    """
    authentication_headers = [str(header) for header in (parsed.get("authentication_results") or [])]
    wanted_ids = {
        value.strip().lower().rstrip(".")
        for value in trusted_authserv_ids
        if value and value.strip()
    }
    matched_authserv_id = None
    if wanted_ids:
        own_headers = [header for header in authentication_headers if _authserv_id(header) in wanted_ids]
        if own_headers:
            # Our own server's verdict supersedes the blanket declaration and
            # anything the sender attached below it.
            trusted = True
            matched_authserv_id = _authserv_id(own_headers[0])
            authentication_headers = own_headers[:1]
        else:
            trusted = False

    closest_result = (
        authentication_headers[0] if authentication_headers else str(parsed.get("dmarc", ""))
    )

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

    relay_indicators = _relay_context(parsed)

    def evidence(status: str, source: str, meaning: str) -> dict:
        recorded_failure = status in _RECORDED_AUTH_FAILURES
        return {
            "status": status,
            "score_status": status if (trusted or recorded_failure) else "untrusted",
            "scored_because": (
                "verified_own_authserv_id" if matched_authserv_id
                else "analyst_declared_trusted_gateway" if trusted
                else "recorded_failure" if recorded_failure
                else "not_scored_unverified_provenance"
            ),
            "source": source,
            "trusted": trusted,
            "relay_context": relay_indicators,
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
        "trusted_authserv_ids": sorted(wanted_ids),
        "matched_authserv_id": matched_authserv_id,
        "scoring_mode": _authentication_scoring_mode(wanted_ids, matched_authserv_id, trusted),
        "caution": _authentication_caution(wanted_ids, matched_authserv_id, trusted),
    }


AUTH_SCORING_MODES = (
    "verified_authserv_id",     # a named receiving server stamped this header
    "authserv_id_no_match",     # ids configured, but none of them wrote a header here
    "trusted_gateway",          # blanket trust declared for the whole capture
    "failures_only",            # nothing configured: failures score, passes do not
)


def _authentication_scoring_mode(
    wanted_ids: set[str], matched: Optional[str], trusted: bool
) -> str:
    """Summarise in one stable token how much of SPF/DKIM/DMARC can be believed."""
    if matched:
        return "verified_authserv_id"
    if wanted_ids:
        return "authserv_id_no_match"
    return "trusted_gateway" if trusted else "failures_only"


def _authentication_caution(
    wanted_ids: set[str], matched: Optional[str], trusted: bool
) -> str:
    """Explain to the analyst exactly how far the authentication results were believed."""
    if matched:
        return (
            f"Scored from the Authentication-Results header written by {matched}, a "
            "receiving server you named. This relies on that server stripping inbound "
            "headers that claim its own authserv-id (RFC 8601 section 5)."
        )
    if wanted_ids:
        return (
            "No Authentication-Results header from a configured receiving server "
            f"({', '.join(sorted(wanted_ids))}) was found, so no 'pass' here is believed. "
            "Recorded failures are still scored, because forging a failure against "
            "oneself gains an attacker nothing. The message may not have passed through "
            "that server, or the capture may have dropped the header."
        )
    if trusted:
        return (
            "Authentication-Results was believed in full because the analyst declared "
            "the capture came from a trusted gateway (--auth-source trusted_gateway)."
        )
    return (
        "Recorded failures are scored, but no 'pass' is believed: anyone can write an "
        "Authentication-Results header claiming success. Name your receiving servers "
        "with --trusted-authserv-id (or PHISHGUARD_TRUSTED_AUTHSERV_IDS) to make a "
        "pass count for something."
    )


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
    # Script hosts and macro-enabled Office formats not covered above.
    ".wsf", ".wsh", ".vbe", ".jse", ".xlam", ".xla", ".xll",
    ".pptm", ".ppam", ".dotm", ".xltm",
}
# Formats that execute script or load content when opened but are also common
# in legitimate mail (saved receipts, exported diagrams), so they score lower.
_ACTIVE_CONTENT_EXTENSIONS = {".html", ".htm", ".shtml", ".svg", ".one", ".chm"}
_ALL_FLAGGED_EXTENSIONS = _RISKY_ATTACHMENT_EXTENSIONS | _ACTIVE_CONTENT_EXTENSIONS
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

    if final_extension in _ACTIVE_CONTENT_EXTENSIONS:
        findings.append({
            "finding_id": "active_content_attachment",
            "message": f"Attachment can run script or load remote content: {filename}",
            "weight": 25,
            "confidence": "medium",
            "evidence": {"filename": filename, "extension": final_extension, "content_type": content_type},
            "false_positive_note": "Saved web pages, receipts, SVG images and OneNote files are often legitimate.",
            "recommended_action": "Do not open it in a normal browser or Office app; inspect it in an approved sandbox.",
        })

    filename_parts = lowered.split(".")
    if len(filename_parts) >= 3 and f".{filename_parts[-1]}" in _ALL_FLAGGED_EXTENSIONS:
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

    detected_type = str(attachment.get("detected_type", ""))
    declared_executable = content_type in _EXECUTABLE_CONTENT_TYPES
    # Bytes beat both the filename and the Content-Type header, either of which
    # the sender chose. An MZ header behind "invoice.pdf" is the whole point.
    detected_executable = (
        detected_type in EXECUTABLE_SIGNATURES
        and final_extension not in _RISKY_ATTACHMENT_EXTENSIONS
    )

    if (declared_executable or detected_executable) and final_extension not in _ALL_FLAGGED_EXTENSIONS:
        if detected_executable:
            message = (
                f"Attachment contents are executable, not the file type its name "
                f"claims: {filename} (detected {detected_type}, declared {content_type})"
            )
            note = (
                "A truncated or unusual file can begin with these bytes by "
                "coincidence; confirm the full file signature in a sandbox."
            )
        else:
            message = f"Attachment type does not match its filename: {filename} ({content_type})"
            note = "Some mail clients assign inaccurate generic MIME types."
        findings.append({
            "finding_id": "attachment_type_mismatch",
            "message": message,
            "weight": 30,
            "confidence": "high",
            "evidence": {
                "filename": filename, "extension": final_extension,
                "content_type": content_type, "detected_type": detected_type,
                "sha256": attachment.get("sha256", ""),
            },
            "false_positive_note": note,
            "recommended_action": "Verify the file signature in an approved sandbox before opening it.",
        })
    elif (
        detected_type
        and final_extension in EXPECTED_SIGNATURES
        and detected_type not in EXPECTED_SIGNATURES[final_extension]
    ):
        # Not executable, but still not what it claims to be — a container
        # swap, or an archive wearing a document name.
        findings.append({
            "finding_id": "attachment_signature_mismatch",
            "message": (
                f"Attachment contents do not match its extension: {filename} "
                f"(detected {detected_type}, expected "
                f"{'/'.join(sorted(EXPECTED_SIGNATURES[final_extension]))})"
            ),
            "weight": 15,
            "confidence": "medium",
            "evidence": {
                "filename": filename, "extension": final_extension,
                "detected_type": detected_type, "sha256": attachment.get("sha256", ""),
            },
            "false_positive_note": (
                "Renamed exports and some generated files legitimately carry a "
                "mismatched extension without being malicious."
            ),
            "recommended_action": "Confirm the real file type before opening the attachment.",
        })

    return findings
