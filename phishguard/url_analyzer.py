"""
PhishGuard URL & Domain Analyzer
=================================
Phase 1 module. Analyzes a single URL or bare domain, independent of any
email context, so it can be used standalone (CLI -u flag) or called from
the email analyzer against URLs pulled out of a message body.

Design philosophy
------------------
Every check below returns its own finding, weight, confidence, and a note on
where it can be wrong. A tool that just says "85% phishing" with no evidence
isn't something a SOC analyst can act on or defend to someone else. Each
check is a pure function with no side effects, except the domain-age RDAP
lookup, which is the one check that touches the network and is skipped
entirely when run_intel=False (the -n/--no-intel convention used everywhere
else in this tool).

Checks implemented
-------------------
1. URL structure      - IP-as-host, '@' tricks, excessive subdomains,
                         suspicious TLD, non-standard port
2. Punycode/homograph - xn-- prefix detection
3. Typosquatting / combosquatting - edit distance + substring match against
                         a configurable brand list (phishguard/data/known_brands.json)
4. Domain age (RDAP)  - network call, gated behind run_intel

Known limitations (read before trusting the score)
----------------------------------------------------
- Registrable-domain extraction is a naive "last two labels" split. It will
  mis-parse multi-part public suffixes like .co.uk or .com.au (it will treat
  "co.uk" as the registrable domain of "example.co.uk"). A future version
  should use a public-suffix-list library (e.g. tldextract) instead. This is
  a known source of false positives/negatives on ccTLD domains.
- Domain age comes from a public RDAP proxy and can be missing entirely due
  to GDPR privacy redaction or inconsistent registry support. Missing age
  data is NOT itself a red flag, it's scored as "no signal", not suspicious.
- The typosquat/combosquat check only knows about brands listed in
  known_brands.json. It is a curated list, not an exhaustive one.
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_BRANDS_PATH = os.path.join(_DATA_DIR, "known_brands.json")

# TLDs seen disproportionately often in phishing/spam campaigns. This is a
# weak, low-weight signal on its own — plenty of legitimate sites use them too.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "country", "kim", "loan",
}

RDAP_URL = "https://rdap.org/domain/{domain}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_known_brands() -> list:
    """Load the brand list from data/known_brands.json, with a small built-in
    fallback so the tool still functions if the config file is missing or
    corrupted (fail-safe, not fail-silent — this is worth noticing in a review
    but shouldn't crash a scan)."""
    try:
        with open(_BRANDS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [b.lower() for b in data.get("brands", [])]
    except (FileNotFoundError, json.JSONDecodeError):
        return ["paypal", "amazon", "microsoft", "google", "apple", "netflix"]


def _levenshtein(a: str, b: str) -> int:
    """Classic edit distance. Brand list is small, so no external dependency
    (python-Levenshtein) is needed for this to be fast enough."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                prev[j] + 1,          # deletion
                curr[j - 1] + 1,      # insertion
                prev[j - 1] + cost,   # substitution
            )
        prev = curr
    return prev[-1]


def _registrable_domain(hostname: str) -> str:
    """Naive 'last two labels' extraction. See module docstring limitations."""
    labels = hostname.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname


# ---------------------------------------------------------------------------
# Check 1: URL structure
# ---------------------------------------------------------------------------

def check_url_structure(url: str) -> list:
    """
    Fast, no-network structural checks on the raw URL string.

    False positives: legitimate services occasionally use raw IPs (internal
    tools, some CDNs) and large orgs legitimately use deep subdomain chains
    (a.b.c.example.com). Each finding here is a moderate signal, not a verdict.

    False negatives: none of these catch a phishing site hosted on a
    perfectly ordinary-looking domain with zero structural tricks — that's
    what the typosquat and domain-age checks are for.
    """
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hostname):
        findings.append({
            "check": "ip_as_hostname",
            "finding": f"URL uses a raw IP address ({hostname}) instead of a domain name",
            "weight": 25,
            "confidence": "medium",
            "false_positive_note": "Some legitimate internal tools and CDNs use bare IPs.",
        })

    if "@" in (parsed.netloc or ""):
        findings.append({
            "check": "at_symbol_trick",
            "finding": "URL contains an '@' before the host — a classic trick to disguise the real destination",
            "weight": 30,
            "confidence": "high",
            "false_positive_note": "Rare in legitimate URLs; almost always intentional obfuscation.",
        })

    if hostname:
        depth = hostname.count(".")
        if depth >= 4:
            findings.append({
                "check": "excessive_subdomains",
                "finding": f"Hostname has {depth} subdomain levels ({hostname}), often used to bury the real domain",
                "weight": 15,
                "confidence": "low",
                "false_positive_note": "Large orgs legitimately use deep subdomains (e.g. mail.corp.eu.example.com).",
            })

    tld = hostname.split(".")[-1].lower() if hostname else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "check": "suspicious_tld",
            "finding": f"Domain uses a TLD ('.{tld}') that is heavily abused for phishing/spam",
            "weight": 15,
            "confidence": "low",
            "false_positive_note": "Plenty of legitimate sites use these TLDs too; weak signal alone.",
        })

    if parsed.port and parsed.port not in (80, 443):
        findings.append({
            "check": "nonstandard_port",
            "finding": f"URL specifies a non-standard port ({parsed.port})",
            "weight": 10,
            "confidence": "low",
            "false_positive_note": "Common for dev/test environments and some legitimate internal apps.",
        })

    return findings


# ---------------------------------------------------------------------------
# Check 2: Punycode / homograph
# ---------------------------------------------------------------------------

def check_punycode_homograph(hostname: str) -> list:
    """
    Detect punycode-encoded labels (xn--), often used to render lookalike
    Unicode characters (Cyrillic 'а' instead of Latin 'a', etc).

    False positives: legitimate internationalized domain names (IDNs) for
    non-English businesses trigger this too — punycode isn't inherently
    malicious, it's worth a human glance, not an automatic block.

    False negatives: does not catch homograph attacks using already-registered
    lookalike ASCII domains (e.g. "rnicrosoft.com" using 'rn' to mimic 'm') —
    that pattern is covered by the typosquat check instead.
    """
    findings = []
    if "xn--" in hostname.lower():
        findings.append({
            "check": "punycode_domain",
            "finding": f"Domain contains punycode-encoded label(s) ({hostname}), which can render as lookalike Unicode characters",
            "weight": 20,
            "confidence": "medium",
            "false_positive_note": "Legitimate non-English domains use punycode too; not malicious by itself.",
        })
    return findings


# ---------------------------------------------------------------------------
# Check 3: Typosquatting / combosquatting
# ---------------------------------------------------------------------------

def check_typosquatting(hostname: str, brands: Optional[list] = None) -> list:
    """
    Two related checks against a configurable brand list
    (phishguard/data/known_brands.json):

    1. Typosquat   - registrable domain is within edit-distance 1-2 of a
                     known brand but isn't the real thing (paypa1.com).
    2. Combosquat  - the brand name appears somewhere in the hostname, but
                     the registrable domain isn't the brand's real domain
                     (paypal-secure-login.net, paypal.verify-account.ru).

    False positives: legitimate resellers, fan sites, or review sites can
    reference brand names in subdomains (paypal.reviews.example.com).

    False negatives: only catches brands present in known_brands.json —
    anything not on that list is invisible to this check. This is a curated
    list, not an exhaustive one, and needs upkeep as new targeted brands emerge.
    """
    if brands is None:
        brands = _load_known_brands()

    findings = []
    registrable = _registrable_domain(hostname)
    main_label = registrable.split(".")[0].lower() if registrable else ""

    for brand in brands:
        if not main_label or main_label == brand:
            continue  # empty, or it IS the real brand domain — nothing to flag

        distance = _levenshtein(main_label, brand)
        if 0 < distance <= 2 and len(brand) > 3:
            findings.append({
                "check": "typosquatting",
                "finding": f"Domain label '{main_label}' is very close to known brand '{brand}' (edit distance {distance})",
                "weight": 35,
                "confidence": "high" if distance == 1 else "medium",
                "false_positive_note": "Short brand names risk false matches; distance > 2 is intentionally excluded to limit noise.",
            })
            break  # one typosquat match is enough signal, avoid stacking noise

        if brand in hostname.lower() and main_label != brand and not registrable.lower().startswith(f"{brand}."):
            findings.append({
                "check": "combosquatting",
                "finding": f"Brand name '{brand}' appears in hostname '{hostname}' but is not the registrable domain",
                "weight": 30,
                "confidence": "medium",
                "false_positive_note": "Legitimate brand-related subdomains on third-party sites can trigger this.",
            })
            break

    return findings


# ---------------------------------------------------------------------------
# Check 4: Domain age (RDAP) — the only network call in this module
# ---------------------------------------------------------------------------

def check_domain_age(hostname: str, timeout: int = 8) -> dict:
    """
    Live RDAP lookup for domain registration date.

    False positives: essentially none — if RDAP reports an age, it's accurate.

    False negatives / blind spots: many registrars redact creation dates
    behind GDPR privacy proxies, and RDAP coverage varies by TLD/registry, so
    a "no data" result is common. This must NOT be treated as suspicious on
    its own — it means this check contributes nothing, not that something's
    wrong. A brand-new domain is also not inherently malicious (new legitimate
    businesses register domains too), so age alone should never carry a
    high weight — it's a supporting signal, not a verdict.
    """
    registrable = _registrable_domain(hostname)
    try:
        resp = requests.get(RDAP_URL.format(domain=registrable), timeout=timeout)
        if resp.status_code != 200:
            return {
                "domain": registrable, "status": "unavailable",
                "created": None, "age_days": None,
                "error": f"RDAP returned HTTP {resp.status_code}",
            }

        data = resp.json()
        created = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created = event.get("eventDate")
                break

        if not created:
            return {
                "domain": registrable, "status": "no_data",
                "created": None, "age_days": None,
                "error": "No registration date in RDAP response (often GDPR-redacted)",
            }

        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created_dt).days
        return {
            "domain": registrable, "status": "found",
            "created": created, "age_days": age_days, "error": None,
        }

    except requests.RequestException as e:
        return {
            "domain": registrable, "status": "error",
            "created": None, "age_days": None, "error": str(e),
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze_url(url: str, run_intel: bool = True) -> dict:
    """
    Analyze a single URL or bare domain and return a structured, explainable report.

    Args:
        url:       The URL or bare domain to analyze (e.g. "paypa1.com" or
                   "http://paypal-verify.evil.ru/login").
        run_intel: If True, performs the RDAP domain-age lookup (the one
                   network call). Same convention as --no-intel elsewhere
                   in PhishGuard — set False for offline/fast use.

    Returns:
        dict with risk_score, risk_level, every finding (each independently
        explainable), and the domain_age result if run_intel was True.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url  # allow bare domains like "example.com"

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    findings = []
    findings += check_url_structure(url)
    findings += check_punycode_homograph(hostname)
    findings += check_typosquatting(hostname)

    domain_age = None
    if run_intel and hostname:
        domain_age = check_domain_age(hostname)
        if domain_age["status"] == "found" and domain_age["age_days"] is not None and domain_age["age_days"] < 60:
            findings.append({
                "check": "young_domain",
                "finding": f"Domain was registered {domain_age['age_days']} day(s) ago",
                "weight": 20,
                "confidence": "medium",
                "false_positive_note": "New legitimate businesses/products also register recently; treat alongside other flags, not alone.",
            })

    score = sum(f["weight"] for f in findings)
    if score >= 70:
        risk_level = "HIGH"
    elif score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "tool": "PhishGuard",
        "url": url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings,
        "domain_age": domain_age,
    }
