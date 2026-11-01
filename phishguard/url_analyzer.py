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
entirely when run_intel=False. The CLI keeps this disabled by default and
requires explicit `--enrich` consent.

Checks implemented
-------------------
1. URL structure      - IP-as-host, '@' tricks, excessive subdomains,
                         suspicious TLD, non-standard port
2. Punycode/homograph - xn-- prefix detection
3. Typosquatting / combosquatting - edit distance + substring match against
                         a configurable brand list (phishguard/data/known_brands.json)
4. Domain registration  - RDAP lookup: age, registration period length, and
                         EPP status codes. Network call, gated behind run_intel.
                         Registrar name is captured for analyst context but
                         intentionally NOT scored (see check_domain_registration
                         docstring for why).
5. SSL/TLS certificate  - live TLS handshake against the host. Flags
                         verification failures (self-signed, expired, unknown
                         CA) and very recently issued certificates. Network
                         call, gated behind run_intel. A VALID certificate is
                         NOT a clean bill of health — see check_ssl_certificate
                         docstring for why.

Known limitations (read before trusting the score)
----------------------------------------------------
- Registrable-domain extraction uses tldextract's bundled public-suffix
  snapshot. It handles common multi-part suffixes, but the snapshot can age
  until the dependency is upgraded.
- TLS enrichment resolves a hostname once and refuses non-public results, but
  production deployments should still enforce outbound egress controls.
- Domain age comes from a public RDAP proxy and can be missing entirely due
  to GDPR privacy redaction or inconsistent registry support. Missing age
  data is NOT itself a red flag, it's scored as "no signal", not suspicious.
- The typosquat/combosquat check only knows about brands listed in
  known_brands.json. It is a curated list, not an exhaustive one.
"""

import json
import ipaddress
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

import requests
import tldextract
from phishguard.triage import disposition_for_findings

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_BRANDS_PATH = os.path.join(_DATA_DIR, "known_brands.json")

# TLDs seen disproportionately often in phishing/spam campaigns. This is a
# weak, low-weight signal on its own — plenty of legitimate sites use them too.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "country", "kim", "loan",
}

RDAP_URL = "https://rdap.org/domain/{domain}"
_PUBLIC_SUFFIX_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=False,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class InvalidURLError(ValueError):
    """Raised when standalone URL input cannot be analyzed safely."""


class EnrichmentTargetBlocked(ValueError):
    """Raised when enrichment would connect to a non-public target."""


def _parse_url_input(url: str):
    """Normalize and validate an HTTP(S) URL or bare hostname."""
    if not isinstance(url, str) or not url.strip():
        raise InvalidURLError("URL must include a hostname.")

    normalized = url.strip()
    explicit_scheme = re.match(r"^([a-z][a-z0-9+.-]*)://", normalized, re.IGNORECASE)
    if explicit_scheme and explicit_scheme.group(1).lower() not in ("http", "https"):
        raise InvalidURLError("Only HTTP and HTTPS URLs are supported.")
    if not explicit_scheme:
        normalized = "http://" + normalized

    try:
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as error:
        raise InvalidURLError(f"Malformed URL: {error}") from None

    if not hostname or any(character.isspace() for character in hostname):
        raise InvalidURLError("URL must include a valid hostname.")

    return normalized, parsed, hostname, port


# Fallback used only when data/known_brands.json is missing or corrupted.
# Deliberately small: a brand with no owned domains still gets checked, it just
# cannot be allowlisted, so the failure mode is extra noise, never a bypass.
_FALLBACK_BRANDS = {
    "paypal": frozenset({"paypal.com"}),
    "amazon": frozenset({"amazon.com", "amazonaws.com"}),
    "microsoft": frozenset({"microsoft.com", "microsoftonline.com"}),
    "google": frozenset({"google.com", "googleapis.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "netflix": frozenset({"netflix.com"}),
}


@lru_cache(maxsize=1)
def _load_known_brands() -> dict:
    """Load brand -> owned registrable domains from data/known_brands.json.

    Cached: the brand data is read once per URL checked, and a single message
    can carry 200 of them, with batch mode multiplying that by 100 files.
    Call ``_load_known_brands.cache_clear()`` if the file changes in-process.

    The file groups brands by owner, so every name in one entry shares that
    owner's domains: "outlook" is not impersonated by office365.com, because
    Microsoft owns both. Returns a flat {brand: frozenset(domains)} mapping.

    Falls back to a small built-in map if the config file is missing or
    corrupted (fail-safe, not fail-silent — worth noticing in a review but it
    shouldn't crash a scan).
    """
    try:
        with open(_BRANDS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        brands: dict = {}
        for group in data.get("brands", []):
            domains = frozenset(str(d).lower() for d in group.get("domains", []))
            for name in group.get("names", []):
                brands[str(name).lower()] = domains
        return brands or dict(_FALLBACK_BRANDS)
    except (FileNotFoundError, json.JSONDecodeError, AttributeError, TypeError):
        return dict(_FALLBACK_BRANDS)


def _normalize_brands(brands) -> dict:
    """Accept either a {brand: owned domains} mapping or a bare brand list.

    The bare-list form keeps call sites and tests that only care about the
    matching rules short; those brands simply have no owned domains, so no
    hostname is allowlisted for them.
    """
    if isinstance(brands, dict):
        return {
            str(brand).lower(): frozenset(str(d).lower() for d in domains)
            for brand, domains in brands.items()
        }
    return {str(brand).lower(): frozenset() for brand in brands}


def brand_owned_domains() -> dict:
    """Return {brand: frozenset(registrable domains that brand's owner owns)}.

    The public read-only view of known_brands.json, so the email analyzer can
    ask the same question about a From header that this module asks about a
    hostname, without either side keeping its own copy of the brand data.
    A copy, so a caller cannot mutate the cached brand data.
    """
    return dict(_load_known_brands())


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


def _is_ip_literal(hostname: str) -> bool:
    """Return whether a hostname is a literal IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def registrable_domain(hostname: str) -> str:
    """Return the registrable domain using the bundled public suffix snapshot.

    When the snapshot does not recognise the suffix — it is a point-in-time
    copy, so any TLD delegated after it was cut lands here — fall back to the
    last two labels instead of returning the whole hostname. Returning the
    whole hostname fails open in the attacker's favour: callers take the
    leftmost label as the registrable one, so "paypal.com.evil.<new-tld>"
    reads as the real PayPal and skips the brand checks entirely. The last
    two labels are the conservative guess, because they are the closest thing
    to a label somebody had to register.
    """
    extracted = _PUBLIC_SUFFIX_EXTRACT(hostname)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    lowered = hostname.lower().strip(".")
    if _is_ip_literal(lowered):
        return lowered  # "1.1" is not the registrable domain of 192.168.1.1

    labels = [label for label in lowered.split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname


def _is_allowed_ip_literal(hostname: str) -> bool:
    """Allow enrichment connections only to globally routable IP literals."""
    try:
        return ipaddress.ip_address(hostname).is_global
    except ValueError:
        return True


def _resolve_enrichment_address(hostname: str, port: int) -> str:
    """Resolve once and return a globally routable address for TLS enrichment."""
    if _is_ip_literal(hostname):
        if not _is_allowed_ip_literal(hostname):
            raise EnrichmentTargetBlocked(
                "TLS enrichment is blocked for non-public IP addresses"
            )
        return hostname

    addresses = {
        info[4][0]
        for info in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    }
    if not addresses:
        raise OSError("Hostname did not resolve to an address")
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise EnrichmentTargetBlocked(
            "TLS enrichment is blocked when a hostname resolves to a non-public address"
        )
    return sorted(addresses)[0]


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
    _, parsed, hostname, port = _parse_url_input(url)

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

    if port and port not in (80, 443):
        findings.append({
            "check": "nonstandard_port",
            "finding": f"URL specifies a non-standard port ({port})",
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

# A brand has to be at least this long before a match at the END of a longer
# label counts. "securepaypal" (6-char brand) is a combosquat; treating the
# tail of "purchase" as "chase" or of "pineapple" as "apple" is not.
_MIN_BRAND_LENGTH_FOR_SUFFIX_MATCH = 6

# Below this, edit distance says nothing: "abc" is 2 edits from "hsbc" and
# "ups" is 1 from "usps" purely because the words are short.
_MIN_LENGTH_FOR_EDIT_DISTANCE = 4
# Two edits only buy a match on a long brand, where "rnicrosoft" for
# "microsoft" needs them and ordinary words are not that close by accident.
_LENGTH_FOR_TWO_EDITS = 8


def _allowed_edit_distance(brand: str, label: str) -> int:
    """How many edits may separate a label from a brand before it is a squat.

    Scaled to the shorter of the two strings, because edit distance is only
    meaningful relative to length: 2 edits on a 4-character word is most of
    the word, while 2 edits on "microsoft" is a deliberate lookalike. Returns
    0 when the pair is too short for the check to mean anything.
    """
    shorter = min(len(brand), len(label))
    if shorter < _MIN_LENGTH_FOR_EDIT_DISTANCE:
        return 0
    return 1 if shorter < _LENGTH_FOR_TWO_EDITS else 2


def _label_carries_brand(label: str, brand: str) -> bool:
    """Whether one hostname label carries the brand at a word boundary.

    The brand must BE the label, start it ("paypal-secure", "paypalsecure"),
    or — only for brands long enough that an accidental word ending is
    implausible — end it ("securepaypal"). A brand buried inside a longer
    word is not a match; a naked substring test is what made "purchase" look
    like "chase" and "pineapple" look like "apple".
    """
    if label.startswith(brand):
        return True
    return len(brand) >= _MIN_BRAND_LENGTH_FOR_SUFFIX_MATCH and label.endswith(brand)


def _brand_comparison_labels(hostname: str, registrable: str) -> set:
    """Split a hostname into the word labels a brand is compared against.

    Splits on dots and on the separators attackers glue brand names together
    with ("secure-paypal-login" -> secure, paypal, login), and drops the
    public suffix so a brand-operated TLD such as ".apple" is not read as an
    impersonation of its own brand.
    """
    lowered = hostname.lower().strip(".")
    suffix = registrable.partition(".")[2]
    if suffix and lowered.endswith(f".{suffix}"):
        lowered = lowered[: -len(suffix) - 1]
    return {label for label in re.split(r"[^a-z0-9]+", lowered) if label}

def check_typosquatting(hostname: str, brands: Optional[list | dict] = None) -> list:
    """
    Two related checks against a configurable brand list
    (phishguard/data/known_brands.json):

    1. Typosquat   - registrable domain is within a length-scaled edit
                     distance of a known brand but isn't the real thing
                     (paypa1.com, rnicrosoft.com).
    2. Combosquat  - the brand name appears as a word inside the hostname,
                     but the registrable domain isn't one the brand owns
                     (paypal-secure-login.net, paypal.verify-account.ru).

    Both checks are skipped for a brand when the hostname's registrable
    domain is one that brand's owner operates. That mapping is the reason
    login.microsoftonline.com, s3.amazonaws.com, fonts.googleapis.com and
    steamcommunity.com are not reported: each legitimately begins with its
    own brand name. Suppression is per owner, not global, so a brand-operated
    hosting domain still catches another brand's name —
    paypal-login.s3.amazonaws.com is reported as a PayPal combosquat.

    False positives: legitimate resellers, fan sites, or review sites can
    reference brand names in subdomains (paypal.reviews.example.com). A brand
    domain missing from known_brands.json also reads as impersonation of
    itself, which is the usual cause of a surprising hit here.

    False negatives: only catches brands present in known_brands.json —
    anything not on that list is invisible to this check. This is a curated
    list, not an exhaustive one, and needs upkeep as new targeted brands
    emerge. A brand sitting in the middle of a longer word is not matched by
    design, and neither is a lookalike that both substitutes a character and
    adds words to the same label ("paypa1-secure-login.ru").
    """
    brand_domains = _normalize_brands(
        _load_known_brands() if brands is None else brands
    )

    findings = []
    registrable = registrable_domain(hostname).lower()
    main_label = registrable.split(".")[0] if registrable else ""
    comparison_labels = _brand_comparison_labels(hostname, registrable)

    for brand, owned_domains in brand_domains.items():
        if not main_label or main_label == brand:
            continue  # empty, or it IS the real brand domain — nothing to flag

        if registrable in owned_domains:
            continue  # a domain this brand's owner operates

        if len(brand) <= 3:
            # Short brand names (e.g. "att", "ups") are too generic even for
            # word-boundary matching — they'd match short ordinary labels and
            # flood the report with noise. Applies to both checks below.
            continue

        allowed_distance = _allowed_edit_distance(brand, main_label)
        distance = _levenshtein(main_label, brand)
        if allowed_distance and 0 < distance <= allowed_distance:
            findings.append({
                "check": "typosquatting",
                "finding": f"Domain label '{main_label}' is very close to known brand '{brand}' (edit distance {distance})",
                "weight": 35,
                "confidence": "high" if distance == 1 else "medium",
                "false_positive_note": "The tolerated edit distance scales with label length, so a short label that merely resembles a brand is not reported; a legitimate brand domain missing from known_brands.json can still produce a hit here.",
            })
            break  # one typosquat match is enough signal, avoid stacking noise

        if any(_label_carries_brand(label, brand) for label in comparison_labels):
            findings.append({
                "check": "combosquatting",
                "finding": f"Brand name '{brand}' appears in hostname '{hostname}' but is not a domain that brand owns",
                "weight": 30,
                "confidence": "medium",
                "false_positive_note": "Legitimate brand-related subdomains on third-party sites can trigger this, as can a brand-owned domain that is missing from known_brands.json.",
            })
            break

    return findings


# ---------------------------------------------------------------------------
# Check 4: Domain age (RDAP) — the only network call in this module
# ---------------------------------------------------------------------------

def check_domain_registration(hostname: str, timeout: int = 8) -> dict:
    """
    Live RDAP lookup for domain registration details: creation date,
    expiration date, registrar name, and EPP status codes. One network call,
    several signals extracted from it.

    Why not just "check if the registrar is legit": registrar identity alone
    is a bad signal. Namecheap, GoDaddy, NameSilo, Cloudflare Registrar, etc.
    host millions of completely legitimate domains and are popular with
    attackers for the same reason legitimate users like them (cheap, fast,
    no vetting friction). A hardcoded "sketchy registrar" list would flag
    huge swaths of the legitimate internet and make unsupportable claims
    about specific companies. Registrar name is returned here for an
    analyst's context, but intentionally NOT scored.

    What IS scored instead, using data from the same RDAP response:

    1. Short registration period + young age: phishing domains are almost
       always registered for the minimum period (1 year) since they're
       throwaway assets. A domain registered yesterday for 5 years is a
       much stronger "real business" signal than one registered yesterday
       for exactly 365 days. This is a supporting signal, combined with age,
       not scored alone.
    2. EPP status codes indicating the registrar itself has already taken
       action (clientHold, serverHold, pendingDelete, redemptionPeriod).
       This is a stronger signal than our own heuristics since it reflects
       an action the registrar took, not a guess we're making.

    False positives: a short registration period alone is common for
    legitimate new projects, side businesses, and personal sites too — most
    people don't pay for multi-year registration by default. Status-code
    holds can also result from billing disputes or transfer processes
    unrelated to abuse.

    False negatives / blind spots: many registrars redact creation/expiry
    dates behind GDPR privacy proxies, and RDAP coverage varies by
    TLD/registry, so "no data" is common and must NOT be treated as
    suspicious on its own.
    """
    registrable = registrable_domain(hostname)
    try:
        resp = requests.get(RDAP_URL.format(domain=registrable), timeout=timeout)
        if resp.status_code != 200:
            return {
                "domain": registrable, "status": "unavailable",
                "created": None, "expires": None, "age_days": None,
                "registration_period_days": None, "registrar": None,
                "domain_status": [], "error": f"RDAP returned HTTP {resp.status_code}",
            }

        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("RDAP response was not a JSON object")

        created = None
        expires = None
        for event in data.get("events", []):
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction")
            if action == "registration":
                created = event.get("eventDate")
            elif action == "expiration":
                expires = event.get("eventDate")

        registrar = None
        for entity in data.get("entities", []):
            if not isinstance(entity, dict):
                continue
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for field in vcard[1]:
                        if len(field) > 3 and field[0] == "fn":
                            registrar = field[3]
                            break
                break

        # RDAP comes from an external server: keep only string status codes
        # so a malformed reply degrades to "no status" instead of crashing.
        raw_status = data.get("status", [])
        domain_status = (
            [code for code in raw_status if isinstance(code, str)]
            if isinstance(raw_status, list) else []
        )

        if not created:
            return {
                "domain": registrable, "status": "no_data",
                "created": None, "expires": expires, "age_days": None,
                "registration_period_days": None, "registrar": registrar,
                "domain_status": domain_status,
                "error": "No registration date in RDAP response (often GDPR-redacted)",
            }

        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created_dt).days

        registration_period_days = None
        if expires:
            expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            registration_period_days = (expires_dt - created_dt).days

        return {
            "domain": registrable, "status": "found",
            "created": created, "expires": expires, "age_days": age_days,
            "registration_period_days": registration_period_days,
            "registrar": registrar, "domain_status": domain_status,
            "error": None,
        }

    except (requests.RequestException, ValueError, TypeError, KeyError, IndexError) as e:
        return {
            "domain": registrable, "status": "error",
            "created": None, "expires": None, "age_days": None,
            "registration_period_days": None, "registrar": None,
            "domain_status": [], "error": str(e),
        }


# EPP status codes indicating the registrar has already restricted a domain,
# typically due to abuse reports, disputes, or non-renewal. Note: some
# non-abuse-related reasons (billing, disputes) also produce these; this is a
# support signal, not a definitive verdict on its own.
_ABUSE_RELATED_STATUS_CODES = {
    "clienthold", "serverhold", "pendingdelete", "redemptionperiod",
}


# ---------------------------------------------------------------------------
# Check 5: SSL/TLS certificate inspection — the second network call in this module
# ---------------------------------------------------------------------------

def check_ssl_certificate(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    """
    Connect to the host on port 443 and inspect its TLS certificate chain.

    Unlike the RDAP check, this doesn't hit a JSON API — it does a real TLS
    handshake against the target. Two outcomes matter for phishing detection:

    1. Certificate fails verification (self-signed, expired, hostname
       mismatch, unknown CA). This uses Python's own ssl module error
       message rather than parsing certificate internals byte-by-byte,
       which would need an extra dependency (the `cryptography` library)
       for a level of detail this tool doesn't need — the failure reason
       string alone is informative enough for a SOC analyst.
    2. Certificate is valid but was issued very recently. Attackers often
       auto-provision a fresh Let's Encrypt cert right before launching a
       campaign, but so does every legitimate new site and every routine
       90-day cert renewal — so freshness alone is a weak signal, only
       meaningful when combined with the domain also being newly registered.

    False positives: legitimate internal tools, dev/staging environments,
    and some small businesses genuinely use self-signed or otherwise
    unverified certificates. A verification failure is suspicious, not proof.

    False negatives: a phishing site can absolutely have a perfectly valid,
    properly-issued certificate — HTTPS/a green padlock says nothing about
    trustworthiness, it only proves encryption in transit. This check will
    correctly find nothing wrong with a well-configured phishing site and
    that must not be read as a clean bill of health for the domain overall.

    Also: no certificate at all (plain HTTP, connection refused, timeout)
    is NOT scored as suspicious here. Plenty of legitimate low-traffic or
    internal sites still don't force HTTPS, and connection issues in this
    environment specifically (firewalls, blocked ports) are common and
    unrelated to the target's legitimacy.
    """
    if not _is_allowed_ip_literal(hostname):
        return {
            "hostname": hostname, "status": "blocked",
            "issuer": None, "not_before": None, "not_after": None,
            "days_since_issued": None,
            "error": "TLS enrichment is blocked for non-public IP addresses",
        }

    try:
        target_address = _resolve_enrichment_address(hostname, port)
        context = ssl.create_default_context()
        with socket.create_connection((target_address, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return _parse_verified_cert(hostname, cert)

    except EnrichmentTargetBlocked as e:
        return {
            "hostname": hostname, "status": "blocked",
            "issuer": None, "not_before": None, "not_after": None,
            "days_since_issued": None, "error": str(e),
        }
    except ssl.SSLCertVerificationError as e:
        return {
            "hostname": hostname, "status": "verification_failed",
            "issuer": None, "not_before": None, "not_after": None,
            "days_since_issued": None, "error": str(e),
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {
            "hostname": hostname, "status": "unavailable",
            "issuer": None, "not_before": None, "not_after": None,
            "days_since_issued": None, "error": str(e),
        }


def _parse_verified_cert(hostname: str, cert: dict) -> dict:
    """Extract issuer and issuance date from a successfully verified certificate."""
    issuer = None
    for rdn in cert.get("issuer", []):
        for key, value in rdn:
            if key == "organizationName":
                issuer = value
                break

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    days_since_issued = None
    if not_before:
        try:
            issued_ts = ssl.cert_time_to_seconds(not_before)
            issued_dt = datetime.fromtimestamp(issued_ts, tz=timezone.utc)
            days_since_issued = (datetime.now(timezone.utc) - issued_dt).days
        except (ValueError, OverflowError):
            pass  # unparseable date format — leave as None rather than guess

    return {
        "hostname": hostname, "status": "verified",
        "issuer": issuer, "not_before": not_before, "not_after": not_after,
        "days_since_issued": days_since_issued, "error": None,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze_url(url: str, run_intel: bool = False) -> dict:
    """
    Analyze a single URL or bare domain and return a structured, explainable report.

    Args:
        url:       The URL or bare domain to analyze (e.g. "paypa1.com" or
                   "http://paypal-verify.evil.ru/login").
        run_intel: If True, performs RDAP and TLS network checks. It defaults
                   to False so standalone analysis stays offline unless a
                   caller explicitly opts in.

    Returns:
        dict with risk_score, risk_level, every finding (each independently
        explainable), plus registration and TLS results when run_intel is True.
    """
    url, _, hostname, port = _parse_url_input(url)

    findings = []
    findings += check_url_structure(url)
    findings += check_punycode_homograph(hostname)
    findings += check_typosquatting(hostname)

    domain_registration = None
    if run_intel and hostname and not _is_ip_literal(hostname):
        domain_registration = check_domain_registration(hostname)

        if domain_registration["status"] == "found":
            age_days = domain_registration["age_days"]
            period_days = domain_registration["registration_period_days"]

            if age_days is not None and age_days < 60:
                findings.append({
                    "check": "young_domain",
                    "finding": f"Domain was registered {age_days} day(s) ago",
                    "weight": 20,
                    "confidence": "medium",
                    "false_positive_note": "New legitimate businesses/products also register recently; treat alongside other flags, not alone.",
                })

            if age_days is not None and age_days < 60 and period_days is not None and period_days <= 366:
                findings.append({
                    "check": "short_registration_period",
                    "finding": f"Domain is both new ({age_days} days old) and registered for only ~{period_days} days, the minimum period — a common pattern for throwaway phishing domains",
                    "weight": 15,
                    "confidence": "low",
                    "false_positive_note": "Most individuals and small legitimate projects also register for just 1 year by default; only meaningful combined with the domain also being brand-new.",
                })

            status_codes = {s.lower() for s in domain_registration.get("domain_status", [])}
            hit_codes = status_codes & _ABUSE_RELATED_STATUS_CODES
            if hit_codes:
                findings.append({
                    "check": "registrar_restriction",
                    "finding": f"Registrar has placed a restriction on this domain: {', '.join(sorted(hit_codes))}",
                    "weight": 25,
                    "confidence": "medium",
                    "false_positive_note": "Can also result from billing disputes, ownership transfers, or non-renewal — not always abuse-related.",
                })

    ssl_result = None
    if run_intel and hostname:
        ssl_result = check_ssl_certificate(hostname, port or 443)

        if ssl_result["status"] == "verification_failed":
            findings.append({
                "check": "invalid_ssl_certificate",
                "finding": f"TLS certificate failed verification: {ssl_result['error']}",
                "weight": 20,
                "confidence": "medium",
                "false_positive_note": "Internal tools, dev/staging environments, and some small legitimate sites use self-signed or unverified certificates too.",
            })

        if ssl_result["status"] == "verified" and ssl_result["days_since_issued"] is not None and ssl_result["days_since_issued"] <= 3:
            findings.append({
                "check": "freshly_issued_certificate",
                "finding": f"TLS certificate was issued {ssl_result['days_since_issued']} day(s) ago",
                "weight": 10,
                "confidence": "low",
                "false_positive_note": "New legitimate sites and routine 90-day cert renewals also produce fresh certificates; only meaningful alongside a newly-registered domain, not alone.",
            })

    finding_counts: dict[str, int] = {}
    normalized_findings = []
    score = 0
    for finding in findings:
        rule_id = finding["check"]
        finding_counts[rule_id] = finding_counts.get(rule_id, 0) + 1
        occurrence = finding_counts[rule_id]
        score_contribution = finding["weight"] if occurrence == 1 else 0
        score += score_contribution
        normalized_findings.append({
            **finding,
            "id": rule_id if occurrence == 1 else f"{rule_id}#{occurrence}",
            "score_contribution": score_contribution,
            "evidence_count": occurrence,
            "message": finding.get("message", finding["finding"]),
            "evidence": finding.get("evidence", {"check": rule_id}),
            "recommended_action": finding.get(
                "recommended_action", "Review the evidence and validate independently."
            ),
        })

    # Same 150 threshold and reasoning as analyzer.py — kept consistent
    # across both engines so "CRITICAL" means the same thing everywhere
    # in the tool, rather than each module inventing its own scale.
    if score >= 150:
        risk_level = "CRITICAL"
    elif score >= 70:
        risk_level = "HIGH"
    elif score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "tool": "PhishGuard",
        "schema_version": "1.0",
        "url": url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "disposition": disposition_for_findings(risk_level, normalized_findings),
        "findings": normalized_findings,
        "domain_registration": domain_registration,
        "ssl_certificate": ssl_result,
    }
