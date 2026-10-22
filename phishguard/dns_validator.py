from typing import Optional
import dns.resolver

from phishguard.url_analyzer import registrable_domain

# ---------------------------------------------------------------------------
# DNS Validator - Live SPF and DMARC Record Lookup
# Uses dnspython to query DNS TXT records in real time.
# This goes beyond just reading email headers — it verifies what the
# domain's DNS actually publishes, which headers can lie or be absent.
# ---------------------------------------------------------------------------


def validate_spf_dns(domain: str) -> dict[str, Optional[str]]:
    """
    Look up the SPF TXT record for a given domain via live DNS query.
    Returns a dict with status and the raw SPF record string.

    Possible statuses:
      - 'found'     : SPF record exists
      - 'not_found' : No SPF TXT record published
      - 'error'     : DNS query failed
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode('utf-8', errors='ignore')
                if decoded.startswith('v=spf1'):
                    return {
                        "domain": domain,
                        "status": "found",
                        "record": decoded,
                        "error": None,
                    }
        return {
            "domain": domain,
            "status": "not_found",
            "record": "",
            "error": "No SPF TXT record found",
        }
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "status": "not_found", "record": "", "error": "Domain does not exist"}
    except dns.resolver.NoAnswer:
        return {"domain": domain, "status": "not_found", "record": "", "error": "No TXT records returned"}
    except dns.resolver.Timeout:
        return {"domain": domain, "status": "error", "record": "", "error": "DNS query timed out"}
    except Exception as e:
        return {"domain": domain, "status": "error", "record": "", "error": str(e)}


def validate_dmarc_dns(domain: str) -> dict[str, Optional[str]]:
    """
    Look up the DMARC policy that applies to a sender domain.

    Per RFC 7489 section 6.6.3, query _dmarc.<domain> first; if no DMARC record
    exists there, fall back to _dmarc.<organizational domain> (the registrable
    domain). Without the fallback, mail from mail.example.com is wrongly
    reported as having no DMARC when example.com publishes a policy.

    Possible statuses:
      - 'found'     : a DMARC record applies (see 'inherited_from_organizational_domain')
      - 'not_found' : no DMARC record at the domain or its organizational domain
      - 'error'     : a DNS query failed (timeout etc.); NOT treated as 'not_found'
    """
    result = _lookup_dmarc(domain, domain)
    if result["status"] == "not_found":
        org_domain = registrable_domain(domain)
        if org_domain and org_domain != domain:
            fallback = _lookup_dmarc(domain, org_domain)
            if fallback["status"] in ("found", "error"):
                return fallback
    return result


def _lookup_dmarc(domain: str, lookup_domain: str) -> dict[str, Optional[str]]:
    """Query _dmarc.<lookup_domain> and describe the result for <domain>."""
    dmarc_domain = f"_dmarc.{lookup_domain}"
    inherited = lookup_domain != domain
    base = {
        "domain": domain,
        "dmarc_domain": dmarc_domain,
        "inherited_from_organizational_domain": inherited,
    }
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode('utf-8', errors='ignore')
                if decoded.startswith('v=DMARC1'):
                    return {**base, "status": "found", "record": decoded,
                            "policy": _parse_dmarc_policy(decoded), "error": None}
        return {**base, "status": "not_found", "record": "", "policy": None,
                "error": "No DMARC record found"}
    except dns.resolver.NXDOMAIN:
        return {**base, "status": "not_found", "record": "", "policy": None,
                "error": "DMARC subdomain does not exist"}
    except dns.resolver.NoAnswer:
        return {**base, "status": "not_found", "record": "", "policy": None,
                "error": "No TXT records for _dmarc subdomain"}
    except dns.resolver.Timeout:
        return {**base, "status": "error", "record": "", "policy": None,
                "error": "DNS query timed out"}
    except Exception as e:
        return {**base, "status": "error", "record": "", "policy": None, "error": str(e)}


def _parse_dmarc_policy(record: str) -> dict[str, str]:
    """
    Parse key DMARC tags from a raw DMARC TXT record string.
    Extracts: p (policy), sp (subdomain policy), rua (report URI), pct (percentage).
    """
    tags: dict[str, str] = {}
    for part in record.split(';'):
        part = part.strip()
        if '=' in part:
            key, _, value = part.partition('=')
            tags[key.strip()] = value.strip()
    policy = tags.get("p", "none")
    return {
        "policy":           policy,
        # RFC 7489 section 6.3: when sp is absent, subdomains use p.
        "subdomain_policy": tags.get("sp", policy),
        "report_uri":       tags.get("rua", ""),
        "pct":              tags.get("pct", "100"),
    }
