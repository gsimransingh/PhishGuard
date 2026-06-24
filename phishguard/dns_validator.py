import dns.resolver

# ---------------------------------------------------------------------------
# DNS Validator - Live SPF and DMARC Record Lookup
# Uses dnspython to query DNS TXT records in real time.
# This goes beyond just reading email headers — it verifies what the
# domain's DNS actually publishes, which headers can lie or be absent.
# ---------------------------------------------------------------------------


def validate_spf_dns(domain: str) -> dict:
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


def validate_dmarc_dns(domain: str) -> dict:
    """
    Look up the DMARC TXT record for a domain by querying _dmarc.<domain>.
    Returns a dict with status and the raw DMARC policy record.

    Possible statuses:
      - 'found'     : DMARC record exists
      - 'not_found' : No DMARC record published (common in phishing domains)
      - 'error'     : DNS query failed
    """
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode('utf-8', errors='ignore')
                if decoded.startswith('v=DMARC1'):
                    policy = _parse_dmarc_policy(decoded)
                    return {
                        "domain": domain,
                        "dmarc_domain": dmarc_domain,
                        "status": "found",
                        "record": decoded,
                        "policy": policy,
                        "error": None,
                    }
        return {
            "domain": domain,
            "dmarc_domain": dmarc_domain,
            "status": "not_found",
            "record": "",
            "policy": None,
            "error": "No DMARC record found",
        }
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "dmarc_domain": dmarc_domain, "status": "not_found", "record": "", "policy": None, "error": "DMARC subdomain does not exist"}
    except dns.resolver.NoAnswer:
        return {"domain": domain, "dmarc_domain": dmarc_domain, "status": "not_found", "record": "", "policy": None, "error": "No TXT records for _dmarc subdomain"}
    except dns.resolver.Timeout:
        return {"domain": domain, "dmarc_domain": dmarc_domain, "status": "error", "record": "", "policy": None, "error": "DNS query timed out"}
    except Exception as e:
        return {"domain": domain, "dmarc_domain": dmarc_domain, "status": "error", "record": "", "policy": None, "error": str(e)}


def _parse_dmarc_policy(record: str) -> dict:
    """
    Parse key DMARC tags from a raw DMARC TXT record string.
    Extracts: p (policy), sp (subdomain policy), rua (report URI), pct (percentage).
    """
    tags = {}
    for part in record.split(';'):
        part = part.strip()
        if '=' in part:
            key, _, value = part.partition('=')
            tags[key.strip()] = value.strip()
    return {
        "policy":           tags.get("p", "none"),
        "subdomain_policy": tags.get("sp", "none"),
        "report_uri":       tags.get("rua", ""),
        "pct":              tags.get("pct", "100"),
    }
