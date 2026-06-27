# PhishGuard

> A Python-based phishing email analyzer built for SOC analysts. Designed to automate Tier 1 email triage — extracting IOCs, validating authentication headers, enriching with live threat intel, and generating structured alert reports.

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![SOC](https://img.shields.io/badge/role-SOC%20Analyst-red) ![Version](https://img.shields.io/badge/version-0.2.0-orange)

---

## What It Does

Given a `.eml` file, PhishGuard will:

1. **Parse** all email headers — From, Reply-To, Received chain, Message-ID, X-Originating-IP
2. **Validate** SPF, DKIM, and DMARC authentication results from headers
3. **DNS Check** — live SPF and DMARC record lookups via `dnspython` to verify what the domain actually publishes
4. **Extract IOCs** — URLs, IPv4 addresses, and attachment metadata from the email body
5. **Threat Intel** — check extracted IPs against AbuseIPDB and URLs against VirusTotal
6. **Score risk** using a weighted flag system (SPF fail, DKIM missing, Reply-To mismatch, suspicious URLs, risky attachments, high-abuse IPs, malicious URLs)
7. **Output** a structured report in text, JSON, HTML, or CEF format

---

## Project Structure

```
PhishGuard/
├── main.py                      # Entry point (thin wrapper)
├── requirements.txt             # Dependencies
├── phishguard/
│   ├── __init__.py              # Package metadata
│   ├── analyzer.py              # Core analysis engine & risk scoring
│   ├── cli.py                   # CLI argument parsing & output formatting
│   ├── email_parser.py          # .eml parsing & IOC extraction
│   ├── dns_validator.py         # Live SPF & DMARC DNS lookups
│   ├── threat_intel.py          # AbuseIPDB & VirusTotal API integrations
│   └── report_generator.py      # HTML report & CEF log generation
└── samples/
    └── phishing_test.eml        # Sample phishing email for testing
```

---

## Installation

```bash
git clone https://github.com/gsimransingh/PhishGuard.git
cd PhishGuard
pip install -r requirements.txt
```

### API Keys (Optional)

Set these as environment variables to enable live threat intel lookups:

```bash
# Free tier: https://www.abuseipdb.com/api
export ABUSEIPDB_API_KEY="your_key_here"

# Free tier: https://www.virustotal.com/gui/join-us
export VIRUSTOTAL_API_KEY="your_key_here"
```

**Windows (PowerShell):**
```powershell
$env:ABUSEIPDB_API_KEY="your_key_here"
$env:VIRUSTOTAL_API_KEY="your_key_here"
```

Without keys, the tool runs fully in offline mode — no crashes, no errors.

---

## Usage

```bash
# Human-readable report (default)
python main.py -f samples/phishing_test.eml

# JSON output (SIEM-ready)
python main.py -f samples/phishing_test.eml -o json

# HTML report (save to file)
python main.py -f samples/phishing_test.eml -o html --html-out report.html

# CEF log (for SIEM ingestion)
python main.py -f samples/phishing_test.eml -o cef

# Offline mode (skip API calls)
python main.py -f samples/phishing_test.eml --no-intel
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-f`, `--file` | Path to the `.eml` file (required) |
| `-o`, `--output` | Output format: `text` (default), `json`, `html`, or `cef` |
| `--no-intel` | Skip AbuseIPDB / VirusTotal lookups (offline mode) |
| `--html-out` | File path to save HTML report (used with `-o html`) |
| `-v`, `--version` | Show version and exit |

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `text` | Human-readable terminal output for quick triage |
| `json` | SIEM integration, scripting, programmatic access |
| `html` | Shareable visual reports for stakeholders |
| `cef` | Common Event Format for SIEM ingestion (Splunk, QRadar, etc.) |

---

## Risk Scoring

PhishGuard calculates a risk score based on weighted flags:

| Check | Score |
|-------|-------|
| SPF fail / softfail | +30 |
| SPF header missing | +15 |
| DKIM signature missing | +20 |
| DMARC fail | +25 |
| DMARC result missing | +10 |
| No SPF DNS record for domain | +10 |
| No DMARC DNS record for domain | +10 |
| Reply-To mismatch | +20 |
| Suspicious URL keywords | +10 per URL (max 30) |
| Risky attachment extension | +40 |
| Reported IP (AbuseIPDB > 0) | +15 |
| High-abuse IP (AbuseIPDB >= 50) | +35 |
| Malicious URL (VirusTotal) | +40 |

| Score | Risk Level |
|-------|------------|
| 0–34 | LOW |
| 35–69 | MEDIUM |
| 70+ | HIGH |

---

## Sample Output

**Text:**
```
============================================================
  PhishGuard v0.2.0 - Analysis Report
  Risk Level : HIGH (score: 115)
============================================================
  Flags:
    [!] SPF check failed
    [!] DKIM signature missing
    [!] DMARC check failed
    [!] Reply-To mismatch: sender=billing@paypal.com, reply_to=collect-funds@evil-domain.ru
    [!] Suspicious URLs found: ['http://paypal-account-verify.login.evil-domain.ru/secure/update']
============================================================
```

**JSON:**
```json
{
  "tool": "PhishGuard",
  "version": "0.2.0",
  "risk_level": "HIGH",
  "risk_score": 115,
  "flags": [
    "SPF check failed",
    "DKIM signature missing",
    "DMARC check failed",
    "Reply-To mismatch: sender=billing@paypal.com, reply_to=collect-funds@evil-domain.ru",
    "Suspicious URLs found: ['http://paypal-account-verify.login.evil-domain.ru/secure/update']"
  ],
  "iocs": {
    "urls": ["http://paypal-account-verify.login.evil-domain.ru/secure/update"],
    "ips": ["185.220.101.47"],
    "attachments": []
  },
  "threat_intel": {
    "ip_checks": [{"ip": "185.220.101.47", "abuse_confidence_score": 98, "total_reports": 847, "is_tor": true}],
    "url_checks": [{"url": "http://paypal-account-verify.login.evil-domain.ru/secure/update", "malicious": 12, "suspicious": 3}]
  }
}
```

---

## Tech Stack

- **Python 3.8+** — `email`, `re`, `argparse`, `json`, `datetime`
- **requests** — AbuseIPDB & VirusTotal API calls
- **dnspython** — live SPF/DMARC DNS lookups
- **ipwhois** — IP geolocation/ASN (future use)

---

## Roadmap

- [x] `.eml` parsing — headers, body, URLs, IPs, attachments
- [x] SPF / DKIM / DMARC header validation
- [x] Live DNS SPF/DMARC record validation
- [x] Risk scoring engine with weighted flags
- [x] AbuseIPDB integration for IP reputation checks
- [x] VirusTotal integration for URL/domain checks
- [x] Offline mode (`--no-intel`)
- [x] JSON output (SIEM-ready)
- [x] HTML report output
- [x] CEF log output (SIEM ingestion)
- [x] Clean package architecture (`analyzer.py` as core engine)
- [x] Full type hints across all modules
- [ ] Batch analysis (analyze a folder of `.eml` files)
- [ ] Async DNS and threat intel lookups
- [ ] Export alerts to CSV
- [ ] Machine learning assisted scoring
- [ ] Browser extension
- [ ] REST API / web interface

---

## Disclaimer

This tool is intended for **educational and defensive security purposes only**. Use it to analyze emails you own or have explicit permission to analyze.

---

*Built as part of a SOC analyst portfolio project by Gursimran Singh.*