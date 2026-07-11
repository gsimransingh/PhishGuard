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

```text
PhishGuard/
├── main.py                      # Entry point (thin wrapper)
├── requirements.txt             # Dependencies
├── requirements-dev.txt         # Dev dependencies (pytest)
├── pytest.ini                   # Test discovery & sys.path config
├── phishguard/
│   ├── __init__.py              # Package metadata
│   ├── analyzer.py              # Core analysis engine & risk scoring
│   ├── cli.py                   # CLI argument parsing & output formatting
│   ├── email_parser.py          # .eml parsing & IOC extraction
│   ├── url_analyzer.py          # Standalone URL/domain analysis (Phase 1)
│   ├── dns_validator.py         # Live SPF & DMARC DNS lookups
│   ├── threat_intel.py          # AbuseIPDB & VirusTotal API integrations
│   ├── report_generator.py      # HTML report & CEF log generation
│   └── data/
│       └── known_brands.json    # Configurable brand list for typosquat detection
├── samples/
│   ├── phishing_test.eml        # Sample phishing email (PayPal spoof)
│   ├── phishing_amazon.eml      # Sample phishing email (Amazon spoof)
│   ├── suspicious_email.eml     # Sample borderline/suspicious email
│   └── legitimate_email.eml     # Sample clean email (for false-positive testing)
└── tests/
    ├── conftest.py              # Shared fixtures & network isolation
    ├── test_email_parser.py
    ├── test_url_analyzer.py
    └── test_analyzer.py
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
python main.py -f samples/phishing_test.eml -o html -O report.html

# CEF log (for SIEM ingestion)
python main.py -f samples/phishing_test.eml -o cef

# Offline mode (skip API calls)
python main.py -f samples/phishing_test.eml -n

# Batch analyze a folder of .eml files
python main.py -F samples/ -V

# Batch analyze and export a CSV summary
python main.py -F samples/ --csv results.csv

# Standalone URL/domain analysis — no .eml file needed
python main.py -u paypa1-verify.com

# Offline URL analysis, JSON output
python main.py -u http://evil.ru/login -n -o json
```

Standalone URL analysis (`-u`) checks structure (IP-as-hostname, `@` tricks, suspicious TLDs), punycode/homograph patterns, and typosquatting/combosquatting against a configurable brand list in `phishguard/data/known_brands.json`. With intel enabled (the default, skip with `-n`), it also does a live RDAP domain-age lookup. Every finding it returns comes with its own weight, confidence level, and a note on when that specific check can false-positive — check the report output (or `phishguard/url_analyzer.py`'s docstrings) rather than trusting the score blindly.

### CLI Options

| Flag | Description |
| ------ | ------------- |
| `-f`, `--file` | Path to a single `.eml` file (required unless `-F` or `-u` is used) |
| `-F`, `--folder` | Path to a folder of `.eml` files for batch analysis |
| `-u`, `--url` | A single URL or bare domain to analyze (no `.eml` file needed) |
| `-o`, `--output` | Output format: `text` (default), `json`, `html`, or `cef` |
| `-O`, `--save-output` | Save report to disk (single file: saves the report; batch: saves a summary) |
| `-n`, `--no-intel` | Skip AbuseIPDB / VirusTotal lookups (offline mode) |
| `-V`, `--verbose` | Batch mode only — print the full report per file instead of a one-line summary |
| `--csv` | Batch mode only — export results to a CSV file |
| `--version` | Show version and exit |

Batch mode (`-F`) is meant for triaging a folder of reported emails at once.

---

## Output Formats

| Format | Use Case |
| -------- | ---------- |
| `text` | Human-readable terminal output for quick triage |
| `json` | SIEM integration, scripting, programmatic access |
| `html` | Shareable visual reports for stakeholders |
| `cef` | Common Event Format for SIEM ingestion (Splunk, QRadar, etc.) |

---

## Risk Scoring

PhishGuard calculates a risk score based on weighted flags:

| Check | Score |
| ------- | ------- |
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
| ------- | ------------ |
| 0–34 | LOW |
| 35–69 | MEDIUM |
| 70+ | HIGH |

---

## Sample Output

**Text:**

```text
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

PhishGuard's long-term vision is a full anti-phishing ecosystem, not just an email tool. The original phase plan put URL/domain analysis first (Phase 1) and email analysis later (Phase 3). In practice, development started with email analysis since phishing most commonly arrives that way, and the auth-header, IOC extraction, and risk-scoring logic built for it are reusable for URL/domain analysis too. The phases below reflect actual status, not build order.

### Foundation (built first, functionality originally scoped as Phase 3)

- [x] `.eml` parsing — headers, body, URLs, IPs, attachments
- [x] SPF / DKIM / DMARC header validation
- [x] Live DNS SPF/DMARC record validation
- [x] Risk scoring engine with weighted, explainable flags
- [x] AbuseIPDB integration for IP reputation checks
- [x] VirusTotal integration for URL/domain checks
- [x] Offline mode (`-n` / `--no-intel`)
- [x] Text, JSON, HTML, and CEF report output
- [x] Batch analysis of a folder of `.eml` files (`-F`), with CSV export and verbose mode
- [x] Clean package architecture (`analyzer.py` as core engine, decoupled from CLI)
- [x] Full type hints across all modules
- [x] Automated test suite (pytest) — 76 tests across email_parser, url_analyzer, and analyzer, all network calls mocked

### Phase 1 — URL & domain analysis (in progress)

- [x] Standalone URL/domain input mode (`-u` / `--url`, no `.eml` required)
- [x] URL structure checks (IP-as-hostname, `@` tricks, excessive subdomains, non-standard port)
- [x] Suspicious TLD detection
- [x] Punycode/homograph detection (`xn--` prefix)
- [x] Typosquatting detection (edit distance against `known_brands.json`)
- [x] Combosquatting detection (brand substring in non-brand domain)
- [x] Domain age lookup via RDAP, gated behind `-n`/`--no-intel`
- [ ] SSL/TLS certificate inspection
- [ ] Public-suffix-aware domain parsing (current registrable-domain extraction is a naive last-two-labels split — see `url_analyzer.py` module docstring for the known false positive/negative it causes on ccTLDs like `.co.uk`)
- [ ] Wire URL findings into the email analyzer's scoring (currently `analyzer.py` only does a crude keyword match on URLs found in emails; the new structural/typosquat checks aren't used there yet)

### Phase 2 — Threat intelligence & heuristics

- [ ] Expanded reputation sources beyond AbuseIPDB/VirusTotal
- [ ] Advanced heuristics (redirect chain analysis, brand impersonation detection)
- [ ] Reporting improvements

### Phase 3 — ML, browser extension, API platform

- [x] Email analysis *(delivered early — see Foundation above)*
- [ ] Machine learning assisted scoring
- [ ] Browser extension
- [ ] REST API / web platform
- [ ] Async DNS and threat intel lookups

### Phase 4 — Community & enterprise

- [ ] Community phishing reporting
- [ ] Threat dashboards
- [ ] Real-time monitoring
- [ ] Enterprise features

---

## Disclaimer

This tool is intended for **educational and defensive security purposes only**. Use it to analyze emails you own or have explicit permission to analyze.

---

*Built as part of a SOC analyst portfolio project by me, Gursimran Singh.*
