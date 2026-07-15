# PhishGuard

> A Python CLI for helping SOC analysts triage suspicious email files. It extracts evidence, applies explainable risk signals, optionally enriches IOCs, and produces reports for analyst review.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-0.2.0-orange)

## Purpose

PhishGuard reduces repetitive Tier 1 email-triage work. It is not an automated blocking engine and must not replace analyst judgment.

It should help an analyst answer:

- What email, URL, IP, attachment, and authentication signals were found?
- Why does each signal matter?
- What evidence supports the assigned risk level?
- What should be investigated next?

## Current capabilities

Given an `.eml` file, PhishGuard can:

- Parse common email headers and the plain-text body
- Extract URLs, public IPv4 addresses, attachment metadata, and Received headers
- Read SPF, DKIM, and DMARC-related header results
- Look up SPF and DMARC DNS records
- Flag Reply-To mismatches, suspicious URL keywords, and risky attachment extensions
- Check IPs with AbuseIPDB and URLs with VirusTotal when API keys are available
- Produce text, JSON, HTML, CEF, batch-summary, and CSV output
- Analyze a standalone URL or domain for structural tricks, typosquatting, RDAP registration signals, and TLS-certificate signals

## Installation

**Supported Python:** Python 3.9 or newer.

```bash
git clone https://github.com/gsimransingh/PhishGuard.git
cd PhishGuard
python -m pip install -r requirements.txt
```

For development and testing:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Basic usage

```bash
# Analyze one email
python main.py -f samples/phishing_test.eml

# JSON for scripting or SIEM ingestion
python main.py -f samples/phishing_test.eml -o json

# HTML report
python main.py -f samples/phishing_test.eml -o html -O report.html

# CEF event
python main.py -f samples/phishing_test.eml -o cef

# Batch triage
python main.py -F samples/ -V

# Batch summary as CSV
python main.py -F samples/ --csv results.csv

# Analyze one URL or domain
python main.py -u paypa1-verify.com

# URL analysis without RDAP or TLS checks
python main.py -u http://evil.ru/login -n -o json
```

## Network and privacy behavior

PhishGuard can contact external services. Treat suspicious emails and IOCs as potentially sensitive data.

- Email analysis performs DNS SPF and DMARC lookups.
- With API keys configured, email analysis may send extracted IPs to AbuseIPDB and up to three URLs to VirusTotal.
- Standalone URL analysis can perform an RDAP lookup and a TLS connection to the target host.
- `--no-intel` skips AbuseIPDB and VirusTotal for email analysis. At present, email DNS validation still runs.
- `--no-intel` skips RDAP and TLS checks for standalone URL analysis.

PhishGuard does **not** execute attachments or fetch webpage content. Analysts should still use approved sandboxing and investigation procedures for malicious URLs and files.

### Optional API keys

```bash
export ABUSEIPDB_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
```

```powershell
$env:ABUSEIPDB_API_KEY="your_key_here"
$env:VIRUSTOTAL_API_KEY="your_key_here"
```

## Risk levels

| Score | Level | Meaning |
| --- | --- | --- |
| 0–34 | LOW | Few or no suspicious signals |
| 35–69 | MEDIUM | Suspicious signals that merit review |
| 70–149 | HIGH | Strong evidence requiring analyst action |
| 150+ | CRITICAL | Multiple strong signals, including corroborating evidence |

Scores are decision-support signals, not proof that a message is malicious. A valid TLS certificate, a clean reputation result, or the absence of flags must not be treated as proof that content is safe.

## Known limitations

- Email parsing currently focuses on plain-text content. HTML-only emails and displayed-link versus destination-link mismatches are not yet analyzed.
- DKIM signature presence is detected, but PhishGuard does not independently perform full DKIM cryptographic verification.
- DNS records show what a sender domain publishes; they do not independently prove a message passed authentication during delivery.
- Standalone URL findings are not yet integrated into email URL scoring.
- Registrable-domain extraction is currently a simple last-two-label approach and can be inaccurate for domains such as `example.co.uk`.
- Threat-intelligence coverage depends on API availability, rate limits, and configured keys.
- Reports should be reviewed before being shared externally.

## Triage-first roadmap

### 0.3 — Reliability, safety, and project baseline

- [ ] Make local development and testing reproducible
- [ ] Add automated CI for tests and quality checks
- [ ] Define supported Python versions in one place
- [ ] Make output handling safe for untrusted email content
- [ ] Make IOC ordering deterministic
- [ ] Clarify and standardize offline versus external-enrichment behavior
- [ ] Update documentation and remove stale references

### 0.4 — Stronger email evidence

- [ ] Extract URLs from HTML email bodies
- [ ] Detect display-text and link-destination mismatches
- [ ] Improve authentication-result interpretation
- [ ] Expand attachment metadata and risky-file heuristics
- [ ] Add representative benign, suspicious, and malicious test fixtures
- [ ] Improve explainability for each finding

### 0.5 — Unified URL and email analysis

- [ ] Use public-suffix-aware domain parsing
- [ ] Integrate URL structure and brand-impersonation findings into email triage
- [ ] Create one shared finding and scoring model
- [ ] Prevent duplicate findings and inflated scores
- [ ] Define safe limits for network enrichment during batch analysis

### 0.6 — Analyst workflow improvements

- [ ] Improve batch prioritization and analyst summaries
- [ ] Stabilize JSON and CEF schemas for downstream systems
- [ ] Add clear recommended next steps to reports
- [ ] Measure false positives and triage-time reduction with real test cases

### Deferred

These are not active implementation commitments until the triage core is reliable and validated:

- Browser extension
- Machine-learning scoring
- Public REST API
- Community reporting
- Enterprise dashboards and monitoring

## Project structure

```text
PhishGuard/
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
├── phishguard/
│   ├── analyzer.py
│   ├── cli.py
│   ├── dns_validator.py
│   ├── email_parser.py
│   ├── report_generator.py
│   ├── threat_intel.py
│   ├── url_analyzer.py
│   └── data/
├── samples/
└── tests/
```

## Disclaimer

PhishGuard is for authorized defensive-security analysis and education. Use it only with emails, URLs, systems, and data you are permitted to investigate.

## License

MIT
