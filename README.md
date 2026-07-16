# PhishGuard

> A Python CLI for helping SOC analysts triage suspicious email files. It extracts evidence, applies explainable risk signals, optionally enriches IOCs, and produces reports for analyst review.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

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

The supported Python versions and runtime dependencies are defined in
[`pyproject.toml`](pyproject.toml).

```bash
git clone https://github.com/gsimransingh/PhishGuard.git
cd PhishGuard
python -m pip install .
```

For development and testing:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Basic usage

```bash
# Analyze one email (the installed command)
phishguard -f samples/phishing_test.eml

# JSON for scripting or SIEM ingestion
phishguard -f samples/phishing_test.eml -o json

# HTML report
phishguard -f samples/phishing_test.eml -o html -O report.html

# CEF event
phishguard -f samples/phishing_test.eml -o cef

# Batch triage
phishguard -F samples/ -V

# Batch summary as CSV
phishguard -F samples/ --csv results.csv

# Analyze one URL or domain
phishguard -u paypa1-verify.com

# Explicitly permit external enrichment when appropriate
phishguard -f samples/phishing_test.eml --enrich
```

## Network and privacy behavior

PhishGuard treats suspicious emails and indicators as potentially sensitive data.
Analysis is offline by default: it does not contact any external service unless
you explicitly pass `--enrich`.

- With `--enrich`, email analysis can perform DNS SPF and DMARC lookups.
- With API keys configured, enrichment can send up to ten extracted IPs to AbuseIPDB and up to three URLs to VirusTotal.
- With `--enrich`, standalone URL analysis can perform an RDAP lookup and a TLS connection to the target host.
- Batch enrichment is limited to ten files to contain third-party requests and rate-limit exposure.

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

## Secure-core limits

Before parsing an untrusted message, PhishGuard enforces a 25 MiB file limit
and a 64 KiB header limit. It also rejects emails with more than 200 MIME
parts, one million extracted plain-text characters, 100 attachments, or 200
unique URLs. Batch processing is capped at 100 files and 250 MiB.

These limits are intentional safety boundaries, not indicators of phishing.
When a limit is exceeded, analysis stops with a clear error rather than
partially processing an unbounded message.

Reports escape untrusted HTML and CEF values. CSV exports neutralize cells
that spreadsheet applications could interpret as formulas. API keys are read
only from environment variables and are never written to reports.

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

- [x] Make local development and testing reproducible
- [x] Add automated CI for tests and quality checks
- [x] Define supported Python versions in one place
- [x] Make output handling safe for untrusted email content
- [x] Make IOC ordering deterministic
- [x] Clarify and standardize offline versus external-enrichment behavior
- [x] Update documentation and remove stale references

### 0.3.1 — Secure core

- [x] Keep analysis offline by default; require explicit enrichment consent
- [x] Enforce limits for hostile message and batch inputs
- [x] Protect HTML, CEF, CSV, and terminal output from untrusted content
- [x] Make network access impossible in ordinary tests
- [x] Add dependency auditing, static security checks, and update automation

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
- [x] Define safe limits for network enrichment during batch analysis

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
