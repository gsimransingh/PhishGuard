# PhishGuard

> A Python CLI for helping SOC analysts triage suspicious email files. It extracts evidence, applies explainable risk signals, optionally enriches IOCs, and produces reports for analyst review.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
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

- Parse common email headers plus plain-text and HTML bodies without rendering them
- Extract HTTP(S) anchor destinations and visible link text from HTML
- Extract URLs, public IPv4 addresses, attachment metadata, and Received headers
- Interpret SPF, DKIM, and DMARC results while preserving the original authentication evidence
- Look up SPF and DMARC DNS records
- Flag Reply-To mismatches, displayed-link versus destination mismatches, suspicious URL keywords, deceptive filenames, risky extensions, and executable MIME mismatches
- Reuse standalone URL structure and brand-impersonation checks during email triage
- Explain each finding with its weight, confidence, evidence, false-positive caveat, and recommended next action
- Assign an L1 disposition, priority, confidence, escalation reason, and recommended next steps
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

# Opt in to submitting VirusTotal-unknown URLs for scanning
phishguard -f samples/phishing_test.eml --enrich --submit-unknown-urls

# Record where Authentication-Results headers came from
phishguard -f samples/phishing_test.eml --auth-source trusted_gateway
```

## Terminal colors

Interactive text reports color the risk level: green for LOW, gold for
MEDIUM, orange for HIGH, and bold red for CRITICAL. Colors are automatically
disabled for redirected output and every machine-readable format.

```bash
phishguard -f email.eml --color always  # force terminal colors
phishguard -f email.eml --no-color      # disable them
```

The `NO_COLOR` environment variable disables automatic color. `--color always`
overrides that preference for an interactive demonstration.

## Network and privacy behavior

PhishGuard treats suspicious emails and indicators as potentially sensitive data.
Analysis is offline by default: it does not contact any external service unless
you explicitly pass `--enrich`.

- With `--enrich`, email analysis can perform DNS SPF and DMARC lookups.
- With API keys configured, enrichment can look up up to ten extracted IPs in AbuseIPDB and up to three URLs in VirusTotal. Unknown VirusTotal URLs are lookup-only unless `--submit-unknown-urls` is also supplied.
- With `--enrich`, standalone URL analysis can perform an RDAP lookup and a TLS connection to the target host. Hostnames are resolved once and TLS enrichment is blocked if any result is non-public.
- Batch enrichment is limited to ten files to contain third-party requests and rate-limit exposure.

PhishGuard does **not** execute attachments or fetch webpage content. Analysts should still use approved sandboxing and investigation procedures for malicious URLs and files.

## Security model

PhishGuard is a decision-support tool, not a sandbox, browser-isolation
system, malware scanner, or automated blocking control.

Its main trust boundaries are:

- `.eml` files, headers, bodies, attachment metadata, filenames, and URLs are
  attacker-controlled input.
- HTML, text, JSON, CSV, and CEF reports can contain attacker-controlled
  evidence and must be handled as untrusted output.
- DNS, RDAP, TLS endpoints, and optional reputation services are external
  dependencies whose responses can be unavailable, incomplete, or hostile.
- External enrichment can disclose an indicator to a third party, so it
  requires explicit `--enrich` consent.

The core security invariants are bounded parsing, no execution of analyzed
content, offline-by-default operation, explicit rejection of malformed URL
input, and context-appropriate output encoding. See
[`SECURITY.md`](SECURITY.md) for vulnerability reporting and supported
security expectations.

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
parts, one million combined plain-text and HTML characters, 100 attachments, or 200
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

The report also includes an L1 disposition. `HIGH` means escalate for review; it
does not automatically mean malicious. `malicious_escalate` is reserved for a
`CRITICAL` score or a direct artifact signal such as a confirmed malicious URL,
a displayed-link mismatch, or a risky attachment/type mismatch. Other MEDIUM
and HIGH results use `suspicious_escalate`, while LOW results use
`likely_benign`. This keeps triage cautious until the evidence is strong enough
to support a malicious classification.

URL words such as `login`, `verify`, or `password` remain visible as analyst
evidence but are score-neutral by themselves. Stronger URL structure,
brand-impersonation, authentication, attachment, or reputation findings must
corroborate them before severity increases.

## Known limitations

- HTML is parsed only for anchor evidence; PhishGuard does not render HTML, fetch images, execute scripts, or interpret CSS-generated content.
- DKIM signature presence is detected, but PhishGuard does not independently perform full DKIM cryptographic verification.
- Authentication-Results headers are reported as message evidence, with an explicit `source_context`. They affect scoring only when `--auth-source trusted_gateway` is supplied; `unknown_capture` and `untrusted_capture` preserve the evidence without trusting attacker-controlled authentication claims.
- DNS records show what a sender domain publishes; they do not independently prove a message passed authentication during delivery.
- URL structure and brand-impersonation findings are integrated into email URL scoring; RDAP and TLS checks remain explicit-enrichment-only.
- Registrable-domain extraction uses a bundled public-suffix snapshot; update the dependency periodically as the suffix list evolves.
- Threat-intelligence coverage depends on API availability, rate limits, and configured keys.
- Reports should be reviewed before being shared externally.
- Repeated instances of the same detection rule remain visible as separate
  evidence, but only the first instance contributes to the risk score so
  duplicated indicators cannot inflate severity.

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

- [x] Extract URLs from HTML email bodies
- [x] Detect display-text and link-destination mismatches
- [x] Improve authentication-result interpretation
- [x] Expand attachment metadata and risky-file heuristics
- [x] Add representative benign, suspicious, and malicious test fixtures
- [x] Improve explainability for each finding

### 0.5 — Unified URL and email analysis

- [x] Use public-suffix-aware domain parsing
- [x] Integrate URL structure and brand-impersonation findings into email triage
- [x] Normalize URL and email findings around common IDs, messages, evidence, and actions
- [x] Prevent duplicate findings and inflated scores
- [x] Define safe limits for network enrichment during batch analysis

### 0.6 — Analyst workflow improvements

- [x] Improve batch prioritization and analyst summaries
- [x] Stabilize JSON and CEF schemas for downstream systems (JSON schema version `1.0` is now declared)
- [x] Add clear recommended next steps to reports
- [x] Establish an offline calibration corpus; real sanitized SOC captures remain the next validation requirement

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
├── pyproject.toml
├── SECURITY.md
├── evaluation/
│   ├── cases.json
│   ├── generate_eml_corpus.py
│   ├── run.py
│   └── synthetic_cases.py
├── phishguard/
│   ├── analyzer.py
│   ├── cli.py
│   ├── dns_validator.py
│   ├── email_parser.py
│   ├── report_generator.py
│   ├── security.py
│   ├── triage.py
│   ├── threat_intel.py
│   ├── url_analyzer.py
│   └── data/
├── samples/
│   └── generated/            # deterministic synthetic .eml regression fixtures
└── tests/
```

## Disclaimer

PhishGuard is for authorized defensive-security analysis and education. Use it only with emails, URLs, systems, and data you are permitted to investigate.

## License

MIT
