# PhishGuard

> Explainable phishing-email triage for SOC analysts. PhishGuard takes a suspicious `.eml` file, extracts the evidence, scores it with rules you can read, and hands the analyst a disposition, a priority, and next steps.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Who it is for

PhishGuard is built for **Tier 1 / Tier 2 SOC analysts** working a reported-phishing queue. It is a decision-support CLI: it speeds up evidence gathering and makes the reasoning behind every score visible. It does not block mail, does not replace analyst judgment, and is not a consumer phishing checker.

For each reported email it answers four questions:

- What sender, link, attachment, and authentication evidence is present?
- Why does each piece of evidence matter, and how could it be wrong?
- What disposition and priority does the evidence support?
- What should the analyst check next?

## Current status: read this before trusting a score

PhishGuard is **pre-1.0**. Detection quality is measured on an offline corpus and the numbers are published here, including the bad ones.

**Corpus:** 41 labelled emails (21 phishing, 20 benign): 7 hand-written fixtures plus 34 deterministic synthetic `.eml` files. **No real-world captures yet.** These numbers say how the rules behave on known patterns, not how the tool performs in production.

| Run mode | Accuracy | Phishing recall | False-positive rate |
| --- | --- | --- | --- |
| Default CLI (`--auth-source unknown_capture`) | 56% | **48%** | 0% |

**What the 48% means:** with default settings, authentication results (SPF/DKIM/DMARC) are recorded but not scored, because PhishGuard cannot tell whether an `Authentication-Results` header was written by your mail gateway or forged by the sender. Phishing that relies mainly on spoofed authentication is therefore under-scored. Fixing this safely is the 0.7 milestone.

Earlier versions of this README reported 100% accuracy. That figure came from an evaluation in which every phishing case ran in trusted-gateway mode and every benign case did not, so the label leaked into the result. It has been withdrawn.

## What it checks

| Area | Checks | Scored by default |
| --- | --- | --- |
| Authentication | SPF, DKIM, DMARC results from `Authentication-Results` / `Received-SPF`; DKIM signature presence | Only with `--auth-source trusted_gateway` |
| Sender | Reply-To vs From mismatch | Yes |
| Links | HTML link text vs real destination; IP hosts, `@` tricks, deep subdomains, abused TLDs, non-standard ports, punycode; typosquat and combosquat against a curated brand list | Yes |
| Attachments | Risky and active-content extensions, double extensions, bidirectional-text filenames, executable MIME type vs filename | Yes |
| Enrichment (opt-in) | AbuseIPDB (IPs), VirusTotal (URLs), SPF/DMARC DNS, RDAP domain age, TLS certificate | Only with `--enrich` |

Every finding carries its weight, confidence, evidence, a false-positive caveat, and a recommended next step. Output formats: text, JSON (schema `1.0`), HTML, CEF, batch summary, and CSV. A standalone `-u` mode lets an analyst pivot on a single URL or domain.

## Known detection gaps

These are confirmed misses or false positives, tracked on the roadmap below. Analysts should check for them manually until they are fixed.

- **Attachments not marked `Content-Disposition: attachment` are not seen.** An executable sent `inline`, or with no disposition, produces no attachment finding.
- **File type comes from the filename and MIME type only.** File signatures (magic bytes) are not checked, so an executable named `invoice.pdf` and sent as `application/octet-stream` scores 0.
- **A direct signal can still end up `likely_benign`.** A link-text mismatch or executable type mismatch only forces escalation when the total score is HIGH.
- **The sender domain itself is not checked for lookalikes.** `"PayPal Security" <service@paypa1.com>` with no links scores 0.
- **HTML forms, iframes, and meta refresh are not extracted.** Only `<a href>` links are.
- **The brand check flags some legitimate domains.** Examples include `login.microsoftonline.com`, `outlook.office365.com`, `s3.amazonaws.com`, and `purchase.com` (contains "chase"). Short brands also match ordinary words (`abc.com` → hsbc, `ups.com` → usps).
- **A display name can hide a Reply-To mismatch.** For example: `"a@x.com <a@x.com>" <evil@y.com>`.
- **URLs containing a backslash are analyzed as the wrong host.** For `http://evil.example\@paypal.com`, browsers go to `evil.example`, but PhishGuard analyzes `paypal.com`.
- **One VirusTotal engine is enough to raise a high-confidence malicious finding.**

### Design limitations

- HTML is parsed for evidence only; PhishGuard never renders HTML, fetches content, or executes attachments.
- DKIM signatures are detected, not cryptographically verified.
- Authentication headers affect scoring only when the analyst declares their provenance, because forged `Authentication-Results` headers are trivial to add.
- DNS records show what a domain publishes, not what happened at delivery.
- Domain extraction uses a bundled public-suffix snapshot; update the dependency periodically.
- Enrichment coverage depends on API keys, availability, and rate limits.
- Repeated hits of one rule stay visible as evidence but score only once.

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
`CRITICAL` score, or a `HIGH` score that includes a direct artifact signal
such as a confirmed malicious URL, a displayed-link mismatch, or an
attachment type mismatch (see Known detection gaps). Other MEDIUM
and HIGH results use `suspicious_escalate`, while LOW results use
`likely_benign`. This keeps triage cautious until the evidence is strong enough
to support a malicious classification.

URL words such as `login`, `verify`, or `password` remain visible as analyst
evidence but are score-neutral by themselves. Stronger URL structure,
brand-impersonation, authentication, attachment, or reputation findings must
corroborate them before severity increases.

## Roadmap

Each milestone ends on a **measurable exit criterion**, not a feature checklist. A milestone is done when its numbers hold on the evaluation corpus, not when its code is merged.

### Shipped (0.3 – 0.5)

Bounded parsing of hostile input, offline-by-default operation, safe HTML/CEF/CSV/terminal output, CI on Python 3.10–3.14 with dependency audit and static security checks, HTML link extraction, link-text mismatch detection, attachment filename heuristics, public-suffix-aware domain parsing, unified URL and email findings, per-rule score de-duplication, L1 disposition and priority, JSON schema `1.0`, and a synthetic offline corpus.

### 0.6: Honest baseline (next)

- [ ] Evaluation runs every case in default CLI mode and reports it alongside any trusted-gateway run
- [ ] Remove the `accuracy == 1.0` test assertion; enforce a minimum recall floor instead
- [ ] Regression tests for every confirmed gap above (written failing first)

**Exit criterion:** default-mode metrics are reproducible with one command and published in this README.

### 0.7: No silent misses

- [ ] `--trusted-authserv-id`: trust only `Authentication-Results` stamped by your own receiving servers (RFC 8601 §5)
- [ ] Detect attachments regardless of `Content-Disposition`; check file signatures; report SHA-256 per attachment
- [ ] Any direct malicious signal escalates to at least `suspicious_escalate`

**Exit criterion:** default-mode phishing recall ≥ 85% on the corpus with false-positive rate unchanged.

### 0.8: Analyst trust

- [ ] Brand-owned domain allowlist, stricter edit distance, whole-token combosquat matching
- [ ] Address-parser-based Reply-To comparison; WHATWG-style backslash handling in URLs
- [ ] Sender-domain lookalike and display-name brand-spoof checks
- [ ] Extract `form[action]`, `iframe`, `meta refresh`, `data:` / `javascript:` URLs; flag password inputs
- [ ] VirusTotal finding requires a minimum engine count

**Exit criterion:** false-positive rate ≤ 5% on a benign set of real brand notifications (Microsoft 365, Google, Amazon, banks), recall ≥ 85% held.

### 0.9: Real-world validation

- [ ] 50+ sanitized real reported-phishing and benign captures added to the corpus (synthetic cases remain as regression tests)
- [ ] Metrics reported separately for real and synthetic sources

**Exit criterion:** recall and false-positive targets from 0.7–0.8 hold on the real-capture set.

### 1.0: Stable for SOC workflows

- [ ] JSON and CEF schemas frozen and documented; breaking changes require a major version
- [ ] Published detection metrics in every release notes entry

**Exit criterion:** two consecutive releases meet the 0.8 targets without schema changes.

### After 1.0 (analyst-workflow candidates, not commitments)

- Outlook `.msg` input
- STIX 2.1 / MISP export of extracted IOCs
- A stable Python API for SOAR playbooks

### Out of scope

PhishGuard will not become a consumer phishing checker, browser extension, community reporting platform, or real-time mail-blocking product. Machine-learning scoring is out of scope until the rule-based engine is validated on real captures, and would only ever be added as an explainable, assistive signal.

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
