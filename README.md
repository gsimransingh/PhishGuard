# PhishGuard

> Explainable phishing-email triage for SOC analysts. PhishGuard takes a suspicious `.eml` file, extracts the evidence, scores it with rules you can read, and hands the analyst a disposition, a priority, and next steps.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
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

**Corpus:** 51 labelled emails (26 phishing, 25 benign): 7 hand-written fixtures plus 44 deterministic synthetic `.eml` files. **No real-world captures yet.** These numbers say how the rules behave on known patterns, not how the tool performs in production.

| Run mode | Accuracy | Phishing recall | False-positive rate |
| --- | --- | --- | --- |
| Default CLI (`--auth-source unknown_capture`) | 100% | **100%** (26/26) | 0% |

**Read that 100% as "this corpus has stopped discriminating", not as "detection is finished".** Ten confirmed gaps are still open below, and the corpus has a case for almost none of them: a credential-harvesting `<form>` with no `<a href>`, a backslash URL, and a display name hiding a Reply-To mismatch are all unmeasured here. A sender-domain lookalike with no links and legitimate brand mail — both unmeasured when this was written — now have cases. The number is a regression floor, not an accuracy claim.

This is a different figure from the 100% this README previously withdrew. That one came from scoring each case under its own `auth_source` label, so the label leaked the answer. This one scores every case in uniform default CLI mode, and the benign half now contains mail that genuinely fails authentication. The methodology is sound; the corpus is simply too easy. Making it harder is milestone 0.9.

**Why recall moved from 48% to 100%:** earlier versions discarded SPF/DKIM/DMARC results entirely unless the analyst declared the header's provenance, so a message that failed all three came back `likely_benign` with no flags. The threat model is asymmetric, though: an attacker who forges an `Authentication-Results` header writes `pass` to slip past a filter — forging `dmarc=fail` against yourself achieves nothing. So a recorded **failure** is now scored whatever its provenance, while a recorded **pass** still counts for nothing unless you pass `--auth-source trusted_gateway`. Absent results (`missing`, `none`, `neutral`) are not scored either, since stripping a header is free. Scoring failures accounts for most of that movement; pointing the brand checks at the `From` header closed the rest, since a lookalike sender domain is attacker-controlled and authenticates perfectly.

**What that costs:** legitimate mail does fail authentication. Forwarding breaks SPF, and a mailing list that appends a footer invalidates DKIM and takes DMARC with it. When a message carries list (RFC 2919/2369) or `Resent-*` headers, authentication failures are scored at half weight with `low` confidence and a caveat naming the relay evidence — the finding stays visible, but ordinary list traffic does not escalate. The benign half of the corpus now includes forwarded and mailing-list messages that genuinely fail authentication, plus ordinary Microsoft 365, Amazon, and Google notifications that name their own brand and link to their own domains, so that 0% false-positive rate is measured rather than assumed.

Earlier versions of this README reported 100% accuracy. That figure came from an evaluation in which every phishing case ran in trusted-gateway mode and every benign case did not, so the label leaked into the result. It has been withdrawn.

## What it checks

| Area | Checks | Scored by default |
| --- | --- | --- |
| Authentication | SPF, DKIM, DMARC results from `Authentication-Results` / `Received-SPF`; DKIM signature presence | Recorded **failures** always; `pass` and `missing` only with `--auth-source trusted_gateway` |
| Sender | Reply-To vs From mismatch; typosquat and combosquat of the `From` domain; brand named in the display name that the sending domain does not own | Yes |
| Links | HTML link text vs real destination; IP hosts, `@` tricks, deep subdomains, abused TLDs, non-standard ports, punycode; typosquat and combosquat against a curated brand list | Yes |
| Attachments | Risky and active-content extensions, double extensions, bidirectional-text filenames, executable MIME type vs filename, **file signature vs extension**; SHA-256 per attachment; found regardless of `Content-Disposition` | Yes |
| Enrichment (opt-in) | AbuseIPDB (IPs), VirusTotal (URLs), SPF/DMARC DNS, RDAP domain age, TLS certificate | Only with `--enrich` |

Extracted indicators include each attachment's SHA-256 and detected file format, so an analyst can pivot to a sandbox or reputation service without opening anything. Every finding carries its weight, confidence, evidence, a false-positive caveat, and a recommended next step. Output formats: text, JSON (schema `1.0`), HTML, CEF, batch summary, and CSV. A standalone `-u` mode lets an analyst pivot on a single URL or domain.

## Known detection gaps

These are confirmed misses or false positives, tracked on the roadmap below. Analysts should check for them manually until they are fixed.

- **HTML forms, iframes, and meta refresh are not extracted.** Only `<a href>` links are.
- **A display name can hide a Reply-To mismatch.** For example: `"a@x.com <a@x.com>" <evil@y.com>`.
- **URLs containing a backslash are analyzed as the wrong host.** For `http://evil.example\@paypal.com`, browsers go to `evil.example`, but PhishGuard analyzes `paypal.com`.
- **One VirusTotal engine is enough to raise a high-confidence malicious finding.**
- **The HTML report omits the authentication interpretation.** It prints the raw SPF/DKIM/DMARC header values but not `score_status` or `scored_because`, so it does not show which results were scored and which were ignored. It also omits `url_analysis`, `dns_validation`, and the received chain, making it a less complete view than the JSON report.
- **IPv6 and obfuscated IP hosts are not flagged as raw-IP destinations.** `ip_as_hostname` matches dotted-quad IPv4 only, so `http://[2001:db8::1]/`, `http://1021342134/` (decimal) and `http://0x7f.1/` (hex) score 0.
- **A valid header-only `.eml` is rejected.** Parsing requires a blank line within the 64 KiB header limit, so a message with no body — a common SOC capture — fails with a misleading size error, as do empty and non-email files.
- **A brand-owned domain missing from `known_brands.json` reads as impersonation of itself.** The owned-domain lists are curated, not exhaustive; a legitimate domain that is not listed can produce a brand finding, and adding it is a data change, not a code change.
- **A lookalike that both substitutes a character and adds words to one label is missed.** `paypa1-secure-login.ru` defeats the edit-distance check (the whole label is too far from the brand) and the combosquat check (the brand spelling is not present).
- **Brand-named mail from a brand's own hosting domain is not checked against that brand.** A page for Amazon hosted on `s3.amazonaws.com` is not reported as an Amazon squat, because that domain is Amazon's. Another brand on the same host still is.

### Design limitations

- HTML is parsed for evidence only; PhishGuard never renders HTML, fetches content, or executes attachments.
- DKIM signatures are detected, not cryptographically verified.
- A recorded authentication **failure** is scored whatever its provenance; a recorded **pass** is scored only when the analyst declares the header trustworthy, because forging a `pass` is exactly what an attacker would do. A `missing` result is never scored — stripping a header costs nothing.
- Relay-aware softening keys off list and `Resent-*` headers, which an attacker can also add. It reduces the weight of an authentication failure; it never suppresses the finding, and every other check still applies at full weight.
- DNS records show what a domain publishes, not what happened at delivery.
- Domain extraction uses a bundled public-suffix snapshot; update the dependency periodically. When the snapshot does not recognise a suffix, the registrable domain falls back to the last two labels, so an unknown TLD cannot make `paypal.com.evil.<new-tld>` read as the real PayPal.
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
attachment type mismatch. Other MEDIUM and HIGH results use
`suspicious_escalate`, and so does **any** direct signal whatever its score:
those checks name an artifact an analyst can act on, so one is never reported
as `likely_benign` just because the arithmetic stayed under the MEDIUM
threshold. Everything else is `likely_benign`. This keeps triage cautious
until the evidence is strong enough to support a malicious classification,
without letting a confirmed artifact be buried by a low total.

URL words such as `login`, `verify`, or `password` remain visible as analyst
evidence but are score-neutral by themselves. Stronger URL structure,
brand-impersonation, authentication, attachment, or reputation findings must
corroborate them before severity increases.

## Roadmap

Each milestone ends on a **measurable exit criterion**, not a feature checklist. A milestone is done when its numbers hold on the evaluation corpus, not when its code is merged.

### Shipped (0.3 – 0.5)

Bounded parsing of hostile input, offline-by-default operation, safe HTML/CEF/CSV/terminal output, CI on Python 3.11–3.14 with dependency audit and static security checks, HTML link extraction, link-text mismatch detection, attachment filename heuristics, public-suffix-aware domain parsing, unified URL and email findings, per-rule score de-duplication, L1 disposition and priority, JSON schema `1.0`, and a synthetic offline corpus with an explicit, published default-mode baseline.

### 0.6: Honest baseline — shipped

- [x] Evaluation runs every case in default CLI mode and reports it alongside any trusted-gateway run
- [x] Remove the `accuracy == 1.0` test assertion; enforce a minimum recall floor instead
- [x] Regression tests for every confirmed gap above (written failing first)

**Exit criterion met:** `python -m evaluation.run --include-synthetic --summary` reproduces the default-mode metrics published above, and prints every miss.

### 0.7: No silent misses (next)

- [x] Score recorded authentication **failures** regardless of header provenance; keep ignoring unverified `pass` and `missing`
- [x] Benign corpus contains mail that legitimately fails authentication (forwarded, mailing list), so the false-positive ceiling is measurable
- [x] Relay-aware softening so legitimate list traffic does not escalate on a broken DKIM signature
- [x] Detect attachments regardless of `Content-Disposition`; check file signatures; report SHA-256 per attachment
- [x] Any direct malicious signal escalates to at least `suspicious_escalate`, whatever the total score
- [ ] `--trusted-authserv-id`: trust a `pass` only when stamped by your own receiving servers (RFC 8601 §5)

**Exit criterion met:** default-mode phishing recall is 100% (23/23) with the false-positive rate still 0%, against a benign set that now includes mail which legitimately fails authentication. The `--trusted-authserv-id` box stays open: it is what would let a `pass` count for something, which matters for ranking rather than for recall.

Weights and thresholds remain uncalibrated against each other — the heaviest direct signal is 40 against a HIGH threshold of 70, so `malicious_escalate` is still hard to reach offline. The disposition floor added here routes around that rather than fixing it; the arithmetic belongs in 0.8.

### 0.8: Analyst trust

- [x] Brand-owned domain allowlist (`known_brands.json` needs a `domains` field), stricter edit distance scaled to label length, whole-token combosquat matching
- [ ] Recalibrate weights against thresholds so a direct signal can reach `malicious_escalate` on its own evidence
- [ ] Address-parser-based Reply-To comparison; WHATWG-style backslash handling in URLs
- [x] Sender-domain lookalike and display-name brand-spoof checks
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
