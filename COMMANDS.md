# PhishGuard command reference

PhishGuard is a decision-support CLI for authorised defensive email triage.
It does not execute attachments or fetch email links.

## Install

```bash
git clone https://github.com/gsimransingh/PhishGuard.git
cd PhishGuard
python -m pip install .
```

For local development and tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The project metadata in [`pyproject.toml`](pyproject.toml) is the source of
truth for supported Python versions and dependencies.

## Analyze an email

```bash
# Human-readable report
phishguard -f samples/phishing_test.eml

# Machine-readable report
phishguard -f samples/phishing_test.eml -o json

# Save an HTML or CEF report
phishguard -f samples/phishing_test.eml -o html -O report.html
phishguard -f samples/phishing_test.eml -o cef -O event.cef
```

`python main.py` remains available when running directly from a checkout.

## Analyze URLs and domains

```bash
phishguard -u paypa1-verify.com
phishguard -u https://example.test/login -o json
```

## Batch triage

```bash
# Summary table
phishguard -F samples/

# Include each full email report
phishguard -F samples/ -V

# Export a summary CSV
phishguard -F samples/ --csv results.csv
```

## Privacy-first enrichment

PhishGuard is offline by default. Use `--enrich` only when you have approval
to send indicators to external DNS, reputation, RDAP, and TLS services:

```bash
phishguard -f samples/phishing_test.eml
phishguard -f samples/phishing_test.eml --enrich
phishguard -F samples/ --enrich --csv results.csv
```

`--enrich` is capped at ten files in batch mode. It can query DNS and, with
configured API keys, contact AbuseIPDB or VirusTotal. VirusTotal results are
lookup-only by default; add `--submit-unknown-urls` when you explicitly approve
submitting URLs that VirusTotal has not seen before. Use `--auth-source`
(`unknown_capture`, `trusted_gateway`, or `untrusted_capture`) to preserve the
provenance of Authentication-Results headers in JSON reports. Authentication
results affect scoring only for `trusted_gateway`; the other values preserve
the evidence but do not trust it for scoring.

```powershell
$env:ABUSEIPDB_API_KEY="your_key_here"
$env:VIRUSTOTAL_API_KEY="your_key_here"
```

## Automation

JSON is written only to standard output; progress messages and the banner are
written to standard error. This keeps JSON safe for pipelines:

```bash
phishguard -f email.eml -o json > report.json
```

Use `--no-banner` for scheduled jobs that do not need the startup banner.

## Terminal colors

Text reports automatically color LOW green, MEDIUM gold, HIGH orange, and
CRITICAL bold red in an interactive terminal. Colors never appear in JSON,
CSV, CEF, HTML, saved output, or redirected pipelines.

```bash
phishguard -f email.eml --color always
phishguard -f email.eml --no-color
```

Set `NO_COLOR=1` to disable automatic terminal color across scripts.

## Safety limits

PhishGuard rejects messages over 25 MiB, headers over 64 KiB, more than 200
MIME parts, one million extracted plain-text characters, 100 attachments, or
200 unique URLs. Batches are capped at 100 files and 250 MiB. These are safety
boundaries for hostile inputs, not phishing detections.

## Help

```bash
phishguard --help
phishguard --version
```
