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

## Offline mode and privacy

Use `--no-intel` whenever the message or indicators must stay local, or when
you need a fast deterministic run:

```bash
phishguard -f samples/phishing_test.eml --no-intel
phishguard -F samples/ --no-intel --csv results.csv
```

Offline mode skips every external lookup: DNS, AbuseIPDB, VirusTotal, RDAP,
and TLS. Without it, PhishGuard can query DNS and may contact AbuseIPDB or
VirusTotal when their API keys are configured.

```powershell
$env:ABUSEIPDB_API_KEY="your_key_here"
$env:VIRUSTOTAL_API_KEY="your_key_here"
```

## Automation

JSON is written only to standard output; progress messages and the banner are
written to standard error. This keeps JSON safe for pipelines:

```bash
phishguard -f email.eml -o json --no-intel > report.json
```

Use `--no-banner` for scheduled jobs that do not need the startup banner.

## Help

```bash
phishguard --help
phishguard --version
```
