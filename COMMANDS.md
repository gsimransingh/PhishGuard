# PhishGuard Command Reference

> Complete guide to using PhishGuard — from basic analysis to advanced SOC workflows.

---

## Quick Start

```bash
# Clone and setup
git clone https://github.com/psycho-manav/PhishGuard.git
cd PhishGuard
pip install -r requirements.txt

# Run your first analysis
python main.py -f samples/phishing_test.eml
```

---

## Table of Contents

1. [Installation](#installation)
2. [Basic Commands](#basic-commands)
3. [Output Formats](#output-formats)
4. [API Configuration](#api-configuration)
5. [Advanced Usage](#advanced-usage)
6. [Batch Processing](#batch-processing)
7. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

```bash
# Check Python version (3.8+ required)
python --version

# Check pip
pip --version
```

### Install PhishGuard

```bash
# Clone repository
git clone https://github.com/psycho-manav/PhishGuard.git
cd PhishGuard

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py --help
```

---

## Basic Commands

### 1. Analyze Email (Default Text Output)

```bash
python main.py -f samples/phishing_test.eml
```

**Output:**
```
============================================================
  PhishGuard v0.2.0 - Analysis Report
  Risk Level : HIGH (score: 120)
============================================================
```

### 2. Analyze Your Own Email

```bash
# First, save email as .eml from your mail client:
# Gmail: Open email → ⋮ → Download message
# Outlook: File → Save As → Outlook Message Format (.msg) or .eml

python main.py -f /path/to/suspicious_email.eml
```

### 3. Quick Risk Check

```bash
python main.py -f email.eml | grep "Risk Level"
```

**Output:** `Risk Level : HIGH (score: 95)`

---

## Output Formats

### Text Format (Human Readable)

```bash
python main.py -f email.eml -o text
# or simply:
python main.py -f email.eml
```

### JSON Format (SIEM Ready)

```bash
python main.py -f email.eml -o json
```

**Save to file:**
```bash
python main.py -f email.eml -o json > report.json
```

**Extract specific fields with `jq`:**
```bash
# Get risk score only
python main.py -f email.eml -o json | jq '.risk_score'

# Get all IOCs
python main.py -f email.eml -o json | jq '.iocs'

# Get URLs only
python main.py -f email.eml -o json | jq '.iocs.urls[]'

# Get flags
python main.py -f email.eml -o json | jq '.flags[]'
```

---

## API Configuration

### Setup API Keys (Optional)

**AbuseIPDB (IP reputation checks):**
- Sign up: https://www.abuseipdb.com/register
- Get free API key: https://www.abuseipdb.com/account/api
- Free tier: 1,000 checks/day

**VirusTotal (URL/domain checks):**
- Sign up: https://www.virustotal.com/gui/join-us
- Get API key: Account → API Key
- Free tier: 4 lookups/min, 500/day

### Set Environment Variables

**Linux/Mac:**
```bash
export ABUSEIPDB_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"

# Make permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export ABUSEIPDB_API_KEY="your_key"' >> ~/.bashrc
echo 'export VIRUSTOTAL_API_KEY="your_key"' >> ~/.bashrc
source ~/.bashrc
```

**Windows (PowerShell):**
```powershell
$env:ABUSEIPDB_API_KEY="your_key_here"
$env:VIRUSTOTAL_API_KEY="your_key_here"

# Make permanent:
[Environment]::SetEnvironmentVariable("ABUSEIPDB_API_KEY", "your_key", "User")
[Environment]::SetEnvironmentVariable("VIRUSTOTAL_API_KEY", "your_key", "User")
```

### Offline Mode (No API Calls)

```bash
# Skip all API lookups
python main.py -f email.eml --no-intel
```

**When to use:**
- No API keys configured
- Working offline
- Fast bulk analysis
- Rate limit concerns

---

## Advanced Usage

### Extract Specific Data

**Get only email metadata:**
```bash
python main.py -f email.eml -o json | jq '.email_metadata'
```

**Get threat intel results:**
```bash
python main.py -f email.eml -o json | jq '.threat_intel'
```

**Get DNS validation results:**
```bash
python main.py -f email.eml -o json | jq '.dns_validation'
```

### Save Reports with Timestamps

```bash
# Text report
python main.py -f email.eml > "report_$(date +%Y%m%d_%H%M%S).txt"

# JSON report
python main.py -f email.eml -o json > "report_$(date +%Y%m%d_%H%M%S).json"
```

### Redirect stderr and stdout

```bash
# Capture all output
python main.py -f email.eml > output.txt 2>&1

# Separate stdout and stderr
python main.py -f email.eml > stdout.txt 2> stderr.txt
```

---

## Batch Processing

### Analyze Multiple Emails

```bash
# Create directory with .eml files
mkdir emails_to_analyze
cp /path/to/*.eml emails_to_analyze/

# Analyze all
for email in emails_to_analyze/*.eml; do
  echo "\n=== Analyzing: $email ==="
  python main.py -f "$email" --no-intel | grep "Risk Level"
done
```

### Generate JSON Reports for All

```bash
for email in emails_to_analyze/*.eml; do
  basename="$(basename "$email" .eml)"
  python main.py -f "$email" -o json > "reports/${basename}_report.json"
  echo "Generated: reports/${basename}_report.json"
done
```

### Filter High-Risk Emails Only

```bash
for email in *.eml; do
  score=$(python main.py -f "$email" -o json --no-intel | jq -r '.risk_score')
  if [ "$score" -ge 70 ]; then
    echo "🚨 HIGH RISK: $email (Score: $score)"
    cp "$email" high_risk_emails/
  fi
done
```

### Create Summary Report

```bash
echo "Email,Risk Level,Score" > summary.csv
for email in *.eml; do
  result=$(python main.py -f "$email" -o json --no-intel)
  level=$(echo "$result" | jq -r '.risk_level')
  score=$(echo "$result" | jq -r '.risk_score')
  echo "$email,$level,$score" >> summary.csv
done
```

---

## Troubleshooting

### Check Installation

```bash
# Verify Python version
python --version  # Should be 3.8+

# Check dependencies
pip list | grep -E "requests|dnspython|ipwhois"

# Test basic functionality
python main.py --help
```

### Common Issues

**1. "ModuleNotFoundError: No module named 'requests'"**
```bash
pip install -r requirements.txt
```

**2. "FileNotFoundError: [Errno 2] No such file or directory"**
```bash
# Check file path
ls -la samples/phishing_test.eml

# Use absolute path
python main.py -f /full/path/to/email.eml
```

**3. "API key not set" warnings**
```bash
# Either set API keys:
export ABUSEIPDB_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"

# Or use offline mode:
python main.py -f email.eml --no-intel
```

**4. DNS timeout errors**
```bash
# Check internet connection
ping 8.8.8.8

# Check DNS
nslookup google.com

# Use offline mode if DNS unavailable
python main.py -f email.eml --no-intel
```

### Debug Mode

```bash
# Verbose Python output
python -v main.py -f email.eml

# Check what's being parsed
python -c "from phishguard.email_parser import parse_eml; import json; print(json.dumps(parse_eml('samples/phishing_test.eml'), indent=2))"
```

---

## Real-World SOC Workflows

### Daily Email Triage

```bash
#!/bin/bash
# daily_triage.sh

EMAIL_DIR="/path/to/reported_emails"
REPORT_DIR="/path/to/reports/$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

for email in "$EMAIL_DIR"/*.eml; do
  name=$(basename "$email" .eml)
  python main.py -f "$email" -o json > "$REPORT_DIR/${name}.json"
  
  # Alert on high-risk
  risk=$(jq -r '.risk_level' "$REPORT_DIR/${name}.json")
  if [ "$risk" = "HIGH" ]; then
    echo "⚠️  HIGH RISK DETECTED: $name" | mail -s "Phishing Alert" soc@company.com
  fi
done
```

### Integration with SIEM

```bash
# Send to syslog
python main.py -f email.eml -o json | logger -t phishguard

# Append to log file
python main.py -f email.eml -o json >> /var/log/phishguard/alerts.json
```

---

## Command Quick Reference

| Command | Purpose |
|---------|--------|
| `python main.py -f email.eml` | Basic analysis (text output) |
| `python main.py -f email.eml -o json` | JSON output |
| `python main.py -f email.eml --no-intel` | Offline mode (no API calls) |
| `python main.py -f email.eml \| grep "Risk"` | Quick risk check |
| `python main.py -f email.eml -o json \| jq '.risk_score'` | Get score only |
| `python main.py -f email.eml > report.txt` | Save to file |
| `for f in *.eml; do ...; done` | Batch processing |

---

## Getting Help

```bash
# Show help message
python main.py --help
python main.py -h
```

**Issues or Questions?**
- GitHub Issues: https://github.com/psycho-manav/PhishGuard/issues
- Documentation: https://github.com/psycho-manav/PhishGuard#readme

---

*Last updated: May 16, 2026 | PhishGuard v0.2.0*
