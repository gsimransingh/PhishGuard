# Security policy

## Reporting a vulnerability

Please do not disclose an unpatched vulnerability in a public issue. Report it
privately through GitHub's **Security** tab using a private vulnerability
report. Include the affected version, a minimal reproducer, expected impact,
and any suggested remediation if available.

Do not include real phishing emails, credentials, API keys, personal data, or
third-party systems in a report. Use synthetic test data and only test systems
you are authorized to assess.

## Supported versions

Security fixes are applied to the latest code on the default branch. Older
releases may not receive backports.

## Security boundaries

PhishGuard assumes all analyzed email and URL content is hostile. The project
aims to preserve these properties:

- Analysis is offline unless the operator explicitly enables enrichment.
- Parsed input is bounded before expensive processing.
- Attachments, scripts, macros, and linked content are never executed.
- Malformed URLs are rejected rather than scored or passed to enrichment.
- Attacker-controlled values are encoded for their output context.
- Secrets are read from environment variables and are not included in reports.

PhishGuard is not a sandbox, antivirus engine, browser-isolation product, or
automated blocking control. A LOW result is not proof that content is safe.

## Out of scope

Reports about detection misses or false positives are valuable quality issues,
but they are not vulnerabilities unless they break a documented security
boundary. Denial of service that exceeds documented input limits, social
engineering without a product flaw, and attacks requiring unauthorized testing
of third-party systems are also out of scope.
