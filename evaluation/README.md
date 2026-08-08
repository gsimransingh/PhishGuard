# PhishGuard evaluation

The evaluation manifest defines the current SOC L1 disposition contract:

- `likely_benign`
- `suspicious_escalate`
- `malicious_escalate`
- `insufficient_evidence`

Run the offline baseline from the repository root:

```powershell
python -m evaluation.run --output evaluation\baseline.json
```

The report measures accuracy, escalation precision and recall, false-positive
rate, false-negative rate, escalation rate, insufficient-evidence rate, and a
four-way confusion matrix. It also breaks results down by case category and
authentication source and counts which detection rules produced evidence.

The disposition policy is intentionally cautious: a HIGH score is an
escalation signal, while a malicious disposition requires CRITICAL severity or
a direct malicious artifact signal.

The bundled seven cases are a smoke baseline, not a production accuracy claim.
Expand the manifest with sanitized organizational cases before using the
metrics for release decisions.
