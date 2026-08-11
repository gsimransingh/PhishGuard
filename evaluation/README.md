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

Add the deterministic parsed-message calibration variants explicitly when you
want the larger offline regression run:

```powershell
python -m evaluation.run --include-synthetic --output evaluation\baseline.json
```

The report measures accuracy, escalation precision and recall, false-positive
rate, false-negative rate, escalation rate, insufficient-evidence rate, and a
four-way confusion matrix. It also breaks results down by case category and
authentication source and counts which detection rules produced evidence.

The disposition policy is intentionally cautious: a HIGH score is an
escalation signal, while a malicious disposition requires CRITICAL severity or
a direct malicious artifact signal.

The default runner evaluates the seven checked-in email fixtures. The optional
synthetic set adds 27 deterministic parsed-message variants. They are useful
for calibration without storing personal mail, but they are not a substitute
for 30–50 real sanitized SOC captures when making production accuracy claims.

The bundled seven cases are a smoke baseline, not a production accuracy claim.
Expand the manifest with sanitized organizational cases before using the
metrics for release decisions.
