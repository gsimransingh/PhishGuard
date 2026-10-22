# PhishGuard evaluation

The evaluation manifest defines the current SOC L1 disposition contract:

- `likely_benign`
- `suspicious_escalate`
- `malicious_escalate`
- `insufficient_evidence`

## Headline metrics: configured and unconfigured

Every report scores **every case with `auth_source=unknown_capture`** (what an
analyst gets from the CLI without `--auth-source`) in two ways:

- `configured_mode` (**headline**): with `trusted_authserv_ids` set to the
  corpus's receiving servers (`CORPUS_TRUSTED_AUTHSERV_IDS` in `run.py`). This
  matches a SOC that has set `PHISHGUARD_TRUSTED_AUTHSERV_IDS`.
- `default_cli_mode`: no configuration at all. Authentication is recorded but
  not scored. Published so the cost of skipping setup stays visible.

The per-case `auth_source` labels are still reported, but they can leak the
expected answer: if only phishing cases are labelled `trusted_gateway`, only
phishing cases get credit for authentication failures.

The corpus is synthetic and was written to exercise these rules, so
configured-mode results are a regression guard, not a real-world accuracy claim.

Quick summary, including every default-mode miss:

```powershell
python -m evaluation.run --include-synthetic --summary
```

`tests/test_evaluation.py` enforces a recall floor and false-positive ceiling
for both modes. Raise the floor whenever a fix lands; never lower it.

Confirmed detection gaps are tracked as `xfail(strict=True)` tests in
`tests/test_known_gaps.py`. When a fix makes one pass, strict mode fails the
suite until the marker is removed, so the list stays honest.

## Full report

Run the offline baseline from the repository root:

```powershell
python -m evaluation.run --output evaluation\baseline.json
```

Add the deterministic generated `.eml` calibration fixtures explicitly when you
want the larger offline regression run:

```powershell
python -m evaluation.run --include-synthetic --output evaluation\baseline.json
```

The report measures accuracy, escalation precision and recall, false-positive
rate, false-negative rate, escalation rate, insufficient-evidence rate, and a
four-way confusion matrix. It also breaks results down by case category and
authentication source and counts which detection rules produced evidence.
Each result also records whether it came from a checked-in fixture or the
synthetic generated `.eml` corpus, and the report breaks metrics down by that
source type.

The disposition policy is intentionally cautious: a HIGH score is an
escalation signal, while a malicious disposition requires CRITICAL severity or
a direct malicious artifact signal.

The default runner evaluates the seven checked-in email fixtures. The optional
synthetic set adds 34 deterministic generated `.eml` fixtures, so the parser,
MIME handling, HTML-link extraction, and attachment metadata paths are also
exercised. They are useful for regression testing without storing personal
mail, but they are not a substitute for 30–50 real sanitized SOC captures when
making production accuracy claims.

Regenerate the synthetic fixtures after changing their definitions:

```powershell
python -m evaluation.generate_eml_corpus
```

The bundled seven cases are a smoke baseline, not a production accuracy claim.
Expand the manifest with sanitized organizational cases before using the
metrics for release decisions.
