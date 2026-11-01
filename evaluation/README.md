# PhishGuard evaluation

The evaluation manifest defines the current SOC L1 disposition contract:

- `likely_benign`
- `suspicious_escalate`
- `malicious_escalate`
- `insufficient_evidence`

## Headline metric: default CLI mode

Every report includes a `default_cli_mode` block that scores **every case with
`auth_source=unknown_capture` and nothing configured**, which is what an
analyst gets when running the CLI with no flags and no setup. Treat this as
the headline number. The per-case `auth_source` labels are still reported, but
they can leak the expected answer: if only phishing cases are labelled
`trusted_gateway`, only phishing cases get credit for authentication failures.

A second block, `configured_mode`, scores the same cases with
`CORPUS_TRUSTED_AUTHSERV_IDS` supplied — the evaluation equivalent of a SOC
setting `PHISHGUARD_TRUSTED_AUTHSERV_IDS` to its own receiving servers, so a
`pass` from them is believed. Both are published deliberately. Reporting only
the configured figure would hide what the tool does before anyone configures
it, and the unconfigured number stays the headline for that reason.

Quick summary, including every miss in both modes:

```powershell
python -m evaluation.run --include-synthetic --summary
```

`tests/test_evaluation.py` enforces a recall floor and false-positive ceiling
for **each** mode. Raise a floor whenever a fix lands; never lower it. The
configured ceiling earns its keep: when a matched authserv-id was first
allowed to cancel relay softening, both mailing-list fixtures escalated and
that ceiling caught it at 8%.

The false-positive ceiling is only meaningful while the benign half of the
corpus contains mail that legitimately fails authentication: forwarded
messages (SPF breaks at the relay) and mailing-list messages (a footer
invalidates DKIM, and DMARC follows). Each case's authentication profile is
chosen explicitly in `AUTH_PROFILES`, independently of its `auth_source`
label. Deriving one from the other made "is this phishing" and "does
authentication fail" the same variable and guaranteed a 0% false-positive
rate regardless of the rules, so
`test_benign_corpus_can_produce_an_authentication_false_positive` guards
against reintroducing that.

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
synthetic set adds 38 deterministic generated `.eml` fixtures, so the parser,
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
