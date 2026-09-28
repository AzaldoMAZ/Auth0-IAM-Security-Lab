# Part 7 — Automated Incident Reporting

Part 7 reads Part 5's findings and Part 6's response log and produces a single, human-readable incident report — the Post-Incident Activity phase of the NIST SP 800-61r2 lifecycle. This closes the loop across the whole lab: Preparation (Parts 1–4) → Detection & Analysis (Part 5) → Containment (Part 6) → Post-Incident Activity (Part 7).

## What this demonstrates

- Synthesizing two independent components' output (detection findings and response actions) into one coherent narrative, rather than leaving a reviewer to cross-reference two JSON files by hand
- Automatic PII masking, applied unconditionally rather than left as a manual step before sharing
- Severity classification per finding, independent of whether an automated response already ran
- A report format usable outside the terminal — Markdown, readable by a manager, a compliance reviewer, or a future employer looking at this repo
- No external dependencies — pure Python standard library, since a reporting script has no reason to carry extra attack surface

## PII masking

Every subject is masked before being written to a report:

- **Email:** `az**********@gmail.com` — first two characters kept, rest masked, domain kept for context
- **Auth0 user ID:** `google-oauth2|********9673` — provider kept, last four characters of the identifier kept, rest masked
- **`unknown`** subjects pass through unchanged (nothing to mask)

This means a generated report is safe to share, screenshot, or commit without a separate redaction step.

## Architecture

1. `generate_report.py` loads `../part-05-audit-logging-anomaly-detection/logs/alerts.json` and `../part-06-automated-incident-response/logs/response_log.json`.
2. Each finding is matched to its corresponding response entry (if one exists) using the same `(technique, subject, alert_time_marker)` key Part 6 uses for idempotency.
3. Each finding's subject is masked, and a severity is assigned (High for brute force and account manipulation, Medium for impossible travel, Low otherwise).
4. An Executive Summary, a Findings table, and Recommendations are assembled into a single Markdown report.
5. The report is written to `reports/incident-report-<timestamp>.md`.

## Local setup

No credentials or `.env` file are required — this script only reads local files already produced by Parts 5 and 6.

Make sure Parts 5 and 6 have run at least once, so `alerts.json` and `response_log.json` exist, then:

```
python generate_report.py
```

## Evidence

A generated report from a real detection-and-response cycle (the same live brute-force test used in Parts 5 and 6) is in `evidence/`.

1. [Generated incident report](evidence/01-sample-incident-report.png)

The report itself has PII masked automatically by the script — no manual redaction was needed for this evidence.

## Security notice

Reports are generated from local `alerts.json` and `response_log.json` files, which are themselves excluded from Git (see Parts 5 and 6). Generated reports under `reports/` mask subjects automatically, but reports are still local build artifacts, not intended to be committed wholesale — commit representative examples deliberately, not the whole `reports/` directory.