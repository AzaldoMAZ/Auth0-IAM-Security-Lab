# Part 6 — Automated Incident Response (Containment & Alerting)

Part 5 detects suspicious activity and writes it to a file that a human
has to go read. Part 6 closes that gap: it reads Part 5's findings and
**acts** on them automatically, moving the lab from the NIST SP 800-61r2
*Detection & Analysis* phase into *Containment*.

## What it does

1. Reads `../part-05-audit-logging-anomaly-detection/logs/alerts.json`.
2. Sends a webhook notification for every finding (optional — skipped
   silently if `WEBHOOK_URL` isn't set).
3. For **brute-force findings only** (MITRE T1110), looks the user up
   by email via the Auth0 Management API and blocks the account.
4. Every other technique (impossible travel, account manipulation, MFA
   bypass) is alerted but explicitly left for manual review — an
   automated system deciding to block a session or revert a permission
   change on its own is a much bigger blast radius than blocking one
   brute-forced account, so this lab draws that line deliberately.
5. Logs every action (or non-action) taken to `logs/response_log.json`,
   with a timestamp and the reasoning, so the response process itself
   has an audit trail.

## Why only brute force gets auto-contained

Automating a response is not "automate everything you can detect." A
brute-force finding is high-confidence and low-cost to reverse (unblock
the account once verified). Impossible travel could be a false positive
from a VPN; a permission change might be entirely legitimate. Knowing
which findings are safe to act on automatically — and leaving the rest
for a human — is itself part of the security design, not a limitation
of the script.

## Safety: DRY_RUN

`respond.py` defaults to `DRY_RUN=true`. In this mode it prints exactly
what it *would* do — including which account it would block — without
calling the Management API's write endpoints. Only set `DRY_RUN=false`
once you've reviewed a dry run and are ready to see a real block happen.

## Setup

1. In the Auth0 Dashboard, open the same M2M application used in Part 5
   (`Audit-Log-Reader-M2M-v2`) and authorize it for two more scopes:
   `read:users` and `update:users`.
2. Copy `.env.example` to `.env` and fill in the same Domain/Client
   ID/Secret as Part 5, plus optionally `WEBHOOK_URL`.
3. `pip install -r requirements.txt`
4. Make sure Part 5 has fresh findings: run its `fetch_logs.py` and
   `detect_anomalies.py` first.
5. `python respond.py` (dry run by default).
6. Review the printed actions and `logs/response_log.json`.
7. When ready, set `DRY_RUN=false` in `.env` and run again to see a
   real containment action execute.

## Unblocking a test account

After testing containment for real, unblock your test user:
Auth0 Dashboard → User Management → Users → select the user →
Actions menu → **Unblock user**.

## Evidence

Redacted screenshots of a dry run, a real containment action, and the
resulting `response_log.json` go in `evidence/`, following the same
numbering convention as Parts 4 and 5.

## Notes / next steps

- A production version would run this continuously (triggered by a Log
  Stream event or a scheduled job) rather than on-demand.
- Containment scope could grow carefully over time — e.g. auto-forcing
  a password reset instead of a full block, once there's confidence in
  the false-positive rate.