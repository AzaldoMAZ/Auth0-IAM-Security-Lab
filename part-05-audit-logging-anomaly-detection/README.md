# Part 5 — Centralized Audit Logging & Anomaly Detection

Parts 1–4 built and hardened access control (role assignment, token
validation, human login, step-up MFA). Part 5 adds the piece that
control alone doesn't give you: **visibility into when that access
control is being tested or abused.**

Tenant log events are pulled from the Auth0 Management API and run
through a lightweight detection engine that flags patterns associated
with credential-based attacks, mapped to MITRE ATT&CK techniques and
triaged along the NIST SP 800-61r2 incident response lifecycle.

## Architecture
Auth0 tenant logs (Management API)
│
▼
fetch_logs.py ──► logs/raw_logs.json
│
▼
detect_anomalies.py ──► logs/alerts.json
│
▼
Findings mapped to MITRE ATT&CK + NIST 800-61r2 phase


## Detections implemented

| Pattern | MITRE ATT&CK | Trigger |
|---|---|---|
| Repeated failed logins in a short window | T1110 – Brute Force | ≥5 failed logins for one user within 10 minutes |
| Login from a new country shortly after another country | T1078 – Valid Accounts (impossible travel) | Country changes between two successful logins within 30 minutes |
| Role/permission change via Management API | T1098 – Account Manipulation | `sapi` log event whose description references role/permission |
| Failed MFA challenge | T1556.006 – MFA Interception/Bypass | `fmfa` / `gd_recovery_failed` log event |

Every finding is tagged with the corresponding **NIST SP 800-61r2**
incident-response phase (currently all land in Detection & Analysis)
and a recommended next action, e.g. rate-limiting an account,
forcing step-up MFA, or reverting an unauthorized permission change.

## Setup

1. In the Auth0 Dashboard, create a Machine-to-Machine application
   authorized for the Management API with `read:logs` and
   `read:logs_users` scopes.
2. Copy `.env.example` to `.env` and fill in `AUTH0_DOMAIN`,
   `M2M_CLIENT_ID`, `M2M_CLIENT_SECRET`.
3. `pip install -r requirements.txt`
4. `python fetch_logs.py`
5. `python detect_anomalies.py`

## Evidence

Redacted screenshots of a detected brute-force run and a detected
role-change alert go in `evidence/`, following the same
numbered-screenshot convention as Part 4.

## Notes / next steps

- Thresholds (`BRUTE_FORCE_THRESHOLD`, time windows) are intentionally
  conservative for a lab demo — tune per environment.
- A production version would stream logs continuously via an
  Auth0 Log Stream rather than polling, and forward alerts to a SIEM
  or Slack/webhook.