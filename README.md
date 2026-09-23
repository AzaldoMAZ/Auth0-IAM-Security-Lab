# Auth0 IAM and API Security Lab

A two-part identity and access management lab demonstrating automated role assignment and permission-protected API access with Auth0.

## Project progression

### Part 1 — Automatic default role assignment

An Auth0 Post Login Action checks whether a user already has a role. If not, it uses the Auth0 Management API to assign a configured default role.

[View Part 1](part-01-default-role-action/README.md)

### Part 2 — Protecting a FastAPI API

A Python FastAPI application validates Auth0 RS256 access tokens and enforces the `read:protected` permission on a protected endpoint.

[View Part 2](part-02-fastapi-api/README.md)

## Security controls demonstrated

- OAuth 2.0 bearer-token authorization
- RS256 JWT validation through Auth0 JWKS
- Issuer, audience and expiration validation
- Permission-based API access
- Least-privilege Management API permissions
- Secure environment-variable handling
- Secrets and access tokens excluded from Git

## Repository structure

```text
.
├── part-01-default-role-action/
│   ├── action.js
│   ├── README.md
│   └── evidence/
├── part-02-fastapi-api/
│   ├── auth.py
│   ├── main.py
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
├── .gitignore
└── README.md
```

## Security notice

Never commit `.env` files, client secrets, passwords or bearer tokens. Evidence should be reviewed and redacted before publication.



## Part 3 — JavaScript user login and protected API access

A React single-page application now authenticates human users through Auth0 Universal Login using Authorization Code Flow with PKCE. It requests an access token for the Part 2 FastAPI audience and calls the `read:protected` endpoint with a Bearer token.

[View Part 3](part-03-react-auth0-client/README.md)



## Part 4 - Step-up MFA for sensitive API access 

Part 4 extends the React and FastAPI integration with step-up OTP MFA. Normal tokens can access the standard protected endpoint, while the sensitive endpoint requires the `read:sensitive` permission and a namespaced MFA proof claim issued during an MFA-requested authorization flow.

Errors, ordinary permission checks, and successful post-MFA access are documented with 15 ordered, redacted screenshots in `part-04-step-up-mfa/evidence`.

part-05-audit-logging-anomaly-detection/README.md
markdown
# Part 5 — Centralized Audit Logging and Anomaly Detection

Part 5 pulls tenant authentication logs from the Auth0 Management API and runs them through a detection engine that flags patterns associated with credential-based attacks, each mapped to a MITRE ATT&CK technique and a NIST SP 800-61r2 incident-response phase.

## What this demonstrates

- A Machine-to-Machine application scoped to least-privilege Management API access (`read:logs`, `read:logs_users`)
- Programmatic retrieval of Auth0 tenant logs via `GET /api/v2/logs`
- Pattern-based detection across four independent techniques
- Findings mapped to MITRE ATT&CK technique IDs
- Findings triaged against the NIST SP 800-61r2 incident-response lifecycle
- A recommended remediation attached to every finding
- Secure environment-variable management, consistent with Parts 1–4

## Detections implemented

| Pattern | MITRE ATT&CK | Trigger |
|---|---|---|
| Repeated failed logins | T1110 — Brute Force | 5 or more failed logins for one user within a 10-minute window |
| Login from a new country shortly after another | T1078 — Valid Accounts (impossible travel) | Country changes between two successful logins within 30 minutes |
| Role or permission change via the Management API | T1098 — Account Manipulation | A `sapi` log event whose description references a role or permission |
| Failed MFA challenge | T1556.006 — MFA Interception/Bypass | An `fmfa` or `gd_recovery_failed` log event |

## Architecture

1. `fetch_logs.py` authenticates to the Auth0 Management API using a client-credentials grant.
2. It pages through `GET /api/v2/logs`, sorted oldest to newest, and writes the results to `logs/raw_logs.json`.
3. `detect_anomalies.py` loads the raw logs and evaluates each of the four detection functions against them.
4. Each finding is written to `logs/alerts.json` with its MITRE technique, subject, NIST phase, and a recommended action.
5. A summary of findings is printed to the terminal.

## Local setup

Create a Machine-to-Machine application in the Auth0 Dashboard, authorized for the Management API with `read:logs` and `read:logs_users`.

Copy `.env.example` to `.env`:

AUTH0_DOMAIN=your-auth0-domain.auth0.com
M2M_CLIENT_ID=your-m2m-client-id
M2M_CLIENT_SECRET=your-m2m-client-secret


Install dependencies and run:

python -m pip install -r requirements.txt
python fetch_logs.py
python detect_anomalies.py


## Evidence

Redacted screenshots of a real detection run — including a live, deliberately-triggered brute-force test against the Part 3 login client that was correctly captured and flagged — are in `evidence/`.

1. [Detection run — full findings output](evidence/01-detection-run.png)

Email addresses and Auth0 user identifiers are redacted from all published evidence.

## Security notice

Never commit `.env`, client secrets, or unredacted log exports — `logs/raw_logs.json` and `logs/alerts.json` contain real user emails and identifiers and must never be committed. Both are excluded via `.gitignore`.
part-06-automated-incident-response/README.md
markdown
# Part 6 — Automated Incident Response

Part 6 consumes Part 5's findings directly and acts on them, moving the lab from NIST SP 800-61r2 Detection & Analysis into Containment. High-confidence findings trigger automatic containment; lower-confidence or higher-risk findings are alerted but deliberately left for human review.

## What this demonstrates

- Consuming another component's output (`part-05-audit-logging-anomaly-detection/logs/alerts.json`) as a pipeline input rather than duplicating detection logic
- Scope-limited Management API automation (`read:users`, `update:users`, in addition to Part 5's `read:logs`, `read:logs_users`)
- Automated account containment via `PATCH /api/v2/users/{id}`
- Deliberate non-automation of ambiguous findings, with a stated security rationale
- A `DRY_RUN` safety switch that simulates every action before real containment is permitted
- A full audit trail of every action taken, or explicitly not taken
- Idempotent response handling, so a repeated run does not reprocess an already-handled finding

## Containment policy

| Technique | Response |
|---|---|
| T1110 — Brute Force | Automated: user is located by email and blocked via the Management API |
| T1078 — Valid Accounts (impossible travel) | Alert only — routed to manual review |
| T1098 — Account Manipulation | Alert only — routed to manual review |
| T1556.006 — MFA Interception/Bypass | Alert only — routed to manual review |

Only brute force is auto-contained. A brute-force finding is high-confidence and cheap to reverse — the account is unblocked once verified. Impossible travel can be a false positive from a VPN or a new device; a permission change may be entirely legitimate administrative activity. An automated system should not decide those cases alone, so this lab draws that line explicitly rather than automating everything it technically could.

## Architecture

1. `respond.py` loads `../part-05-audit-logging-anomaly-detection/logs/alerts.json`.
2. Each finding not already present in `logs/response_log.json` is processed.
3. An optional webhook notification is sent for every finding.
4. Brute-force findings resolve the subject's email to a `user_id` via `GET /api/v2/users-by-email`, then block the account via `PATCH /api/v2/users/{user_id}`.
5. All other techniques are logged as "alert only — manual review required."
6. Every outcome — containment, alert-only, or failure — is appended to `logs/response_log.json` with a timestamp.

## Local setup

Authorize the same Machine-to-Machine application used in Part 5 for two additional Management API scopes: `read:users` and `update:users`.

Copy `.env.example` to `.env`:

AUTH0_DOMAIN=your-auth0-domain.auth0.com
M2M_CLIENT_ID=your-m2m-client-id
M2M_CLIENT_SECRET=your-m2m-client-secret
WEBHOOK_URL=
DRY_RUN=true


Install dependencies and run Part 5 first, so fresh findings exist:

python -m pip install -r requirements.txt
cd ../part-05-audit-logging-anomaly-detection
python fetch_logs.py
python detect_anomalies.py
cd ../part-06-automated-incident-response
python respond.py


Review the dry-run output and `logs/response_log.json`. Set `DRY_RUN=false` in `.env` only once ready to permit a real containment action, then run again.

## Evidence

A live brute-force attempt against the Part 3 login client was used to verify the full pipeline end-to-end, with `DRY_RUN=false`.

1. [respond.py source](evidence/05-respond-py-code.png)
2. [.env with DRY_RUN=false, all secrets redacted](evidence/04-env-dry-run-false-redacted.png)
3. [Terminal output of the response run](evidence/03-respond-py-terminal-output.png)
4. [Auth0 Dashboard confirming the account was blocked](evidence/01-user-blocked-dashboard.png)
5. [Resulting "account has been blocked" message on next login attempt](evidence/02-login-blocked-message.png)

Email addresses, client IDs, and client secrets are redacted from all published evidence.

## Security notice

Never commit `.env`, client secrets, or unredacted `logs/response_log.json` — action logs may contain real user emails. `DRY_RUN` defaults to `true`; disabling it enables a real, live account block against the configured Auth0 tenant. Review every containment action logged before assuming it was appropriate — automation flags findings for response, it does not replace human judgment on ambiguous ones.
