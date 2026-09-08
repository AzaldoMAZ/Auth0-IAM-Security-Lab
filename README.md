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

