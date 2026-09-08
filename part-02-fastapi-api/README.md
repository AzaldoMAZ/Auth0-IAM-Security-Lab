# Auth0 FastAPI Lab

A security-focused Python API demonstrating authentication and permission-based authorization using FastAPI and Auth0.

## Project Overview

This project demonstrates how a FastAPI application can validate Auth0 JSON Web Tokens (JWTs) and protect API endpoints.

The application includes:

- A public endpoint accessible without authentication
- A protected endpoint requiring a valid Auth0 access token
- RS256 JWT signature validation using Auth0's JWKS endpoint
- Issuer and audience validation
- Permission-based authorization using `read:protected`
- Secure environment-variable management

## Authentication Flow

1. A client requests an access token from Auth0.
2. Auth0 issues an RS256-signed JWT for this API.
3. The client sends the token using the `Authorization: Bearer <token>` header.
4. FastAPI obtains Auth0's public signing key from its JWKS endpoint.
5. FastAPI validates the token's signature, issuer, audience and expiration.
6. The protected endpoint checks for the `read:protected` permission.
7. Access is granted or denied.

## API Endpoints

| Method | Endpoint | Access |
|---|---|---|
| GET | `/` | Public health check |
| GET | `/api/public` | Public |
| GET | `/api/protected` | Valid token and `read:protected` permission required |
| GET | `/docs` | Swagger UI documentation |

## Technologies

- Python
- FastAPI
- Auth0
- PyJWT
- OAuth 2.0
- JSON Web Tokens
- RS256 asymmetric signing
- Swagger UI

## Local Setup

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd Auth0-FastAPI-Lab
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate it on Windows

```cmd
.venv\Scripts\activate
```

### 4. Install the dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure the environment

Copy `.env.example` to `.env`:

```cmd
copy .env.example .env
```

Update `.env` with your Auth0 API settings:

```env
AUTH0_DOMAIN=your-auth0-domain.auth0.com
AUTH0_AUDIENCE=https://auth0-fastapi-lab-api
AUTH0_ALGORITHMS=RS256
```

Do not add client secrets or access tokens to this file.

### 6. Start the development server

```bash
fastapi dev main.py
```

Open the interactive documentation:

```text
http://127.0.0.1:8000/docs
```

## Expected Security Responses

| Status | Meaning |
|---|---|
| `200 OK` | Authentication and authorization succeeded |
| `401 Unauthorized` | No token, invalid token or expired token |
| `403 Forbidden` | Valid token without the required permission |

## Security Practices Demonstrated

- Secrets and local environment files are excluded from Git
- Tokens are verified using Auth0 public signing keys
- The expected token issuer and audience are validated
- Expired and invalid tokens are rejected
- Permissions are checked before protected resources are returned
- No client secret is stored in the application source code

## Important Security Notice

Never commit any of the following:

- `.env`
- Client secrets
- Access tokens
- Screenshots containing bearer tokens
- Private credentials

## Disclaimer

This project is an educational IAM and API-security lab. It is not a production-ready authentication platform.
