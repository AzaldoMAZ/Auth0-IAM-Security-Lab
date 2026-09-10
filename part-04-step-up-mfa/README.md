# Part 4 - Step-Up MFA for Sensitive API Access

This stage adds step-up multi-factor authentication to the Auth0, React, and FastAPI lab.

## Security flow

1. A user signs in normally and can call `/api/protected` with `read:protected`.
2. A call to `/api/sensitive` without MFA is denied with HTTP 403.
3. React starts a new Auth0 authorization request containing the MFA `acr_values` value.
4. A Post Login Action requires OTP MFA and adds a namespaced MFA proof claim to the access token.
5. FastAPI requires both `read:sensitive` and the MFA proof claim.

## Controls demonstrated

- Role-based permissions
- Step-up authentication
- OTP multi-factor authentication
- Namespaced access-token claims
- Server-side enforcement
- Negative and positive authorization testing

## Evidence

The `evidence` directory contains 15 ordered screenshots. Personal email addresses and Auth0 user identifiers are redacted. The MFA enrollment QR code is excluded.
