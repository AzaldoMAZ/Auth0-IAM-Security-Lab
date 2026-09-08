# Part 1 — Automatic Default Role Assignment

This section demonstrates an Auth0 Post Login Action that assigns a default role to a user who does not already have one.

## What was configured

- A custom Auth0 API
- A `Default-role` role
- A Machine-to-Machine application with least-privilege Management API access
- An Auth0 Post Login Action using the Auth0 Node.js SDK
- Action secrets for the tenant, application and role identifiers
- The Action attached to the Post Login flow

## Least-privilege permissions

The Machine-to-Machine application received only:

- `read:roles`
- `update:users`

## Evidence

1. [Custom API settings](evidence/01-custom-api-settings.png)
2. [Default role created](evidence/02-default-role-created.png)
3. [Least-privilege API access](evidence/03-least-privilege-api-access.png)
4. [Action code and secret names](evidence/04-action-code-and-secrets.png)
5. [Auth0 dependency](evidence/05-auth0-dependency.png)
6. [Post Login flow](evidence/06-post-login-flow.png)
7. [Successful Action test](evidence/07-successful-action-test.png)
8. [Default role assigned](evidence/08-default-role-assigned.png)

The evidence images are redacted and do not expose client secrets or access tokens.

