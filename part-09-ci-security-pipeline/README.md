# Part 9 — Continuous Integration Security Pipeline

Part 8's pre-commit hook has a real limitation: it is local, opt-in per clone, and trivially bypassed with `git commit --no-verify`. Part 9 closes that gap with a GitHub Actions workflow that enforces the same checks server-side, on every push, regardless of what is or isn't installed on the contributor's machine — plus an automated test suite for Part 2's permission logic, so a broken access-control check is caught by CI, not discovered later.

## What this demonstrates

- Defense in depth for a single control: a local hook (Part 8) and a server-side enforcement layer (Part 9) that does not depend on it
- Automated unit testing of security-critical logic, independent of a live Auth0 tenant or network access
- A CI pipeline as a genuine gate, not just a status badge — a failing scan or test blocks the pipeline
- Testing the negative case explicitly: not just "the right permission is granted" but "a different permission is never accidentally granted instead"

## Why two separate jobs

- **`secret-scan`** re-runs Part 8's scanner against every tracked file in the repository, not just staged changes — this catches anything that made it into a commit through a bypassed or never-installed hook.
- **`permission-tests`** runs a pytest suite against Part 2's `require_permission()` function directly, calling the inner checker with fake token payloads. This is deliberate: it tests the actual authorization logic in isolation, in milliseconds, without needing Auth0 credentials in CI at all.

## Architecture

1. `.github/workflows/security-pipeline.yml` triggers on every push and pull request to `main`.
2. The `secret-scan` job checks out the repo and runs `scan_secrets.py` (Part 8) against every file tracked by git, using `git ls-files` rather than the staged-file check the pre-commit hook uses.
3. The `permission-tests` job installs Part 2's dependencies and pytest, then runs `test_auth.py`, which imports `require_permission` from Part 2's `auth.py` and exercises it with constructed token payloads covering: permission granted via `permissions`, permission granted via `scope`, permission denied, an empty token, and a token with a different, unrelated permission.
4. Either job failing fails the pipeline.

## Local setup

Run the tests locally before pushing:

```
cd part-02-fastapi-api
pip install -r requirements.txt pytest
pytest ../part-09-ci-security-pipeline/test_auth.py -v
```

No `.env` or Auth0 credentials are required for this test suite — it never calls the network.

## Evidence

A screenshot of the GitHub Actions run, showing both jobs passing on a real push, is in `evidence/`.

1. [CI pipeline passing — secret scan and permission tests](evidence/01-ci-pipeline-passing.png)

## Security notice

CI secrets scanning re-checks the full repository on every run, which means a secret merged before Part 8 or Part 9 existed would still need to be found and rotated manually — CI catches new incidents going forward, it does not retroactively find or remove anything already in the repository's history.