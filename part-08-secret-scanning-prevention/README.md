# Part 8 — Secret Scanning and Pre-Commit Protection

Part 8 is a direct response to real incidents that occurred while building Parts 5–7 of this lab: an Auth0 M2M client secret was exposed in plaintext on two separate occasions, a GitHub personal access token was exposed once, and raw log files containing a real email address and Auth0 user ID were committed to this repository before being caught and removed manually in Part 7. Each of those was caught by a human noticing, after the fact. Part 8 builds the control that should have caught all three automatically, before they ever reached a commit.

## What this demonstrates

- Treating a real security incident in your own environment as a Preparation-phase lesson, not just an embarrassment to move past
- A git pre-commit hook that scans every staged file and blocks the commit if it finds a likely secret or PII
- Pattern-based detection for GitHub tokens, AWS keys, private key blocks, generic secret/token/password assignments, and email addresses
- Placeholder-awareness, so `.env.example` files with empty or obviously-fake values are never flagged
- A scanner that never prints the actual matched value — only a masked preview — so the tool designed to prevent leaks cannot itself become one

## Why this belongs in the lab

A security lab that only builds detection and response for an external attacker, while the actual PII exposures in this project came from the developer's own workflow, is missing its most relevant threat model. Parts 5 and 6 detect and respond to someone else attacking the tenant. Part 8 defends against the far more mundane and, in this project's actual history, far more likely failure mode: a real credential ending up somewhere it shouldn't by accident.

## Architecture

1. `install_hook.py` writes a `pre-commit` hook into `.git/hooks/`, which is not tracked by git and must be installed once per clone.
2. The hook calls `scan_secrets.py` with no arguments, which reads the list of currently staged files via `git diff --cached --name-only`.
3. Each staged file is scanned line by line against a set of patterns for tokens, keys, and email addresses.
4. Any non-placeholder match blocks the commit (exit code 1) and prints the file, line number, and a masked preview — never the real value.
5. A clean scan (exit code 0) allows the commit to proceed as normal.

## Local setup

Run once, from the repository root:

```
python part-08-secret-scanning-prevention/install_hook.py
```

From then on, every `git commit` in this repository is scanned automatically. No further action is needed unless the repository is re-cloned elsewhere.

To scan specific files manually, without committing:

```
python part-08-secret-scanning-prevention/scan_secrets.py path/to/file.py
```

## Evidence

A deliberately staged fake secret was committed to test the hook, then removed. The screenshot shows the hook correctly blocking the commit and printing only a masked preview.

1. [Pre-commit hook blocking a commit with a test secret](evidence/01-hook-blocking-commit.png)

## Security notice

This scanner catches common, recognizable secret formats and email addresses — it is a safety net, not a guarantee. It does not replace reviewing `git status` and `git diff --cached` before committing, and it cannot detect a secret in a format it doesn't recognize (for example, a bare Auth0 client secret with no `SECRET=` prefix pasted into an unrelated file). Rotating any credential that was ever exposed, even briefly, remains the correct response — a scanner prevents the next incident, it does not undo one that already happened.