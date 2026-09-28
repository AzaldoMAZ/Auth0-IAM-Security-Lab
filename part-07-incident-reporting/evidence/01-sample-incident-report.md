# Incident Report - 2026-09-28 22:26 UTC

Generated automatically from 7 finding(s) detected in Part 5 and their corresponding response actions from Part 6.

## Executive Summary

- **Findings analyzed:** 7
- **Accounts automatically contained:** 1
- **Findings routed to manual review:** 6
- **NIST SP 800-61r2 phases covered:** Detection & Analysis, Containment, Post-Incident Activity

## Findings

| Technique | Subject (masked) | Severity | NIST Phase | Response Action |
|---|---|---|---|---|
| T1110 - Brute Force | `az**************@gmail.com` | High | Containment | Blocked user google-oauth2|********7673 (az**************@gmail.com) |
| T1098 - Account Manipulation | `google-oauth2|********7673` | High | Detection & Analysis | Alert only - manual review required |
| T1098 - Account Manipulation | `google-oauth2|********7673` | High | Detection & Analysis | Alert only - manual review required |
| T1098 - Account Manipulation | `unknown` | High | Detection & Analysis | Alert only - manual review required |
| T1098 - Account Manipulation | `google-oauth2|********7673` | High | Detection & Analysis | Alert only - manual review required |
| T1098 - Account Manipulation | `unknown` | High | Detection & Analysis | Alert only - manual review required |
| T1098 - Account Manipulation | `google-oauth2|********7673` | High | Detection & Analysis | Alert only - manual review required |

## Recommendations

- 6 finding(s) require human review before this incident can be closed. Automated response deliberately does not act on account-manipulation, impossible-travel, or MFA-bypass findings without confirmation.
- 1 account(s) were automatically blocked. Confirm the block was appropriate, then unblock via the Auth0 Dashboard once verified, or escalate if the activity is confirmed malicious.

---
*This report was generated automatically. Subjects are masked. Raw logs are retained separately under access control and are not included here.*