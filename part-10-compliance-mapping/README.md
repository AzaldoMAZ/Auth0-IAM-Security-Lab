# Part 10 - Compliance Controls Mapping

Parts 1-9 build and demonstrate real security controls. Part 10 does something different: it translates each of those technical controls into the language a compliance reviewer, auditor, or GRC analyst actually uses - cross-referenced against three frameworks commonly required in job postings and real audits. Building a control and being able to state which requirement it satisfies, in which framework, are two different skills. This part demonstrates the second one.

## What this demonstrates

- Crosswalking a single implemented control across multiple industry frameworks, the way GRC work is actually done (an auditor rarely asks about only one framework)
- Distinguishing implementation (what Parts 1-9 built) from assurance (whether it has been formally tested, documented, and reviewed - it has not)
- Explicit scoping: naming what this lab does *not* cover is as important to a reviewer as what it does
- Writing for a non-technical audience without losing technical accuracy

## Frameworks referenced

- **NIST CSF 2.0** - the Cybersecurity Framework's six functions: Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC)
- **ISO/IEC 27001:2022 Annex A** - the standard's control reference numbers
- **CIS Controls v8** - the Center for Internet Security's prioritized safeguards

## Controls matrix

| Part | Control implemented | NIST CSF 2.0 | ISO/IEC 27001:2022 Annex A | CIS Controls v8 |
|---|---|---|---|---|
| 1 | Automatic least-privilege role assignment on user creation | PR.AA-05 | A.5.18 (Access rights) | 5.1 (Inventory of accounts) |
| 2 | Per-endpoint permission enforcement on API access | PR.AA-05, PR.AA-01 | A.8.3 (Access restriction) | 6.8 (Role-based access control) |
| 3 | Authenticated user login via OAuth2 Authorization Code + PKCE | PR.AA-03 | A.8.5 (Secure authentication) | 6.2 (Access revoking process) |
| 4 | Step-up multi-factor authentication for sensitive operations | PR.AA-03 | A.8.5 (Secure authentication) | 6.3, 6.4 (MFA for applications/admin access) |
| 5 | Continuous log analysis and anomaly detection | DE.CM-01, DE.CM-03 | A.8.16 (Monitoring activities) | 8.5, 13.1 (Audit logs, centralized alerting) |
| 6 | Automated incident containment (account blocking) | RS.MI-01 | A.5.26 (Response to incidents) | 17.4, 17.9 (Incident response process, thresholds) |
| 7 | Post-incident reporting with automatic PII masking | RS.MA-05 | A.5.27, A.5.28 (Lessons learned, evidence collection) | 17.8 (Post-incident review) |
| 8 | Pre-commit scanning to prevent secret and PII leakage | PR.DS-01 | A.8.12 (Data leakage prevention) | 3.10, 3.11 (Sensitive data protection) |
| 9 | CI-enforced secret scanning and automated permission testing | PR.PS-06 | A.8.25, A.8.28 (Secure development lifecycle, secure coding) | 16.1 (Secure application development process) |

## Gap analysis - what this lab does not cover

A reviewer's first question after seeing a matrix like the one above should be "what's missing?" Naming the gaps directly is more credible than implying completeness:

- **Asset and data inventory** - this lab has no formal register of what data is processed or where it lives, beyond what appears in the code itself.
- **Third-party and vendor risk management** - Auth0 itself is a critical vendor dependency with no documented risk assessment.
- **Business continuity and disaster recovery** - no backup, restoration, or continuity plan exists for any component.
- **Security awareness and training** - there is no human-factors control in this lab; every control here is technical.
- **Formal risk assessment** - controls were built reactively (including Part 8, built directly after a real incident) rather than from a documented risk register.
- **Independent audit or penetration testing** - every claim in this matrix is a self-assessment by the person who built the system, which is exactly the kind of assessment a real audit exists to challenge.

## Why this matters

A technical portfolio shows what someone can build. A controls matrix with an honest gap analysis shows something a hiring manager in compliance, GRC, or business analysis can evaluate directly: whether the candidate can reason about coverage, map work to requirements, and, critically, recognize the limits of their own claims rather than overstate them.

## Security notice

This mapping is a self-assessment for portfolio and learning purposes. It has not been reviewed by a qualified auditor and should not be represented as a certification, attestation, or formal compliance statement for any framework listed above.