"""
generate_report.py
Reads Part 5's findings (alerts.json) and Part 6's response log
(response_log.json) and produces a single, human-readable incident
report in Markdown -- the Post-Incident Activity phase of the NIST
SP 800-61r2 lifecycle, closing the loop that Parts 5 and 6 opened.

All subjects (emails, Auth0 user IDs) are masked before being written
to the report -- including inside free-text fields like a response's
action_taken description, not just the structured "subject" field.
These reports are meant to be shareable -- with a manager, in a
portfolio, in an audit -- so redaction happens automatically rather
than depending on a human doing it afterward.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ALERTS_PATH = (
    Path(__file__).parent.parent
    / "part-05-audit-logging-anomaly-detection"
    / "logs"
    / "alerts.json"
)
RESPONSE_LOG_PATH = (
    Path(__file__).parent.parent
    / "part-06-automated-incident-response"
    / "logs"
    / "response_log.json"
)
REPORTS_DIR = Path(__file__).parent / "reports"

EMAIL_RE = re.compile(r"^[^@]+@[^@]+$")
EMAIL_IN_TEXT_RE = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+")
OAUTH_IN_TEXT_RE = re.compile(r"[a-zA-Z0-9_-]+\|[a-zA-Z0-9]+")


def mask_subject(subject: str) -> str:
    """Mask a single email or Auth0 user_id value."""
    if EMAIL_RE.match(subject):
        local, domain = subject.split("@", 1)
        visible = local[:2] if len(local) > 2 else local[:1]
        return f"{visible}{'*' * max(len(local) - len(visible), 3)}@{domain}"

    if "|" in subject:
        provider, identifier = subject.split("|", 1)
        tail = identifier[-4:] if len(identifier) > 4 else identifier
        return f"{provider}|{'*' * 8}{tail}"

    if subject == "unknown":
        return subject

    if len(subject) > 4:
        return f"{subject[:2]}{'*' * (len(subject) - 4)}{subject[-2:]}"
    return "*" * len(subject)


def mask_text(text: str) -> str:
    """Mask any email or Auth0 user_id that appears inside a free-text
    string, such as a response log's action_taken description."""
    text = EMAIL_IN_TEXT_RE.sub(lambda m: mask_subject(m.group(0)), text)
    text = OAUTH_IN_TEXT_RE.sub(lambda m: mask_subject(m.group(0)), text)
    return text


def load_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def match_response(alert: dict, responses: list[dict]) -> dict | None:
    marker = alert.get("window_end") or alert.get("date") or ""
    for r in responses:
        if (
            r.get("technique") == alert.get("technique")
            and r.get("subject") == alert.get("subject")
            and r.get("alert_time_marker", "") == marker
        ):
            return r
    return None


def severity_for(technique: str) -> str:
    if technique.startswith("T1110") or technique.startswith("T1098"):
        return "High"
    if technique.startswith("T1078"):
        return "Medium"
    return "Low"


def build_report(alerts: list[dict], responses: list[dict]) -> str:
    now = datetime.now(timezone.utc)
    lines = []

    lines.append(f"# Incident Report - {now.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")
    lines.append(
        f"Generated automatically from {len(alerts)} finding(s) detected in "
        "Part 5 and their corresponding response actions from Part 6."
    )
    lines.append("")

    contained = sum(
        1 for a in alerts
        if (r := match_response(a, responses)) and r.get("nist_phase") == "Containment"
        and "Blocked" in r.get("action_taken", "")
    )
    manual_review = sum(
        1 for a in alerts
        if (r := match_response(a, responses)) and "manual review" in r.get("action_taken", "")
    )

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Findings analyzed:** {len(alerts)}")
    lines.append(f"- **Accounts automatically contained:** {contained}")
    lines.append(f"- **Findings routed to manual review:** {manual_review}")
    lines.append(
        "- **NIST SP 800-61r2 phases covered:** Detection & Analysis, "
        "Containment, Post-Incident Activity"
    )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| Technique | Subject (masked) | Severity | NIST Phase | Response Action |")
    lines.append("|---|---|---|---|---|")
    for alert in alerts:
        response = match_response(alert, responses)
        masked = mask_subject(alert.get("subject", "unknown"))
        severity = severity_for(alert["technique"])
        raw_action = response["action_taken"] if response else "Not yet processed by Part 6"
        action = mask_text(raw_action)
        phase = response["nist_phase"] if response else alert.get("nist_phase", "Detection & Analysis")
        lines.append(
            f"| {alert['technique']} | `{masked}` | {severity} | {phase} | {action} |"
        )
    lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    if manual_review > 0:
        lines.append(
            f"- {manual_review} finding(s) require human review before this "
            "incident can be closed. Automated response deliberately does not "
            "act on account-manipulation, impossible-travel, or MFA-bypass "
            "findings without confirmation."
        )
    if contained > 0:
        lines.append(
            f"- {contained} account(s) were automatically blocked. Confirm "
            "the block was appropriate, then unblock via the Auth0 Dashboard "
            "once verified, or escalate if the activity is confirmed malicious."
        )
    if not alerts:
        lines.append("- No findings in this run. No action required.")
    lines.append("")

    lines.append("---")
    lines.append(
        "*This report was generated automatically. Subjects are masked. "
        "Raw logs are retained separately under access control and are not "
        "included here.*"
    )

    return "\n".join(lines)


def main() -> None:
    alerts = load_json(ALERTS_PATH)
    responses = load_json(RESPONSE_LOG_PATH)

    if not alerts:
        print(f"No alerts found at {ALERTS_PATH}. Run Parts 5 and 6 first.")
        return

    report = build_report(alerts, responses)

    REPORTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_path = REPORTS_DIR / f"incident-report-{timestamp}.md"
    out_path.write_text(report, encoding="utf-8")

    print(f"Report generated -> {out_path}")
    print(f"({len(alerts)} findings, {len(responses)} logged responses)")


if __name__ == "__main__":
    main()