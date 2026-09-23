"""
respond.py
Reads findings from Part 5's logs/alerts.json and acts on them:
  - Sends a webhook alert for every finding (if WEBHOOK_URL is set).
  - For brute-force findings (T1110), looks the user up by email via
    the Auth0 Management API and blocks the account (containment).
  - All other techniques are alerted but flagged for manual review --
    auto-blocking on impossible travel or a privilege change is too
    aggressive for an automated system to decide alone.
  - Every action taken (or skipped) is recorded in logs/response_log.json
    so the response itself has an audit trail.

Safety: DRY_RUN defaults to true. Set DRY_RUN=false in .env to allow
respond.py to actually call the Management API and block a user.

Requires the M2M application to additionally have `read:users` and
`update:users` scopes authorized (on top of Part 5's read:logs /
read:logs_users).
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["M2M_CLIENT_ID"]
CLIENT_SECRET = os.environ["M2M_CLIENT_SECRET"]
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "").strip()
DRY_RUN = os.environ.get("DRY_RUN", "true").strip().lower() != "false"

ALERTS_PATH = (
    Path(__file__).parent.parent
    / "part-05-audit-logging-anomaly-detection"
    / "logs"
    / "alerts.json"
)
RESPONSE_LOG_PATH = Path(__file__).parent / "logs" / "response_log.json"

AUTO_CONTAIN_TECHNIQUES = ("T1110",)  # Brute Force only


def get_management_token() -> str:
    resp = requests.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
            "grant_type": "client_credentials",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def find_user_id_by_email(token: str, email: str) -> str | None:
    resp = requests.get(
        f"https://{AUTH0_DOMAIN}/api/v2/users-by-email",
        headers={"Authorization": f"Bearer {token}"},
        params={"email": email},
        timeout=10,
    )
    resp.raise_for_status()
    results = resp.json()
    return results[0]["user_id"] if results else None


def block_user(token: str, user_id: str) -> None:
    resp = requests.patch(
        f"https://{AUTH0_DOMAIN}/api/v2/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"blocked": True},
        timeout=10,
    )
    resp.raise_for_status()


def send_webhook_alert(alert: dict) -> bool:
    if not WEBHOOK_URL:
        return False
    message = (
        f":rotating_light: *{alert['technique']}*\n"
        f"Subject: `{alert['subject']}`\n"
        f"NIST phase: {alert.get('nist_phase', 'Detection & Analysis')}\n"
        f"Recommended action: {alert.get('recommended_action', 'Review manually.')}"
    )
    try:
        resp = requests.post(WEBHOOK_URL, json={"text": message}, timeout=10)
        return resp.status_code < 300
    except requests.RequestException:
        return False


def load_alerts() -> list[dict]:
    if not ALERTS_PATH.exists():
        raise FileNotFoundError(
            f"No alerts found at {ALERTS_PATH}. Run Part 5's fetch_logs.py "
            "and detect_anomalies.py first."
        )
    return json.loads(ALERTS_PATH.read_text())


def load_response_log() -> list[dict]:
    if RESPONSE_LOG_PATH.exists():
        return json.loads(RESPONSE_LOG_PATH.read_text())
    return []


def alert_time_marker(alert: dict) -> str:
    # Brute-force findings carry a window_end; other techniques carry a
    # plain date. Falling back to "" only happens if neither is present.
    return alert.get("window_end") or alert.get("date") or ""


def already_handled(log: list[dict], alert: dict) -> bool:
    key = (alert["technique"], alert["subject"], alert_time_marker(alert))
    for entry in log:
        entry_key = (
            entry.get("technique"),
            entry.get("subject"),
            entry.get("alert_time_marker", ""),
        )
        if entry_key == key:
            return True
    return False


def handle_alert(token: str | None, alert: dict) -> dict:
    technique_code = alert["technique"].split(" - ")[0]
    webhook_sent = send_webhook_alert(alert)
    marker = alert_time_marker(alert)

    if technique_code not in AUTO_CONTAIN_TECHNIQUES:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "technique": alert["technique"],
            "subject": alert["subject"],
            "alert_time_marker": marker,
            "action_taken": "Alert only - manual review required",
            "nist_phase": "Detection & Analysis",
            "webhook_sent": webhook_sent,
            "dry_run": DRY_RUN,
        }

    # Brute force -> attempt containment
    subject = alert["subject"]
    if DRY_RUN:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "technique": alert["technique"],
            "subject": subject,
            "alert_time_marker": marker,
            "action_taken": f"[DRY RUN] Would block user for: {subject}",
            "nist_phase": "Containment",
            "webhook_sent": webhook_sent,
            "dry_run": True,
        }

    try:
        user_id = find_user_id_by_email(token, subject)
        if not user_id:
            action = f"Could not resolve user_id for {subject}; no action taken"
        else:
            block_user(token, user_id)
            action = f"Blocked user {user_id} ({subject})"
    except requests.RequestException as exc:
        action = f"Containment failed: {exc}"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "technique": alert["technique"],
        "subject": subject,
        "alert_time_marker": marker,
        "action_taken": action,
        "nist_phase": "Containment",
        "webhook_sent": webhook_sent,
        "dry_run": False,
    }


def main() -> None:
    alerts = load_alerts()
    response_log = load_response_log()

    token = None
    if not DRY_RUN:
        token = get_management_token()

    new_entries = []
    for alert in alerts:
        if already_handled(response_log, alert):
            continue
        entry = handle_alert(token, alert)
        new_entries.append(entry)
        print(f"[{entry['technique']}] {entry['action_taken']}")

    if not new_entries:
        print("No new alerts to respond to.")
        return

    response_log.extend(new_entries)
    RESPONSE_LOG_PATH.parent.mkdir(exist_ok=True)
    RESPONSE_LOG_PATH.write_text(json.dumps(response_log, indent=2))
    print(f"\n{len(new_entries)} response(s) logged -> {RESPONSE_LOG_PATH}")
    if DRY_RUN:
        print("DRY_RUN is on - no accounts were actually blocked. Set DRY_RUN=false in .env to enable containment.")


if __name__ == "__main__":
    main()