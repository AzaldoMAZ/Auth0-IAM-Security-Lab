"""
detect_anomalies.py
Reads logs/raw_logs.json (Auth0 tenant logs) and flags suspicious
patterns, each mapped to a MITRE ATT&CK technique. Writes findings to
logs/alerts.json and prints an incident-response-style summary aligned
to the NIST SP 800-61r2 lifecycle (Detection & Analysis phase).

Detections:
  1. Brute force            -> T1110 (Brute Force)
  2. Impossible travel      -> T1078 (Valid Accounts)
  3. Privilege escalation   -> T1098 (Account Manipulation)
  4. MFA bypass attempt     -> T1556.006 (MFA interception/bypass)
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

LOGS_PATH = Path(__file__).parent / "logs" / "raw_logs.json"
ALERTS_PATH = Path(__file__).parent / "logs" / "alerts.json"

# Auth0 log type codes: https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes
FAILED_LOGIN_TYPES = {"f", "fp", "fu", "fc", "fco"}
SUCCESS_LOGIN_TYPES = {"s", "scoa"}
ROLE_CHANGE_TYPES = {"sapi"}  # successful Management API call (role/permission writes)
MFA_FAIL_TYPES = {"fmfa", "gd_recovery_failed"}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
IMPOSSIBLE_TRAVEL_WINDOW = timedelta(minutes=30)


def load_logs() -> list[dict]:
    return json.loads(LOGS_PATH.read_text())


def parse_time(entry: dict) -> datetime:
    return datetime.fromisoformat(entry["date"].replace("Z", "+00:00"))


def detect_brute_force(logs: list[dict]) -> list[dict]:
    alerts = []
    by_user: dict[str, list[dict]] = defaultdict(list)
    for entry in logs:
        if entry.get("type") in FAILED_LOGIN_TYPES:
            key = entry.get("user_id") or entry.get("user_name") or entry.get("ip", "unknown")
            by_user[key].append(entry)

    for key, attempts in by_user.items():
        attempts.sort(key=parse_time)
        for i in range(len(attempts) - BRUTE_FORCE_THRESHOLD + 1):
            window = attempts[i : i + BRUTE_FORCE_THRESHOLD]
            if parse_time(window[-1]) - parse_time(window[0]) <= BRUTE_FORCE_WINDOW:
                alerts.append(
                    {
                        "technique": "T1110 - Brute Force",
                        "subject": key,
                        "count": len(window),
                        "window_start": window[0]["date"],
                        "window_end": window[-1]["date"],
                        "nist_phase": "Detection & Analysis",
                        "recommended_action": "Rate-limit / lock account; review source IP reputation.",
                    }
                )
                break
    return alerts


def detect_impossible_travel(logs: list[dict]) -> list[dict]:
    alerts = []
    by_user: dict[str, list[dict]] = defaultdict(list)
    for entry in logs:
        if entry.get("type") in SUCCESS_LOGIN_TYPES and entry.get("location_info"):
            key = entry.get("user_id") or entry.get("user_name", "unknown")
            by_user[key].append(entry)

    for key, events in by_user.items():
        events.sort(key=parse_time)
        for prev, curr in zip(events, events[1:]):
            prev_country = prev["location_info"].get("country_code")
            curr_country = curr["location_info"].get("country_code")
            if (
                prev_country
                and curr_country
                and prev_country != curr_country
                and parse_time(curr) - parse_time(prev) <= IMPOSSIBLE_TRAVEL_WINDOW
            ):
                alerts.append(
                    {
                        "technique": "T1078 - Valid Accounts (impossible travel)",
                        "subject": key,
                        "from_country": prev_country,
                        "to_country": curr_country,
                        "minutes_apart": (parse_time(curr) - parse_time(prev)).seconds // 60,
                        "nist_phase": "Detection & Analysis",
                        "recommended_action": "Force step-up MFA / session revocation; verify with user.",
                    }
                )
    return alerts


def detect_privilege_escalation(logs: list[dict]) -> list[dict]:
    alerts = []
    for entry in logs:
        if entry.get("type") in ROLE_CHANGE_TYPES:
            desc = (entry.get("description") or "").lower()
            if "role" in desc or "permission" in desc:
                alerts.append(
                    {
                        "technique": "T1098 - Account Manipulation",
                        "subject": entry.get("user_id", "unknown"),
                        "actor": entry.get("details", {}).get("client_id", "unknown-client"),
                        "description": entry.get("description"),
                        "date": entry.get("date"),
                        "nist_phase": "Detection & Analysis",
                        "recommended_action": "Confirm change against change-management record; revert if unauthorized.",
                    }
                )
    return alerts


def detect_mfa_bypass_attempts(logs: list[dict]) -> list[dict]:
    alerts = []
    for entry in logs:
        if entry.get("type") in MFA_FAIL_TYPES:
            alerts.append(
                {
                    "technique": "T1556.006 - MFA Interception/Bypass Attempt",
                    "subject": entry.get("user_id", "unknown"),
                    "date": entry.get("date"),
                    "nist_phase": "Detection & Analysis",
                    "recommended_action": "Alert user of failed MFA attempt; review device trust.",
                }
            )
    return alerts


def main() -> None:
    logs = load_logs()
    alerts = (
        detect_brute_force(logs)
        + detect_impossible_travel(logs)
        + detect_privilege_escalation(logs)
        + detect_mfa_bypass_attempts(logs)
    )

    ALERTS_PATH.parent.mkdir(exist_ok=True)
    ALERTS_PATH.write_text(json.dumps(alerts, indent=2))

    print(f"Analyzed {len(logs)} log events.")
    print(f"Findings: {len(alerts)}")
    for a in alerts:
        print(f"  [{a['technique']}] subject={a['subject']}")
    print(f"\nFull report -> {ALERTS_PATH}")


if __name__ == "__main__":
    main()