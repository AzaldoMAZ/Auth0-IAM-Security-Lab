"""
fetch_logs.py
Pulls tenant log events from the Auth0 Management API using a
client-credentials grant and writes them to logs/raw_logs.json.

Requires an Auth0 Machine-to-Machine application authorized for the
Management API with the `read:logs` and `read:logs_users` scopes.
"""

import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["M2M_CLIENT_ID"]
CLIENT_SECRET = os.environ["M2M_CLIENT_SECRET"]

OUTPUT_PATH = Path(__file__).parent / "logs" / "raw_logs.json"


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


def fetch_logs(token: str, per_page: int = 100, max_pages: int = 20) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}"}
    all_logs: list[dict] = []
    page = 0

    while page < max_pages:
        resp = requests.get(
            f"https://{AUTH0_DOMAIN}/api/v2/logs",
            headers=headers,
            params={
                "per_page": per_page,
                "page": page,
                "sort": "date:1",
            },
            timeout=10,
        )

        if resp.status_code == 400:
            # Auth0 caps page-based pagination around ~1000 results.
            print(f"Reached pagination limit at page {page}; stopping.")
            break

        resp.raise_for_status()
        batch = resp.json()

        # Defensive: handle either a plain list or a {"logs": [...]} wrapper.
        if isinstance(batch, dict):
            batch = batch.get("logs", [])

        if not batch:
            break

        all_logs.extend(batch)
        page += 1
        time.sleep(0.3)  # be polite to the rate limit

    return all_logs


def main() -> None:
    token = get_management_token()
    logs = fetch_logs(token)
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(logs, indent=2))
    print(f"Fetched {len(logs)} log events -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()