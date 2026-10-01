"""Small queue worker entry point for deployment cron or a background service.

It intentionally only manages durable queue state. Provider-specific delivery
and Shiftwise API calls must be configured in the deployment environment.
"""

from __future__ import annotations

import os

from storage import Store
from integrations import send_email, send_line, send_teams


def process_notifications(store: Store) -> tuple[int, int]:
    sent = failed = 0
    for notification in store.claim_queued_notifications():
        try:
            channel = notification["channel"]
            if channel == "email":
                send_email(notification["recipient"], "AIMS 營運通知", notification["message"])
            elif channel == "line":
                send_line(notification["recipient"], notification["message"])
            elif channel == "teams":
                send_teams(notification["recipient"], notification["message"])
            else:
                raise ValueError(f"Unsupported notification channel: {channel}")
            store.mark_notification(notification["id"], "sent")
            sent += 1
        except (OSError, ValueError, KeyError) as exc:
            store.mark_notification(notification["id"], "failed", str(exc))
            failed += 1
    return sent, failed


def main() -> None:
    store = Store(database_url=os.getenv("AIMS_DATABASE_URL"))
    store.initialize()
    sent, failed = process_notifications(store)
    print(
        f"AIMS worker complete: sent={sent}, failed={failed}, dry_run={os.getenv('AIMS_DRY_RUN', 'true')}."
    )


if __name__ == "__main__":
    main()
