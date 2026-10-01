from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    account TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS polc_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    account TEXT NOT NULL,
    stage TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft'
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'manager',
    created_at TEXT NOT NULL,
    UNIQUE (tenant_id, email)
);
"""

POSTGRES_SCHEMA = SCHEMA.replace(
    "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Persistence adapter with SQLite fallback and optional PostgreSQL support."""

    def __init__(self, database_url: str | None = None, path: str = "aims_local.db") -> None:
        self.database_url = database_url or os.getenv("AIMS_DATABASE_URL")
        self.path = Path(path)

    @property
    def backend(self) -> str:
        return "postgresql" if self.database_url and self.database_url.startswith(("postgres://", "postgresql://")) else "sqlite"

    @contextmanager
    def connection(self) -> Iterator[Any]:
        if self.backend == "postgresql":
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("PostgreSQL requires psycopg[binary]; install requirements.txt first.") from exc
            connection = psycopg.connect(self.database_url)
            try:
                yield connection
                connection.commit()
            finally:
                connection.close()
            return
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connection() as connection:
            if self.backend == "postgresql":
                with connection.cursor() as cursor:
                    for statement in POSTGRES_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
            else:
                connection.executescript(SCHEMA)

    def add_audit(self, account: str, action: str, detail: str) -> None:
        with self.connection() as connection:
            if self.backend == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO audit_events (created_at,account,action,detail) VALUES (%s,%s,%s,%s)",
                        (_now(), account, action, detail),
                    )
            else:
                connection.execute(
                    "INSERT INTO audit_events (created_at,account,action,detail) VALUES (?,?,?,?)",
                    (_now(), account, action, detail),
                )

    def add_job(self, source: str, payload: dict[str, Any]) -> int:
        with self.connection() as connection:
            if self.backend == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO sync_jobs (source,status,payload,updated_at) VALUES (%s,%s,%s,%s) RETURNING id",
                        (source, "queued", json.dumps(payload), _now()),
                    )
                    return int(cursor.fetchone()[0])
            result = connection.execute(
                "INSERT INTO sync_jobs (source,status,payload,updated_at) VALUES (?,?,?,?)",
                (source, "queued", json.dumps(payload), _now()),
            )
            return int(result.lastrowid)

    def add_report(self, account: str, stage: str, title: str, content: str) -> None:
        with self.connection() as connection:
            values = (_now(), account, stage, title, content)
            if self.backend == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO polc_reports (created_at,account,stage,title,content) VALUES (%s,%s,%s,%s,%s)",
                        values,
                    )
            else:
                connection.execute(
                    "INSERT INTO polc_reports (created_at,account,stage,title,content) VALUES (?,?,?,?,?)",
                    values,
                )

    def add_notification(self, channel: str, recipient: str, message: str) -> None:
        with self.connection() as connection:
            values = (_now(), channel, recipient, message)
            if self.backend == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO notifications (created_at,channel,recipient,message) VALUES (%s,%s,%s,%s)",
                        values,
                    )
            else:
                connection.execute(
                    "INSERT INTO notifications (created_at,channel,recipient,message) VALUES (?,?,?,?)",
                    values,
                )

    def claim_queued_notifications(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connection() as connection:
            if self.backend == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT id,channel,recipient,message,attempts FROM notifications WHERE status='queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT %s",
                        (limit,),
                    )
                    return [dict(zip(("id", "channel", "recipient", "message", "attempts"), row)) for row in cursor.fetchall()]
            rows = connection.execute(
                "SELECT id,channel,recipient,message,attempts FROM notifications WHERE status='queued' ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def mark_notification(self, notification_id: int, status: str, error: str | None = None) -> None:
        with self.connection() as connection:
            if self.backend == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE notifications SET status=%s, attempts=attempts+1, last_error=%s WHERE id=%s",
                        (status, error, notification_id),
                    )
            else:
                connection.execute(
                    "UPDATE notifications SET status=?, attempts=attempts+1, last_error=? WHERE id=?",
                    (status, error, notification_id),
                )
