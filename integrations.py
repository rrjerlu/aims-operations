from __future__ import annotations

import json
import os
import smtplib
from email.message import EmailMessage
from urllib.request import Request, urlopen


def _dry_run() -> bool:
    return os.getenv("AIMS_DRY_RUN", "true").lower() in {"1", "true", "yes"}


def send_email(recipient: str, subject: str, message: str) -> str:
    if _dry_run():
        return "dry-run"
    host = os.environ["AIMS_SMTP_HOST"]
    port = int(os.getenv("AIMS_SMTP_PORT", "587"))
    username = os.environ["AIMS_SMTP_USERNAME"]
    password = os.environ["AIMS_SMTP_PASSWORD"]
    sender = os.environ["AIMS_SMTP_FROM"]
    email = EmailMessage()
    email["From"], email["To"], email["Subject"] = sender, recipient, subject
    email.set_content(message)
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(email)
    return "sent"


def send_line(recipient: str, message: str) -> str:
    if _dry_run():
        return "dry-run"
    token = os.environ["AIMS_LINE_TOKEN"]
    request = Request(
        "https://api.line.me/v2/bot/message/push",
        data=json.dumps({"to": recipient, "messages": [{"type": "text", "text": message}]}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=20):
        return "sent"


def send_teams(webhook: str, message: str) -> str:
    if _dry_run():
        return "dry-run"
    request = Request(
        webhook,
        data=json.dumps({"text": message}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=20):
        return "sent"


def fetch_shiftwise_json(url: str) -> object:
    token = os.getenv("SHIFTWISE_API_TOKEN")
    headers = {"Accept": "application/json", "User-Agent": "AIMS/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urlopen(Request(url, headers=headers), timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))
