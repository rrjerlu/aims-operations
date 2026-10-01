from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from storage import Store


@dataclass(frozen=True)
class Identity:
    account: str
    role: str
    provider: str


ROLE_PERMISSIONS = {
    "admin": {"read", "write", "publish", "manage_users"},
    "manager": {"read", "write", "publish"},
    "auditor": {"read"},
}


def current_identity(session_state: dict[str, Any]) -> Identity:
    return Identity(
        account=str(session_state.get("account", "store001")),
        role=str(session_state.get("role", "manager")),
        provider=str(session_state.get("auth_provider", "demo")),
    )


def can(identity: Identity, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(identity.role, set())


def create_polc_report(store: Store, identity: Identity, stage: str, title: str, content: str) -> None:
    if not can(identity, "publish"):
        raise PermissionError("目前角色沒有發布 POLC 報告的權限。")
    store.add_report(identity.account, stage, title, content)
    store.add_audit(identity.account, "建立 POLC 報告", f"{stage} · {title}")


def queue_notification(store: Store, identity: Identity, channel: str, recipient: str, message: str) -> None:
    if not can(identity, "write"):
        raise PermissionError("目前角色沒有建立通知的權限。")
    if channel not in {"email", "line", "teams"}:
        raise ValueError("通知渠道必須是 email、line 或 teams。")
    store.add_notification(channel, recipient, message)
    store.add_audit(identity.account, "建立通知", f"{channel} · {recipient}")
