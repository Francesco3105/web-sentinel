"""Audit log: who did what, when, on which object."""

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AuditLog, User


def record(
    db: Session,
    user: User | None,
    action: str,
    object_type: str | None = None,
    object_id: int | str | None = None,
    details: dict[str, Any] | None = None,
    user_email: str | None = None,
) -> None:
    """Add an audit entry to the session; the caller commits."""
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_email=user.email if user else user_email,
            action=action,
            object_type=object_type,
            object_id=None if object_id is None else str(object_id),
            details=details or {},
        )
    )
