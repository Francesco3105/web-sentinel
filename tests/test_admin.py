from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import verify_password
from app.config import get_settings
from app.db.models import AuditLog, Check, Site, User
from app.db.seed import seed
from app.ui.rendering import worker_status
from app.worker.main import beat
from tests.conftest import PASSWORD, login


def test_seed_is_complete_and_idempotent(db: Session) -> None:
    created = seed(db, get_settings())
    assert created == {"sites": 4, "alert_rules": 5, "alert_recipients": 1, "users": 1}
    assert seed(db, get_settings()) == {
        "sites": 0,
        "alert_rules": 0,
        "alert_recipients": 0,
        "users": 0,
    }
    checks = db.scalars(select(Check)).all()
    assert len(checks) == 4 * 3 + 3
    domain_targets = sorted(check.target for check in checks if check.type == "domain")
    assert domain_targets == [
        "example.com",
        "example.net",
        "example.org",
    ]
    assert not any(site.is_authorized for site in db.scalars(select(Site)))
    admin = db.scalars(select(User)).one()
    assert admin.role == "admin"
    assert verify_password(admin.password_hash, get_settings().admin_password)


def test_admin_manages_users(client: TestClient, admin: User, db: Session) -> None:
    token = login(client, admin.email)
    data = {
        "email": "Operatore@Example.test",
        "full_name": "Op",
        "role": "operator",
        "active": "on",
        "password": PASSWORD,
        "csrf_token": token,
    }
    assert client.post("/admin/users", data=data, follow_redirects=False).status_code == 303
    created = db.scalars(select(User).where(User.email == "operatore@example.test")).one()
    assert created.role == "operator"

    assert client.post("/admin/users", data={**data, "password": "short"}).status_code == 422

    response = client.post(
        f"/admin/users/{created.id}/edit",
        data={"email": created.email, "role": "viewer", "active": "on", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    actions = db.scalars(select(AuditLog.action).order_by(AuditLog.id)).all()
    assert actions == ["login", "user_create", "user_update"]
    page = client.get("/admin/audit").text
    assert "Utente creato" in page and PASSWORD not in page


def test_last_admin_cannot_be_demoted(client: TestClient, admin: User, db: Session) -> None:
    token = login(client, admin.email)
    response = client.post(
        f"/admin/users/{admin.id}/edit",
        data={"email": admin.email, "role": "viewer", "active": "on", "csrf_token": token},
    )
    assert response.status_code == 422
    db.expire_all()
    assert db.get(User, admin.id).role == "admin"  # type: ignore[union-attr]


def test_worker_heartbeat_status(db: Session) -> None:
    assert worker_status(db)["state"] == "unknown"
    now = datetime.now(UTC)
    beat(db, started_at=now)
    assert worker_status(db)["state"] == "ok"
    beat(db, started_at=now, now=now - timedelta(hours=1))
    assert worker_status(db)["state"] == "down"
