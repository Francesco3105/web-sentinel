import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.auth.security import LoginLimiter, hash_password, verify_password
from app.db.models import AuditLog, Role, User
from tests.conftest import PASSWORD, POSTGRES, csrf, login, make_user


def test_password_hash_roundtrip() -> None:
    hashed = hash_password(PASSWORD)
    assert hashed.startswith("$argon2")
    assert verify_password(hashed, PASSWORD)
    assert not verify_password(hashed, "wrong")
    assert not verify_password("not-a-hash", PASSWORD)


def test_limiter_blocks_and_expires() -> None:
    limiter = LoginLimiter(max_attempts=2, window_seconds=60)
    limiter.register_failure("k", now=0)
    assert not limiter.is_blocked("k", now=1)
    limiter.register_failure("k", now=1)
    assert limiter.is_blocked("k", now=2)
    assert not limiter.is_blocked("k", now=62)


def test_pages_require_login(client: TestClient) -> None:
    for path in ("/", "/sites", "/admin/users", "/admin/audit"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
    assert client.get("/sites", follow_redirects=False).headers["location"] == "/login"


def test_login_success_sets_hardened_cookie(client: TestClient, admin: User, db: Session) -> None:
    response = client.post(
        "/login",
        data={"email": admin.email, "password": PASSWORD, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "httponly" in response.headers["set-cookie"].lower()
    assert client.get("/sites").status_code == 200
    assert db.scalar(select(AuditLog.action).order_by(AuditLog.id.desc())) == "login"


def test_login_with_user_name_and_short_password_shows_warning(
    client: TestClient, db: Session
) -> None:
    db.add(User(email="admin", role=Role.ADMIN, password_hash=hash_password("admin")))
    db.commit()
    response = client.post(
        "/login", data={"email": "Admin", "password": "admin", "csrf_token": csrf(client)}
    )
    assert response.status_code == 200
    assert "Password troppo corta" in response.text


def test_long_password_shows_no_warning(client: TestClient, admin: User) -> None:
    login(client, admin.email)
    assert "Password troppo corta" not in client.get("/sites").text


def test_login_wrong_password_is_audited(client: TestClient, admin: User, db: Session) -> None:
    response = client.post(
        "/login", data={"email": admin.email, "password": "nope", "csrf_token": csrf(client)}
    )
    assert response.status_code == 401
    assert "Credenziali non valide" in response.text
    assert db.scalar(select(AuditLog.action)) == "login_failed"


def test_inactive_user_cannot_login(client: TestClient, db: Session) -> None:
    make_user(db, "off@example.test", Role.ADMIN, active=False)
    response = client.post(
        "/login",
        data={"email": "off@example.test", "password": PASSWORD, "csrf_token": csrf(client)},
    )
    assert response.status_code == 401


def test_login_without_csrf_is_rejected(client: TestClient, admin: User) -> None:
    response = client.post("/login", data={"email": admin.email, "password": PASSWORD})
    assert response.status_code == 403


def test_login_rate_limit(client: TestClient, admin: User) -> None:
    token = csrf(client)
    for _ in range(3):
        client.post("/login", data={"email": admin.email, "password": "x", "csrf_token": token})
    response = client.post(
        "/login", data={"email": admin.email, "password": PASSWORD, "csrf_token": token}
    )
    assert response.status_code == 429


def test_logout(client: TestClient, admin: User) -> None:
    token = login(client, admin.email)
    assert client.post("/logout", data={"csrf_token": token}).status_code == 200
    assert client.get("/sites", follow_redirects=False).status_code == 303


@pytest.mark.skipif(not POSTGRES, reason="the append-only trigger exists only on PostgreSQL")
def test_audit_log_is_append_only(db: Session) -> None:
    db.add(AuditLog(action="login", details={}))
    db.commit()
    for statement in ("UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log"):
        with pytest.raises(DBAPIError):
            db.execute(text(statement))
        db.rollback()
