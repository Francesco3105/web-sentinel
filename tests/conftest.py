"""Test setup: a dedicated `<name>_test` database, migrated with Alembic.

Without DATABASE_URL (no Docker) the tests fall back to a temporary SQLite file; the
PostgreSQL-only ones are skipped.
"""

import os
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, make_url, text

POSTGRES = "DATABASE_URL" in os.environ
if POSTGRES:
    _base_url = make_url(os.environ["DATABASE_URL"])
    TEST_DB = f"{_base_url.database}_test"
    _test_url = _base_url.set(database=TEST_DB).render_as_string(hide_password=False)
else:
    _sqlite_file = Path(tempfile.mkdtemp(prefix="websentinel-test-")) / "test.db"
    _test_url = f"sqlite:///{_sqlite_file.as_posix()}"
os.environ.update(
    DATABASE_URL=_test_url,
    SECRET_KEY="test-secret-key",
    SESSION_COOKIE_SECURE="false",
    LOGIN_MAX_ATTEMPTS="3",
    ADMIN_EMAIL="admin@example.test",
    ADMIN_PASSWORD="test-admin-password",
)

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.auth.security import hash_password  # noqa: E402
from app.db.models import Base, Role, User  # noqa: E402
from app.db.session import get_engine, get_sessionmaker  # noqa: E402
from app.main import app  # noqa: E402
from app.ui import routes_auth  # noqa: E402

PASSWORD = "correct-horse-battery"
CSRF_RE = re.compile(r'name="csrf-token" content="([^"]+)"')


@pytest.fixture(scope="session", autouse=True)
def _database() -> Iterator[None]:
    if not POSTGRES:
        command.upgrade(Config("alembic.ini"), "head")
        yield
        get_engine().dispose()
        return
    admin = create_engine(_base_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{TEST_DB}"'))
    command.upgrade(Config("alembic.ini"), "head")
    yield
    get_engine().dispose()
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)'))
    admin.dispose()


@pytest.fixture(autouse=True)
def _clean() -> None:
    with get_engine().begin() as conn:
        if POSTGRES:
            tables = ", ".join(f'"{table.name}"' for table in Base.metadata.sorted_tables)
            conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
        else:
            for table in reversed(Base.metadata.sorted_tables):
                conn.execute(table.delete())
    routes_auth.limiter.clear()
    routes_auth.ip_limiter.clear()


@pytest.fixture
def db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session


def make_user(db: Session, email: str, role: Role, active: bool = True) -> User:
    user = User(email=email, role=role, active=active, password_hash=hash_password(PASSWORD))
    db.add(user)
    db.commit()
    return user


def csrf(client: TestClient, path: str = "/login") -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match is not None
    return match.group(1)


def login(client: TestClient, email: str, password: str = PASSWORD) -> str:
    """Log in and return the CSRF token of the authenticated session."""
    response = client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return csrf(client, "/sites")


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin(db: Session) -> User:
    return make_user(db, "admin@example.test", Role.ADMIN)


@pytest.fixture
def viewer(db: Session) -> User:
    return make_user(db, "viewer@example.test", Role.VIEWER)
