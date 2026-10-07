from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditLog, CheckResult, Site, User
from tests.conftest import login

VALID = {
    "name": "Sito di prova",
    "url": "https://www.example.test/",
    "criticality": "high",
    "active": "on",
    "technical_name": "Mario Rossi",
    "technical_email": "mario@example.test",
}


def _create(client: TestClient, token: str, **overrides: str) -> None:
    response = client.post(
        "/sites", data={**VALID, **overrides, "csrf_token": token}, follow_redirects=False
    )
    assert response.status_code == 303, response.text


def test_admin_creates_site_with_default_checks(
    client: TestClient, admin: User, db: Session
) -> None:
    _create(client, login(client, admin.email))
    site = db.scalars(select(Site)).one()
    assert site.name == "Sito di prova"
    assert not site.is_authorized
    assert sorted(check.type for check in site.checks) == ["dns", "http", "tls"]
    assert site.contact("technical").email == "mario@example.test"  # type: ignore[union-attr]
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "site_create")).one()
    assert entry.user_email == admin.email
    assert entry.object_id == str(site.id)
    assert "Sito di prova" in client.get("/sites").text


def test_site_status_follows_worst_enabled_check(
    client: TestClient, admin: User, db: Session
) -> None:
    _create(client, login(client, admin.email), domain_check_enabled="on")
    site = db.scalars(select(Site)).one()
    assert site.status == "pending"
    assert "In attesa" in client.get("/sites").text
    by_type = {check.type: check for check in site.checks}
    for check in site.checks:
        check.last_status = "ok"
    assert site.status == "ok"
    by_type["tls"].last_status = "warn"
    assert site.status == "warn"
    by_type["http"].last_status = "fail"
    assert site.status == "fail"
    by_type["http"].enabled = False
    assert site.status == "warn"


def test_invalid_site_is_rejected(client: TestClient, admin: User, db: Session) -> None:
    token = login(client, admin.email)
    for overrides in (
        {"url": "ftp://example.test"},
        {"url": "https://user:pw@example.test/"},
        {"name": ""},
        {"authorized_by": "Mario Rossi"},  # who without when
    ):
        response = client.post("/sites", data={**VALID, **overrides, "csrf_token": token})
        assert response.status_code == 422
    assert db.scalars(select(Site)).all() == []


def test_duplicate_url_is_rejected(client: TestClient, admin: User) -> None:
    token = login(client, admin.email)
    _create(client, token)
    response = client.post("/sites", data={**VALID, "csrf_token": token})
    assert response.status_code == 422
    assert "Esiste già" in response.text


def test_edit_records_authorization_and_domain_check(
    client: TestClient, admin: User, db: Session
) -> None:
    token = login(client, admin.email)
    _create(client, token)
    site_id = db.scalars(select(Site.id)).one()
    response = client.post(
        f"/sites/{site_id}/edit",
        data={
            **VALID,
            "criticality": "medium",
            "domain_check_enabled": "on",
            "authorized_by": "Mario Rossi",
            "authorized_at": "2026-10-01",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    db.expire_all()
    site = db.get(Site, site_id)
    assert site is not None and site.is_authorized
    assert site.criticality == "medium"
    domain = next(check for check in site.checks if check.type == "domain")
    assert domain.enabled and domain.target == "example.test"
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "site_update")).one()
    assert entry.details["criticality"] == {"da": "high", "a": "medium"}


def test_delete_site(client: TestClient, admin: User, db: Session) -> None:
    token = login(client, admin.email)
    _create(client, token)
    site_id = db.scalars(select(Site.id)).one()
    response = client.post(
        f"/sites/{site_id}/delete", data={"csrf_token": token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert db.scalars(select(Site)).all() == []
    assert db.scalars(select(AuditLog).where(AuditLog.action == "site_delete")).one()


def test_viewer_is_read_only(client: TestClient, admin: User, viewer: User, db: Session) -> None:
    _create(client, login(client, admin.email))
    client.cookies.clear()
    token = login(client, viewer.email)
    site_id = db.scalars(select(Site.id)).one()
    assert client.get("/sites").status_code == 200
    assert client.get(f"/sites/{site_id}").status_code == 200
    assert client.get("/sites/new").status_code == 403
    assert client.get("/admin/users").status_code == 403
    assert client.post("/sites", data={**VALID, "csrf_token": token}).status_code == 403
    assert client.post(f"/sites/{site_id}/delete", data={"csrf_token": token}).status_code == 403


def test_post_without_csrf_is_rejected(client: TestClient, admin: User, db: Session) -> None:
    login(client, admin.email)
    assert client.post("/sites", data=VALID).status_code == 403
    assert db.scalars(select(Site)).all() == []


def test_missing_site_is_404(client: TestClient, admin: User) -> None:
    login(client, admin.email)
    response = client.get("/sites/999")
    assert response.status_code == 404
    # A logged-in user keeps the menu on error pages.
    assert 'href="/admin/audit"' in response.text
    client.cookies.clear()
    assert 'href="/admin/audit"' not in client.get("/missing").text


def test_overview_and_site_figures(client: TestClient, admin: User, db: Session) -> None:
    token = login(client, admin.email)
    _create(client, token)
    site = db.scalars(select(Site)).one()
    http = next(check for check in site.checks if check.type == "http")
    for status, value in (("ok", 180.0), ("ok", 220.0), ("fail", None), ("ok", 200.0)):
        db.add(
            CheckResult(check_id=http.id, site_id=site.id, status=status, value=value, message="x")
        )
    db.commit()

    page = client.get("/").text
    assert "Panoramica" in page and "75,00 %" in page and "Nessun incidente aperto." in page

    page = client.get(f"/sites/{site.id}").text
    assert 'class="chart"' in page and page.count("chart-fail") == 1
    assert page.count("<polyline") == 2 and "75,00 %" in page
