import asyncio
import socket
import ssl
import time
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks import runner, sync_default_checks
from app.checks.runner import USER_AGENT, Outcome, execute
from app.db.models import AuditLog, CheckResult, CheckStatus, Site, User
from app.worker.scheduler import due_checks, run_and_record
from tests.conftest import login

URL = "https://www.example.test/"


def _run(check_type: str, target: str, thresholds: dict[str, object] | None = None) -> Outcome:
    return asyncio.run(execute(check_type, target, 5, thresholds or {}))


@respx.mock
def test_http_ok_sends_user_agent() -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200))
    outcome = _run("http", URL, {"warn_ms": 2000})
    assert outcome.status == CheckStatus.OK
    assert "HTTP 200" in outcome.message
    assert route.calls.last.request.headers["user-agent"] == USER_AGENT


@respx.mock
def test_http_failures() -> None:
    respx.get(URL).mock(return_value=httpx.Response(503))
    assert _run("http", URL).status == CheckStatus.FAIL
    respx.get(URL).mock(side_effect=httpx.ConnectError("down"))
    assert _run("http", URL).status == CheckStatus.FAIL
    respx.get(URL).mock(side_effect=httpx.ReadTimeout("slow"))
    assert "Nessuna risposta" in _run("http", URL).message


@respx.mock
def test_http_slow_response_is_a_warning() -> None:
    respx.get(URL).mock(return_value=httpx.Response(200))
    assert _run("http", URL, {"warn_ms": -1}).status == CheckStatus.WARN


def test_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def found(host: str) -> list[str]:
        return ["192.0.2.10"]

    async def missing(host: str) -> list[str]:
        raise socket.gaierror

    monkeypatch.setattr(runner, "resolve", found)
    assert _run("dns", "example.test").status == CheckStatus.OK
    assert _run("dns", "example.test", {"expected": ["192.0.2.10"]}).status == CheckStatus.OK
    assert _run("dns", "example.test", {"expected": ["192.0.2.99"]}).status == CheckStatus.WARN
    monkeypatch.setattr(runner, "resolve", missing)
    assert _run("dns", "example.test").status == CheckStatus.FAIL


@pytest.mark.parametrize(
    ("days", "expected"),
    [(90, CheckStatus.OK), (20, CheckStatus.WARN), (3, CheckStatus.WARN), (-2, CheckStatus.FAIL)],
)
def test_tls_expiry_thresholds(
    monkeypatch: pytest.MonkeyPatch, days: int, expected: CheckStatus
) -> None:
    async def expiry(host: str, port: int = 443) -> float:
        return time.time() + days * 86400 + 3600

    monkeypatch.setattr(runner, "certificate_expiry", expiry)
    outcome = _run("tls", "example.test", {"warn_days": 30})
    assert outcome.status == expected
    assert outcome.value == days


def test_tls_invalid_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    async def invalid(host: str, port: int = 443) -> float:
        raise ssl.SSLCertVerificationError("certificate has expired")

    monkeypatch.setattr(runner, "certificate_expiry", invalid)
    assert _run("tls", "example.test").status == CheckStatus.FAIL


def test_unexpected_error_becomes_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(host: str) -> list[str]:
        raise RuntimeError("boom")

    monkeypatch.setattr(runner, "resolve", broken)
    assert _run("dns", "example.test").status == CheckStatus.FAIL


def _site(db: Session, authorized: bool) -> Site:
    site = Site(name="Prova", url=URL, active=True)
    if authorized:
        site.authorized_by = "Mario Rossi"
        site.authorized_at = date(2026, 10, 1)
    sync_default_checks(site)
    db.add(site)
    db.commit()
    return site


def _stub_runners(monkeypatch: pytest.MonkeyPatch, status: CheckStatus) -> None:
    async def stub(target: str, timeout: int, thresholds: dict[str, object]) -> Outcome:
        return Outcome(status, 1.0, "stub")

    for check_type in list(runner.RUNNERS):
        monkeypatch.setitem(runner.RUNNERS, check_type, stub)


def test_unauthorized_or_suspended_sites_are_never_checked(db: Session) -> None:
    site = _site(db, authorized=False)
    assert due_checks(db, datetime.now(UTC)) == []
    site.authorized_by, site.authorized_at, site.active = "Mario Rossi", date(2026, 10, 1), False
    db.commit()
    assert due_checks(db, datetime.now(UTC)) == []


def test_due_checks_respect_intervals_and_results_are_recorded(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = _site(db, authorized=True)
    _stub_runners(monkeypatch, CheckStatus.FAIL)
    now = datetime.now(UTC)
    due = due_checks(db, now)
    assert sorted(check.type for check in due) == ["dns", "http", "tls"]

    assert asyncio.run(run_and_record(db, due)) == 3
    assert len(db.scalars(select(CheckResult)).all()) == 3
    assert site.status == "fail"
    assert all(check.consecutive_failures == 1 for check in site.checks)

    assert due_checks(db, now + timedelta(seconds=30)) == []
    later = due_checks(db, now + timedelta(minutes=6))
    assert [check.type for check in later] == ["http"]

    _stub_runners(monkeypatch, CheckStatus.OK)
    asyncio.run(run_and_record(db, later))
    assert later[0].consecutive_failures == 0


def test_run_all_checks_now_skips_unauthorized_sites(
    client: TestClient, admin: User, viewer: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_runners(monkeypatch, CheckStatus.OK)
    token = login(client, admin.email)
    response = client.post("/sites/run-checks", data={"csrf_token": token})
    assert "Controlli non eseguiti" in response.text

    authorized = _site(db, authorized=True)
    other = Site(name="Senza autorizzazione", url="https://other.example.test/", active=True)
    sync_default_checks(other)
    db.add(other)
    db.commit()

    response = client.post("/sites/run-checks", data={"csrf_token": token})
    assert "Eseguiti 3 controlli su 1 siti autorizzati" in response.text
    results = db.scalars(select(CheckResult)).all()
    assert {result.site_id for result in results} == {authorized.id}
    assert db.scalars(select(AuditLog).where(AuditLog.action == "run_all_checks")).one()

    client.cookies.clear()
    token = login(client, viewer.email)
    assert client.post("/sites/run-checks", data={"csrf_token": token}).status_code == 403


def test_run_checks_now(
    client: TestClient, admin: User, viewer: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_runners(monkeypatch, CheckStatus.OK)
    site = _site(db, authorized=False)
    token = login(client, admin.email)

    response = client.post(f"/sites/{site.id}/run-checks", data={"csrf_token": token})
    assert "Controlli non eseguiti" in response.text
    assert db.scalars(select(CheckResult)).all() == []

    site.authorized_by, site.authorized_at = "Mario Rossi", date(2026, 10, 1)
    db.commit()
    response = client.post(f"/sites/{site.id}/run-checks", data={"csrf_token": token})
    assert "Eseguiti 3 controlli" in response.text
    assert len(db.scalars(select(CheckResult)).all()) == 3
    assert db.scalars(select(AuditLog).where(AuditLog.action == "site_run_checks")).one()
    assert ">OK<" in client.get("/sites").text

    client.cookies.clear()
    token = login(client, viewer.email)
    response = client.post(f"/sites/{site.id}/run-checks", data={"csrf_token": token})
    assert response.status_code == 403


def test_run_buttons_are_disabled_when_nothing_can_run(
    client: TestClient, admin: User, db: Session
) -> None:
    site = _site(db, authorized=False)
    login(client, admin.email)
    for path in ("/sites", f"/sites/{site.id}"):
        page = client.get(path).text
        assert "disabled" in page and "Controlli non eseguibili" in page

    site.authorized_by, site.authorized_at = "Mario Rossi", date(2026, 10, 1)
    db.commit()
    for path in ("/sites", f"/sites/{site.id}"):
        page = client.get(path).text
        assert "disabled" not in page and "Controlli non eseguibili" not in page
