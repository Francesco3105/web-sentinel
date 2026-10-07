import asyncio
import time
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts import engine
from app.alerts.mailer import Mail
from app.checks import domain, sync_default_checks
from app.checks.runner import Outcome, execute
from app.config import Settings, get_settings
from app.db.models import Check, CheckStatus, Incident, IncidentStatus, Site
from app.db.seed import seed
from app.incidents.service import evaluate

NOW = datetime(2026, 10, 7, 8, 0, tzinfo=UTC)


def _rdap(expiry: datetime) -> httpx.Response:
    events = [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": expiry.strftime("%Y-%m-%dT%H:%M:%SZ")},
    ]
    return httpx.Response(200, json={"events": events})


def _in_days(days: int) -> datetime:
    return datetime.fromtimestamp(time.time() + days * 86400 + 3600, tz=UTC)


def _run(target: str) -> Outcome:
    thresholds = {"warn_days": 30, "critical_days": 7}
    return asyncio.run(execute("domain", target, 30, thresholds))


def test_candidates_go_from_the_full_name_to_the_shortest() -> None:
    assert domain.candidates("www.example.co.uk") == ["www.example.co.uk", "example.co.uk", "co.uk"]
    assert domain.candidates("example.org") == ["example.org"]


@pytest.mark.parametrize(
    "text",
    ["2027-01-15", "2027-01-15T10:00:00Z", "15-01-2027", "15/01/2027", "2027.01.15", "15-Jan-2027"],
)
def test_expiry_date_formats(text: str) -> None:
    parsed = domain.parse_date(text)
    assert parsed is not None and (parsed.year, parsed.month, parsed.day) == (2027, 1, 15)


@respx.mock
@pytest.mark.parametrize(
    ("days", "status"),
    [(200, CheckStatus.OK), (20, CheckStatus.WARN), (3, CheckStatus.WARN), (-3, CheckStatus.FAIL)],
)
def test_rdap_finds_the_registrable_domain(days: int, status: CheckStatus) -> None:
    async def no_whois(name: str, timeout: int) -> None:
        return None

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(domain, "whois_expiry", no_whois)
        respx.get("https://rdap.org/domain/www.example.org").mock(return_value=httpx.Response(404))
        respx.get("https://rdap.org/domain/example.org").mock(return_value=_rdap(_in_days(days)))
        outcome = _run("www.example.org")
    assert (outcome.status, outcome.value) == (status, days)
    assert "example.org" in outcome.message and "www.example.org" not in outcome.message


@respx.mock
def test_whois_is_the_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    respx.get("https://rdap.org/domain/example.it").mock(return_value=httpx.Response(404))
    asked: list[tuple[str, str]] = []

    async def whois(server: str, query: str, timeout: int) -> str:
        asked.append((server, query))
        if server == domain.IANA_WHOIS:
            return "% IANA WHOIS server\nrefer:        whois.nic.it\n"
        expiry = _in_days(120).strftime("%Y-%m-%d")
        return f"Domain:      example.it\nStatus:      ok\nExpire Date: {expiry}\n"

    monkeypatch.setattr(domain, "whois_query", whois)
    outcome = _run("example.it")
    assert outcome.status == CheckStatus.OK and outcome.value in (119, 120)
    assert asked == [(domain.IANA_WHOIS, "example.it"), ("whois.nic.it", "example.it")]


@respx.mock
def test_unknown_expiry_is_a_warning_without_value(monkeypatch: pytest.MonkeyPatch) -> None:
    async def unreachable(server: str, query: str, timeout: int) -> str:
        raise OSError("no route")

    monkeypatch.setattr(domain, "whois_query", unreachable)
    respx.get("https://rdap.org/domain/example.org").mock(side_effect=httpx.ConnectError("down"))
    outcome = _run("example.org")
    assert (outcome.status, outcome.value) == (CheckStatus.WARN, None)


@pytest.fixture
def site(db: Session) -> Site:
    seed(db, get_settings())
    site = Site(
        name="Prova",
        url="https://www.example.test/",
        active=True,
        domain_check_enabled=True,
        authorized_by="Mario Rossi",
        authorized_at=date(2026, 10, 1),
    )
    sync_default_checks(site)
    db.add(site)
    db.commit()
    return site


def _check(site: Site, check_type: str) -> Check:
    return next(check for check in site.checks if check.type == check_type)


def _apply(db: Session, check: Check, outcome: Outcome, now: datetime) -> Incident | None:
    failed = outcome.status == CheckStatus.FAIL
    check.consecutive_failures = check.consecutive_failures + 1 if failed else 0
    incident = evaluate(db, check, outcome, now)
    db.commit()
    return incident


def test_domain_expiry_opens_its_own_incident_at_once(db: Session, site: Site) -> None:
    check = _check(site, "domain")
    unknown = Outcome(CheckStatus.WARN, None, "Scadenza del dominio non determinabile")
    assert _apply(db, check, unknown, NOW) is None
    assert _apply(db, check, Outcome(CheckStatus.OK, 200, "valido"), NOW) is None

    incident = _apply(db, check, Outcome(CheckStatus.WARN, 20, "in scadenza tra 20 giorni"), NOW)
    assert incident is not None and incident.severity == "warning"
    _apply(db, check, Outcome(CheckStatus.WARN, 5, "in scadenza tra 5 giorni"), NOW)
    assert incident.severity == "critical"

    # A site failure is a separate incident, and its recovery leaves the domain one open.
    http = _check(site, "http")
    down = Outcome(CheckStatus.FAIL, None, "Nessuna risposta entro 120 s")
    for _ in range(3):
        _apply(db, http, down, NOW)
    assert len(db.scalars(select(Incident)).all()) == 2
    _apply(db, http, Outcome(CheckStatus.OK, 200, "HTTP 200 in 200 ms"), NOW)
    assert incident.status == IncidentStatus.OPEN

    _apply(db, check, Outcome(CheckStatus.OK, 365, "valido"), NOW + timedelta(days=1))
    assert incident.status == IncidentStatus.CLOSED


def test_domain_reminders_come_once_a_day(db: Session, site: Site) -> None:
    sent: list[Mail] = []

    def outbox(settings: Settings, mail: Mail) -> None:
        sent.append(mail)

    settings = get_settings().model_copy(
        update={"environment": "development", "mail_real_delivery": False}
    )
    expiring = Outcome(CheckStatus.WARN, 5, "Dominio example.test in scadenza tra 5 giorni")
    _apply(db, _check(site, "domain"), expiring, NOW)
    assert engine.process(db, NOW, settings, outbox) == 1
    assert engine.process(db, NOW + timedelta(hours=2), settings, outbox) == 0
    assert engine.process(db, NOW + timedelta(hours=23), settings, outbox) == 0
    assert engine.process(db, NOW + timedelta(hours=24), settings, outbox) == 1
    assert sent[0].subject.startswith("[CRITICAL] Prova – Scadenza dominio")
