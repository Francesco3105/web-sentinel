from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.alerts import engine
from app.alerts.mailer import Mail
from app.checks import sync_default_checks
from app.checks.runner import Outcome
from app.config import Settings, get_settings
from app.db.models import AlertLog, Check, CheckStatus, Incident, IncidentStatus, Site, User
from app.db.seed import seed
from app.incidents.service import evaluate
from app.worker.scheduler import due_checks
from tests.conftest import login

# 10:00 in Rome (UTC+2 in October): inside the 08:00-20:00 window of the warnings.
DAY = datetime(2026, 10, 7, 8, 0, tzinfo=UTC)
NIGHT = datetime(2026, 10, 7, 20, 30, tzinfo=UTC)

FAIL = Outcome(CheckStatus.FAIL, None, "Nessuna risposta entro 120 s")
OK = Outcome(CheckStatus.OK, 200, "HTTP 200 in 200 ms")
SLOW = Outcome(CheckStatus.WARN, 31000, "HTTP 200 in 31000 ms: risposta lenta")


class Outbox:
    def __init__(self) -> None:
        self.mails: list[Mail] = []
        self.broken = False

    def __call__(self, settings: Settings, mail: Mail) -> None:
        if self.broken:
            raise ConnectionRefusedError("smtp down")
        self.mails.append(mail)


@pytest.fixture
def outbox() -> Outbox:
    return Outbox()


@pytest.fixture
def settings() -> Settings:
    return get_settings().model_copy(
        update={"environment": "development", "mail_real_delivery": False}
    )


@pytest.fixture
def site(db: Session) -> Site:
    seed(db, get_settings())
    site = Site(
        name="Prova",
        url="https://www.example.test/",
        active=True,
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


def _fail_three_times(db: Session, check: Check, now: datetime) -> Incident:
    assert _apply(db, check, FAIL, now) is None
    assert _apply(db, check, FAIL, now) is None
    incident = _apply(db, check, FAIL, now)
    assert incident is not None
    return incident


def test_incident_opens_at_the_third_failure_and_closes_on_recovery(
    db: Session, site: Site
) -> None:
    incident = _fail_three_times(db, _check(site, "http"), DAY)
    assert (incident.severity, incident.status) == ("critical", IncidentStatus.OPEN)
    assert incident.title == "HTTP/HTTPS: Nessuna risposta entro 120 s"

    # Further failures keep the same incident.
    assert _apply(db, _check(site, "http"), FAIL, DAY) is incident
    assert len(db.scalars(select(Incident)).all()) == 1

    _apply(db, _check(site, "http"), OK, DAY + timedelta(minutes=20))
    assert incident.status == IncidentStatus.CLOSED
    assert [event.kind for event in incident.events] == ["opened", "recovered"]


def test_a_site_that_is_down_gets_one_incident_for_all_its_checks(
    db: Session, site: Site, settings: Settings, outbox: Outbox
) -> None:
    http, dns = _check(site, "http"), _check(site, "dns")
    incident = _fail_three_times(db, http, DAY)
    for _ in range(3):
        _apply(db, dns, Outcome(CheckStatus.FAIL, 0, "Il nome non risolve"), DAY)
    assert db.scalars(select(Incident)).all() == [incident]
    assert [event.kind for event in incident.events] == ["opened", "correlated"]
    assert engine.process(db, DAY, settings, outbox) == 1

    # Still open while one of the checks keeps failing.
    _apply(db, http, OK, DAY + timedelta(minutes=5))
    assert incident.status == IncidentStatus.OPEN
    _apply(db, dns, Outcome(CheckStatus.OK, 1, "Risolve a 192.0.2.10"), DAY + timedelta(minutes=6))
    assert incident.status == IncidentStatus.CLOSED
    assert engine.process(db, DAY + timedelta(minutes=6), settings, outbox) == 1
    assert len(outbox.mails) == 2


def test_slow_response_never_opens_an_incident(db: Session, site: Site) -> None:
    for _ in range(5):
        assert _apply(db, _check(site, "http"), SLOW, DAY) is None
    assert db.scalars(select(Incident)).all() == []


def test_certificate_alert_only_under_seven_days(db: Session, site: Site) -> None:
    tls = _check(site, "tls")
    in_20_days = Outcome(CheckStatus.WARN, 20, "Certificato in scadenza tra 20 giorni")
    in_5_days = Outcome(CheckStatus.WARN, 5, "Certificato in scadenza tra 5 giorni")
    assert _apply(db, tls, in_20_days, DAY) is None

    incident = _apply(db, tls, in_5_days, DAY)
    assert incident is not None and incident.severity == "warning"

    renewed = Outcome(CheckStatus.OK, 89, "Certificato valido, scade tra 89 giorni")
    _apply(db, tls, renewed, DAY)
    assert incident.status == IncidentStatus.CLOSED


def test_expired_certificate_escalates_the_warning(db: Session, site: Site) -> None:
    tls = _check(site, "tls")
    incident = _apply(db, tls, Outcome(CheckStatus.WARN, 2, "Certificato in scadenza"), DAY)
    expired = Outcome(CheckStatus.FAIL, -1, "Certificato scaduto")
    for _ in range(3):
        _apply(db, tls, expired, DAY)
    assert incident is not None and incident.severity == "critical"
    assert len(db.scalars(select(Incident)).all()) == 1


def test_critical_one_mail_then_reminders_then_recovery(
    db: Session, site: Site, settings: Settings, outbox: Outbox
) -> None:
    http = _check(site, "http")
    _fail_three_times(db, http, NIGHT)

    # Critical alerts go out at any hour, once.
    assert engine.process(db, NIGHT, settings, outbox) == 1
    assert engine.process(db, NIGHT + timedelta(minutes=1), settings, outbox) == 0
    assert engine.process(db, NIGHT + timedelta(minutes=29), settings, outbox) == 0
    opened = outbox.mails[0]
    assert opened.subject == "[CRITICAL] Prova – HTTP/HTTPS: Nessuna risposta entro 120 s"
    assert "Azione consigliata" in opened.text and "/incidents/" in opened.html

    assert engine.process(db, NIGHT + timedelta(minutes=30), settings, outbox) == 1
    assert engine.process(db, NIGHT + timedelta(minutes=45), settings, outbox) == 0
    assert engine.process(db, NIGHT + timedelta(minutes=61), settings, outbox) == 1
    assert outbox.mails[1].subject.endswith("(promemoria)")

    _apply(db, http, OK, NIGHT + timedelta(minutes=70))
    assert engine.process(db, NIGHT + timedelta(minutes=70), settings, outbox) == 1
    assert engine.process(db, NIGHT + timedelta(minutes=120), settings, outbox) == 0
    recovery = outbox.mails[-1]
    assert recovery.subject.startswith("[RISOLTO] Prova")
    assert "1 h 10 min" in recovery.text
    kinds = db.scalars(select(AlertLog.kind).order_by(AlertLog.id)).all()
    assert kinds == ["opened", "reminder", "reminder", "recovery"]


def test_warning_waits_for_the_window_and_is_deduplicated(
    db: Session, site: Site, settings: Settings, outbox: Outbox
) -> None:
    tls = _check(site, "tls")
    expiring = Outcome(CheckStatus.WARN, 5, "Certificato in scadenza tra 5 giorni")
    renewed = Outcome(CheckStatus.OK, 89, "Certificato valido, scade tra 89 giorni")
    _apply(db, tls, expiring, NIGHT)

    assert engine.process(db, NIGHT, settings, outbox) == 0
    morning = DAY + timedelta(days=1)
    assert engine.process(db, morning, settings, outbox) == 1
    assert outbox.mails[0].subject.startswith("[WARNING] Prova")
    # No reminders for warnings.
    assert engine.process(db, morning + timedelta(hours=5), settings, outbox) == 0

    # The same problem coming back within six hours produces no second mail.
    _apply(db, tls, renewed, morning + timedelta(minutes=10))
    assert engine.process(db, morning + timedelta(minutes=10), settings, outbox) == 1  # recovery
    _apply(db, tls, expiring, morning + timedelta(minutes=20))
    assert engine.process(db, morning + timedelta(minutes=20), settings, outbox) == 0
    assert engine.process(db, morning + timedelta(minutes=40), settings, outbox) == 0
    statuses = db.scalars(select(AlertLog.status).order_by(AlertLog.id)).all()
    assert statuses == ["sent", "sent", "deduplicated"]


def test_failed_delivery_is_logged_and_retried_later(
    db: Session, site: Site, settings: Settings, outbox: Outbox
) -> None:
    _fail_three_times(db, _check(site, "http"), DAY)
    outbox.broken = True
    assert engine.process(db, DAY, settings, outbox) == 0
    log = db.scalars(select(AlertLog)).one()
    assert (log.status, log.error) == ("failed", "ConnectionRefusedError")

    outbox.broken = False
    assert engine.process(db, DAY + timedelta(minutes=1), settings, outbox) == 0
    assert engine.process(db, DAY + timedelta(minutes=6), settings, outbox) == 1


def test_real_delivery_outside_production_reaches_the_test_recipient_only(
    db: Session, site: Site, settings: Settings, outbox: Outbox
) -> None:
    _fail_three_times(db, _check(site, "http"), DAY)
    real = settings.model_copy(update={"mail_real_delivery": True, "mail_test_recipient": ""})
    assert engine.process(db, DAY, real, outbox) == 0
    assert db.scalars(select(AlertLog.status)).one() == "failed"

    real = real.model_copy(update={"mail_test_recipient": "prova@example.test"})
    assert engine.process(db, DAY + timedelta(minutes=6), real, outbox) == 1
    assert [mail.recipient for mail in outbox.mails] == ["prova@example.test"]


def test_unconfirmed_failure_is_checked_again_sooner(db: Session, site: Site) -> None:
    now = datetime.now(UTC)
    http = _check(site, "http")
    for check in site.checks:
        check.last_run_at = now
    http.consecutive_failures = 1
    db.commit()
    assert due_checks(db, now + timedelta(seconds=30)) == []
    assert due_checks(db, now + timedelta(seconds=61)) == [http]


def test_incident_pages(
    client: TestClient, admin: User, db: Session, site: Site, settings: Settings, outbox: Outbox
) -> None:
    incident = _fail_three_times(db, _check(site, "http"), DAY)
    engine.process(db, DAY, settings, outbox)
    login(client, admin.email)

    page = client.get("/incidents").text
    assert "Nessuna risposta entro 120 s" in page and "Critico" in page
    assert "Nessun incidente." in client.get("/incidents?stato=chiusi").text

    page = client.get(f"/incidents/{incident.id}").text
    assert "Azione consigliata" in page and "Apertura" in page and "Inviata" in page
    assert "Incidenti aperti" in client.get(f"/sites/{site.id}").text
    assert client.get("/incidents/999").status_code == 404
