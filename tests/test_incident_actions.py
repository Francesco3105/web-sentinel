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
from app.db.models import AuditLog, Check, CheckStatus, Incident, IncidentStatus, Role, Site, User
from app.db.seed import seed
from app.incidents.service import evaluate
from tests.conftest import login, make_user

NOW = datetime(2026, 10, 7, 8, 0, tzinfo=UTC)
FAIL = Outcome(CheckStatus.FAIL, None, "Nessuna risposta entro 120 s")


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


def _http(site: Site) -> Check:
    return next(check for check in site.checks if check.type == "http")


def _fail(db: Session, check: Check, now: datetime) -> Incident | None:
    check.consecutive_failures += 1
    incident = evaluate(db, check, FAIL, now)
    db.commit()
    return incident


@pytest.fixture
def incident(db: Session, site: Site) -> Incident:
    found = None
    for _ in range(3):
        found = _fail(db, _http(site), NOW)
    assert found is not None
    return found


def _post(client: TestClient, path: str, token: str, **data: str) -> str:
    response = client.post(path, data={**data, "csrf_token": token})
    assert response.status_code == 200, response.text
    return response.text


def test_operator_takes_charge_adds_a_note_and_closes(
    client: TestClient, db: Session, incident: Incident
) -> None:
    operator = make_user(db, "operatore@example.test", Role.OPERATOR)
    token = login(client, operator.email)
    base = f"/incidents/{incident.id}"

    page = client.get(base).text
    assert "Prendi in carico" in page and "Aggiungi nota" in page and ">Chiudi<" in page

    page = _post(client, f"{base}/acknowledge", token)
    db.refresh(incident)
    assert incident.status == IncidentStatus.ACKNOWLEDGED
    assert incident.assigned_to_id == operator.id and incident.acknowledged_at is not None
    assert "In carico a" in page and "Prendi in carico</button>" not in page

    page = _post(
        client, f"{base}/notes", token, text="  Sentito il fornitore:\nriavvio in corso.  "
    )
    assert "Sentito il fornitore:" in page and "operatore@example.test" in page
    assert "Nota non salvata" in _post(client, f"{base}/notes", token, text="   ")

    page = _post(client, f"{base}/close", token)
    db.refresh(incident)
    assert incident.status == IncidentStatus.CLOSED and incident.closed_at is not None
    assert "Chiuso a mano" in page and ">Chiudi<" not in page
    assert "già chiuso" in _post(client, f"{base}/close", token)
    assert "già chiuso" in _post(client, f"{base}/acknowledge", token)

    kinds = [event.kind for event in db.get(Incident, incident.id).events]  # type: ignore[union-attr]
    assert kinds == ["opened", "acknowledged", "note", "closed_manually"]
    actions = db.scalars(
        select(AuditLog.action).where(AuditLog.object_type == "incident").order_by(AuditLog.id)
    ).all()
    assert actions == ["incident_acknowledge", "incident_note", "incident_close"]


def test_viewer_cannot_act_on_incidents(
    client: TestClient, db: Session, viewer: User, incident: Incident
) -> None:
    token = login(client, viewer.email)
    base = f"/incidents/{incident.id}"
    page = client.get(base).text
    assert "Prendi in carico" not in page and "Aggiungi nota" not in page
    for action in ("acknowledge", "notes", "close"):
        response = client.post(f"{base}/{action}", data={"csrf_token": token, "text": "x"})
        assert response.status_code == 403
    db.refresh(incident)
    assert incident.status == IncidentStatus.OPEN and len(incident.events) == 1


def test_taking_charge_stops_reminders_but_not_the_recovery(
    client: TestClient, db: Session, admin: User, site: Site, incident: Incident
) -> None:
    sent: list[Mail] = []

    def outbox(settings: Settings, mail: Mail) -> None:
        sent.append(mail)

    settings = get_settings().model_copy(
        update={"environment": "development", "mail_real_delivery": False}
    )
    assert engine.process(db, NOW, settings, outbox) == 1
    token = login(client, admin.email)
    _post(client, f"/incidents/{incident.id}/acknowledge", token)
    # The request used its own session: reload what this one has cached.
    db.expire_all()

    assert engine.process(db, NOW + timedelta(minutes=31), settings, outbox) == 0
    assert engine.process(db, NOW + timedelta(hours=3), settings, outbox) == 0

    http = _http(site)
    http.consecutive_failures = 0
    evaluate(db, http, Outcome(CheckStatus.OK, 200, "HTTP 200 in 200 ms"), NOW + timedelta(hours=4))
    db.commit()
    assert engine.process(db, NOW + timedelta(hours=4), settings, outbox) == 1
    assert sent[-1].subject.startswith("[RISOLTO]")


def test_a_problem_still_there_after_a_manual_close_opens_a_new_incident(
    client: TestClient, db: Session, admin: User, site: Site, incident: Incident
) -> None:
    token = login(client, admin.email)
    _post(client, f"/incidents/{incident.id}/close", token)
    db.expire_all()
    again = _fail(db, _http(site), NOW + timedelta(minutes=5))
    assert again is not None and again.id != incident.id
    assert again.status == IncidentStatus.OPEN
