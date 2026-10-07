from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.auth import audit
from app.auth.deps import DbDep, OperatorDep, UserDep, csrf_protect
from app.db.models import AlertLog, Incident, IncidentStatus, Role, Site, User
from app.incidents import service
from app.ui.rendering import flash, render

router = APIRouter(prefix="/incidents", dependencies=[Depends(csrf_protect)])

PAGE_SIZE = 100
FILTERS = {"aperti": "Aperti", "chiusi": "Chiusi", "tutti": "Tutti"}
SEVERITY_RANK = {"malware": 0, "security": 1, "critical": 2, "warning": 3, "info": 4}
CAN_MANAGE = (Role.ADMIN, Role.OPERATOR)
NOTE_MAX_LENGTH = 2000


def _get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id, options=[selectinload(Incident.events)])
    if incident is None:
        raise HTTPException(status_code=404)
    return incident


@router.get("", response_class=HTMLResponse)
def incident_list(request: Request, db: DbDep, user: UserDep, stato: str = "aperti") -> Response:
    if stato not in FILTERS:
        stato = "aperti"
    query = select(Incident).order_by(Incident.id.desc()).limit(PAGE_SIZE)
    if stato == "aperti":
        query = query.where(Incident.status != IncidentStatus.CLOSED)
    elif stato == "chiusi":
        query = query.where(Incident.status == IncidentStatus.CLOSED)
    # Open incidents first, the most serious on top; then the most recent.
    incidents = sorted(
        db.scalars(query).all(),
        key=lambda item: (
            item.status == IncidentStatus.CLOSED,
            SEVERITY_RANK.get(item.severity, len(SEVERITY_RANK)),
            -item.id,
        ),
    )
    sites = {site.id: site for site in db.scalars(select(Site))}
    context = {"incidents": incidents, "sites": sites, "filters": FILTERS, "current": stato}
    return render(request, "incidents/list.html", context, db=db, user=user)


@router.get("/{incident_id}", response_class=HTMLResponse)
def incident_detail(incident_id: int, request: Request, db: DbDep, user: UserDep) -> Response:
    incident = _get_incident(db, incident_id)
    mails = db.scalars(
        select(AlertLog).where(AlertLog.incident_id == incident.id).order_by(AlertLog.id)
    ).all()
    people = {event.user_id for event in incident.events} | {incident.assigned_to_id}
    people.discard(None)
    authors: dict[int, str] = {}
    if people:
        rows = db.execute(select(User.id, User.email).where(User.id.in_(people)))
        authors = {user_id: email for user_id, email in rows}
    context = {
        "incident": incident,
        "site": db.get(Site, incident.site_id),
        "mails": mails,
        "authors": authors,
        "can_manage": user.role in CAN_MANAGE,
        "note_max_length": NOTE_MAX_LENGTH,
    }
    return render(request, "incidents/detail.html", context, db=db, user=user)


def _back(incident: Incident) -> Response:
    return RedirectResponse(f"/incidents/{incident.id}", status_code=303)


@router.post("/{incident_id}/acknowledge")
def incident_acknowledge(
    incident_id: int, request: Request, db: DbDep, user: OperatorDep
) -> Response:
    incident = _get_incident(db, incident_id)
    try:
        service.acknowledge(incident, user, datetime.now(UTC))
    except service.IncidentClosed:
        flash(request, "L'incidente è già chiuso.", "error")
        return _back(incident)
    audit.record(db, user, "incident_acknowledge", "incident", incident.id)
    db.commit()
    flash(request, "Incidente preso in carico: i promemoria via mail si fermano.")
    return _back(incident)


@router.post("/{incident_id}/notes")
def incident_note(
    incident_id: int,
    request: Request,
    db: DbDep,
    user: OperatorDep,
    text: Annotated[str, Form()] = "",
) -> Response:
    incident = _get_incident(db, incident_id)
    text = text.strip()
    if not text or len(text) > NOTE_MAX_LENGTH:
        flash(
            request,
            f"Nota non salvata: serve un testo, al massimo {NOTE_MAX_LENGTH} caratteri.",
            "error",
        )
        return _back(incident)
    service.add_note(incident, user, text, datetime.now(UTC))
    audit.record(db, user, "incident_note", "incident", incident.id)
    db.commit()
    flash(request, "Nota aggiunta.")
    return _back(incident)


@router.post("/{incident_id}/close")
def incident_close(incident_id: int, request: Request, db: DbDep, user: OperatorDep) -> Response:
    incident = _get_incident(db, incident_id)
    try:
        service.close_manually(incident, user, datetime.now(UTC))
    except service.IncidentClosed:
        flash(request, "L'incidente è già chiuso.", "error")
        return _back(incident)
    audit.record(db, user, "incident_close", "incident", incident.id)
    db.commit()
    flash(request, "Incidente chiuso.")
    return _back(incident)
