from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.auth.deps import DbDep, UserDep, csrf_protect
from app.db.models import AlertLog, Incident, IncidentStatus, Site
from app.ui.rendering import render

router = APIRouter(prefix="/incidents", dependencies=[Depends(csrf_protect)])

PAGE_SIZE = 100
FILTERS = {"aperti": "Aperti", "chiusi": "Chiusi", "tutti": "Tutti"}


@router.get("", response_class=HTMLResponse)
def incident_list(request: Request, db: DbDep, user: UserDep, stato: str = "aperti") -> Response:
    if stato not in FILTERS:
        stato = "aperti"
    query = select(Incident).order_by(Incident.id.desc()).limit(PAGE_SIZE)
    if stato == "aperti":
        query = query.where(Incident.status != IncidentStatus.CLOSED)
    elif stato == "chiusi":
        query = query.where(Incident.status == IncidentStatus.CLOSED)
    incidents = db.scalars(query).all()
    sites = {site.id: site for site in db.scalars(select(Site))}
    context = {"incidents": incidents, "sites": sites, "filters": FILTERS, "current": stato}
    return render(request, "incidents/list.html", context, db=db, user=user)


@router.get("/{incident_id}", response_class=HTMLResponse)
def incident_detail(incident_id: int, request: Request, db: DbDep, user: UserDep) -> Response:
    incident = db.get(Incident, incident_id, options=[selectinload(Incident.events)])
    if incident is None:
        raise HTTPException(status_code=404)
    mails = db.scalars(
        select(AlertLog).where(AlertLog.incident_id == incident.id).order_by(AlertLog.id)
    ).all()
    context = {"incident": incident, "site": db.get(Site, incident.site_id), "mails": mails}
    return render(request, "incidents/detail.html", context, db=db, user=user)
