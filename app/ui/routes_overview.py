from collections import Counter

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.auth.deps import DbDep, UserDep, csrf_protect
from app.db.models import Incident, IncidentStatus, Site
from app.ui import stats
from app.ui.rendering import render
from app.ui.routes_incidents import SEVERITY_RANK

router = APIRouter(dependencies=[Depends(csrf_protect)])

SEVERITY_ORDER = ("fail", "warn", "pending", "ok")


@router.get("/", response_class=HTMLResponse)
def overview(request: Request, db: DbDep, user: UserDep) -> Response:
    sites = list(db.scalars(select(Site).options(selectinload(Site.checks)).order_by(Site.name)))
    sites.sort(key=lambda site: SEVERITY_ORDER.index(site.status))
    monitored = [site for site in sites if site.active and site.is_authorized]
    incidents = db.scalars(
        select(Incident)
        .where(Incident.status != IncidentStatus.CLOSED)
        .order_by(Incident.id.desc())
    ).all()
    incidents = sorted(incidents, key=lambda item: (SEVERITY_RANK.get(item.severity, 9), -item.id))
    context = {
        "sites": sites,
        "site_by_id": {site.id: site for site in sites},
        "monitored": len(monitored),
        "operational": sum(1 for site in monitored if site.status in ("ok", "warn")),
        "incidents": incidents,
        "open_by_site": Counter(incident.site_id for incident in incidents),
        "uptime": stats.overall_uptime(db),
        "uptime_by_site": stats.uptime_by_site(db),
        "expiries": stats.expiries(db, sites),
    }
    return render(request, "overview.html", context, db=db, user=user)
