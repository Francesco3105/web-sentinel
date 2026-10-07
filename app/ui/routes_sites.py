from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import case, select
from sqlalchemy.orm import Session, selectinload

from app.auth import audit
from app.auth.deps import AdminDep, DbDep, OperatorDep, UserDep, csrf_protect
from app.checks import sync_default_checks
from app.config import get_settings
from app.db.models import CheckResult, ContactKind, Criticality, Role, Site, SiteContact
from app.ui.forms import ContactData, SiteForm
from app.ui.rendering import flash, render
from app.worker.scheduler import run_and_record, runnable_checks

router = APIRouter(dependencies=[Depends(csrf_protect)])

CAN_RUN_CHECKS = (Role.ADMIN, Role.OPERATOR)

AUDITED_FIELDS = (
    "name",
    "url",
    "criticality",
    "active",
    "domain_check_enabled",
    "authorized_by",
    "authorized_at",
    "notes",
)


def _get_site(db: Session, site_id: int) -> Site:
    site = db.get(Site, site_id, options=[selectinload(Site.contacts), selectinload(Site.checks)])
    if site is None:
        raise HTTPException(status_code=404)
    return site


def _snapshot(site: Site) -> dict[str, Any]:
    values: dict[str, Any] = {name: getattr(site, name) for name in AUDITED_FIELDS}
    values["authorized_at"] = site.authorized_at.isoformat() if site.authorized_at else None
    for contact in site.contacts:
        values[f"contact_{contact.kind}"] = [contact.name, contact.email, contact.phone]
    return values


def _apply(site: Site, form: SiteForm) -> None:
    site.name = form.name
    site.url = form.url
    site.criticality = form.criticality
    site.active = form.active
    site.domain_check_enabled = form.domain_check_enabled
    site.authorized_by = form.authorized_by or None
    site.authorized_at = form.authorized_date
    site.notes = form.notes or None
    for kind in ContactKind:
        data = form.contacts[kind.value]
        contact = site.contact(kind)
        if contact is None:
            contact = SiteContact(kind=kind)
            site.contacts.append(contact)
        contact.name = data.name or None
        contact.email = data.email or None
        contact.phone = data.phone or None
    sync_default_checks(site)


def _form_from_site(site: Site) -> SiteForm:
    return SiteForm(
        name=site.name,
        url=site.url,
        criticality=site.criticality,
        active=site.active,
        domain_check_enabled=site.domain_check_enabled,
        authorized_by=site.authorized_by or "",
        authorized_at=site.authorized_at.isoformat() if site.authorized_at else "",
        notes=site.notes or "",
        contacts={
            kind.value: ContactData(
                name=(c.name or "") if (c := site.contact(kind)) else "",
                email=(c.email or "") if c else "",
                phone=(c.phone or "") if c else "",
            )
            for kind in ContactKind
        },
    )


def _url_taken(db: Session, url: str, exclude_id: int | None = None) -> bool:
    query = select(Site.id).where(Site.url == url)
    if exclude_id is not None:
        query = query.where(Site.id != exclude_id)
    return db.scalar(query) is not None


@router.get("/")
def home() -> Response:
    return RedirectResponse("/sites", status_code=303)


@router.get("/sites", response_class=HTMLResponse)
def site_list(request: Request, db: DbDep, user: UserDep) -> Response:
    by_criticality = case(
        (Site.criticality == Criticality.HIGH, 0),
        (Site.criticality == Criticality.MEDIUM, 1),
        else_=2,
    )
    sites = db.scalars(
        select(Site).options(selectinload(Site.checks)).order_by(by_criticality, Site.name)
    ).all()
    context = {
        "sites": sites,
        "status_counts": Counter(site.status for site in sites),
        "can_run": user.role in CAN_RUN_CHECKS,
        "runnable": any(runnable_checks(site) for site in sites),
    }
    return render(request, "sites/list.html", context, db=db, user=user)


@router.post("/sites/run-checks")
async def run_all_checks(request: Request, db: DbDep, user: OperatorDep) -> Response:
    """Run now every runnable check of all active, authorized sites."""
    sites = db.scalars(select(Site).options(selectinload(Site.checks))).all()
    by_site = {site.id: runnable_checks(site) for site in sites}
    checks = [check for site_checks in by_site.values() for check in site_checks]
    site_count = sum(1 for site_checks in by_site.values() if site_checks)
    if not checks:
        flash(request, "Controlli non eseguiti: nessun sito attivo con autorizzazione.", "error")
    else:
        count = await run_and_record(db, checks, get_settings().worker_max_concurrency)
        audit.record(db, user, "run_all_checks", details={"sites": site_count, "checks": count})
        db.commit()
        flash(request, f"Eseguiti {count} controlli su {site_count} siti autorizzati.")
    return RedirectResponse("/sites", status_code=303)


@router.get("/sites/new", response_class=HTMLResponse)
def site_new(request: Request, db: DbDep, user: AdminDep) -> Response:
    context = {"form": SiteForm(), "site": None}
    return render(request, "sites/form.html", context, db=db, user=user)


@router.post("/sites", response_class=HTMLResponse)
async def site_create(request: Request, db: DbDep, user: AdminDep) -> Response:
    form = SiteForm.parse(await request.form())
    if "url" not in form.errors and _url_taken(db, form.url):
        form.errors["url"] = "Esiste già un sito con questo URL."
    if form.errors:
        context = {"form": form, "site": None}
        return render(request, "sites/form.html", context, db=db, user=user, status_code=422)
    site = Site()
    _apply(site, form)
    db.add(site)
    db.flush()
    audit.record(db, user, "site_create", "site", site.id, _snapshot(site))
    db.commit()
    flash(request, f"Sito «{site.name}» creato.")
    return RedirectResponse(f"/sites/{site.id}", status_code=303)


@router.get("/sites/{site_id}", response_class=HTMLResponse)
def site_detail(site_id: int, request: Request, db: DbDep, user: UserDep) -> Response:
    site = _get_site(db, site_id)
    last_results = {
        check.id: db.scalar(
            select(CheckResult)
            .where(CheckResult.check_id == check.id)
            .order_by(CheckResult.id.desc())
            .limit(1)
        )
        for check in site.checks
    }
    context = {
        "site": site,
        "last_results": last_results,
        "can_run": user.role in CAN_RUN_CHECKS,
        "runnable": bool(runnable_checks(site)),
    }
    return render(request, "sites/detail.html", context, db=db, user=user)


@router.post("/sites/{site_id}/run-checks")
async def site_run_checks(site_id: int, request: Request, db: DbDep, user: OperatorDep) -> Response:
    site = _get_site(db, site_id)
    checks = runnable_checks(site)
    if not checks:
        flash(
            request,
            "Controlli non eseguiti: serve un sito attivo con autorizzazione registrata.",
            "error",
        )
    else:
        count = await run_and_record(db, checks, get_settings().worker_max_concurrency)
        audit.record(db, user, "site_run_checks", "site", site.id, {"checks": count})
        db.commit()
        flash(request, f"Eseguiti {count} controlli su «{site.name}».")
    return RedirectResponse(f"/sites/{site.id}", status_code=303)


@router.get("/sites/{site_id}/edit", response_class=HTMLResponse)
def site_edit(site_id: int, request: Request, db: DbDep, user: AdminDep) -> Response:
    site = _get_site(db, site_id)
    context = {"form": _form_from_site(site), "site": site}
    return render(request, "sites/form.html", context, db=db, user=user)


@router.post("/sites/{site_id}/edit", response_class=HTMLResponse)
async def site_update(site_id: int, request: Request, db: DbDep, user: AdminDep) -> Response:
    site = _get_site(db, site_id)
    form = SiteForm.parse(await request.form())
    if "url" not in form.errors and _url_taken(db, form.url, exclude_id=site.id):
        form.errors["url"] = "Esiste già un sito con questo URL."
    if form.errors:
        context = {"form": form, "site": site}
        return render(request, "sites/form.html", context, db=db, user=user, status_code=422)
    before = _snapshot(site)
    _apply(site, form)
    after = _snapshot(site)
    changes = {
        key: {"da": before.get(key), "a": value}
        for key, value in after.items()
        if before.get(key) != value
    }
    if changes:
        audit.record(db, user, "site_update", "site", site.id, changes)
    db.commit()
    flash(request, f"Sito «{site.name}» aggiornato.")
    return RedirectResponse(f"/sites/{site.id}", status_code=303)


@router.post("/sites/{site_id}/delete")
def site_delete(site_id: int, request: Request, db: DbDep, user: AdminDep) -> Response:
    site = _get_site(db, site_id)
    audit.record(db, user, "site_delete", "site", site.id, {"name": site.name, "url": site.url})
    db.delete(site)
    db.commit()
    flash(request, f"Sito «{site.name}» eliminato.")
    return RedirectResponse("/sites", status_code=303)
