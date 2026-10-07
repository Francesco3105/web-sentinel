"""Jinja2 environment, labels and helpers shared by the UI routes."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth.deps import csrf_token
from app.checks import CHECK_LABELS
from app.config import get_settings
from app.db.models import User, WorkerHeartbeat

UI_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=UI_DIR / "templates")

CRITICALITY_LABELS = {"high": "Alta", "medium": "Media", "low": "Bassa"}
ROLE_LABELS = {"admin": "Amministratore", "operator": "Operatore", "viewer": "Sola lettura"}
# status -> (label, badge style)
STATUS_LABELS = {
    "ok": ("OK", "ok"),
    "warn": ("Attenzione", "warning"),
    "fail": ("Errore", "critical"),
    "pending": ("In attesa", "muted"),
}
# severity -> (label, badge style)
SEVERITY_LABELS = {
    "info": ("Informazione", "info"),
    "warning": ("Attenzione", "warning"),
    "critical": ("Critico", "critical"),
    "security": ("Sicurezza", "security"),
    "malware": ("Malware", "malware"),
}
INCIDENT_STATUS_LABELS = {"open": "Aperto", "acknowledged": "Preso in carico", "closed": "Chiuso"}
EVENT_LABELS = {
    "opened": "Aperto",
    "recovered": "Rientrato",
    "severity_changed": "Cambio di gravità",
    "correlated": "Altro controllo fallito",
}
MAIL_KIND_LABELS = {"opened": "Apertura", "reminder": "Promemoria", "recovery": "Rientro"}
CONTACT_LABELS = {"technical": "Referente tecnico", "business": "Referente business"}
ACTION_LABELS = {
    "login": "Accesso",
    "login_failed": "Accesso fallito",
    "logout": "Uscita",
    "site_create": "Sito creato",
    "site_update": "Sito modificato",
    "site_delete": "Sito eliminato",
    "site_run_checks": "Controlli eseguiti a mano",
    "run_all_checks": "Controlli eseguiti a mano su tutti i siti",
    "user_create": "Utente creato",
    "user_update": "Utente modificato",
}


def format_datetime(value: datetime | None, fmt: str = "%d/%m/%Y %H:%M") -> str:
    if value is None:
        return "–"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(ZoneInfo(get_settings().app_timezone)).strftime(fmt)


def format_interval(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} s"


templates.env.filters["dt"] = format_datetime
templates.env.filters["interval"] = format_interval
templates.env.globals.update(
    # Changes at every start, so browsers never keep a stale stylesheet or script.
    asset_version=str(int(datetime.now(UTC).timestamp())),
    criticality_labels=CRITICALITY_LABELS,
    role_labels=ROLE_LABELS,
    check_labels=CHECK_LABELS,
    status_labels=STATUS_LABELS,
    severity_labels=SEVERITY_LABELS,
    incident_status_labels=INCIDENT_STATUS_LABELS,
    event_labels=EVENT_LABELS,
    mail_kind_labels=MAIL_KIND_LABELS,
    contact_labels=CONTACT_LABELS,
    action_labels=ACTION_LABELS,
)


def worker_status(db: Session) -> dict[str, Any]:
    row = db.get(WorkerHeartbeat, 1)
    if row is None:
        return {"state": "unknown", "label": "Worker mai avviato", "last_beat_at": None}
    last_beat_at = row.last_beat_at
    if last_beat_at.tzinfo is None:  # SQLite (local run without Docker) drops the time zone
        last_beat_at = last_beat_at.replace(tzinfo=UTC)
    age = (datetime.now(UTC) - last_beat_at).total_seconds()
    if age > get_settings().worker_stale_seconds:
        return {"state": "down", "label": "Worker fermo", "last_beat_at": last_beat_at}
    return {"state": "ok", "label": "Worker attivo", "last_beat_at": last_beat_at}


def flash(request: Request, message: str, kind: str = "ok") -> None:
    request.session["flash"] = {"message": message, "kind": kind}


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    db: Session | None = None,
    user: User | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    full: dict[str, Any] = {
        "user": user,
        "csrf_token": csrf_token(request),
        "flash": request.session.pop("flash", None),
        "weak_password": bool(user) and bool(request.session.get("weak_password")),
        "worker": worker_status(db) if db is not None and user is not None else None,
    }
    full.update(context or {})
    return templates.TemplateResponse(request, name, full, status_code=status_code)
