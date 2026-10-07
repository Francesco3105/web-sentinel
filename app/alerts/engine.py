"""Decides which alert mails are due, from the incidents and the rules of each severity.

`alert_log` is both the record of what was sent and the memory used to avoid duplicates.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.alerts import mailer
from app.alerts.mailer import Mail
from app.config import Settings, get_settings
from app.db.models import (
    AlertLog,
    AlertRecipient,
    AlertRule,
    Check,
    CheckResult,
    Incident,
    IncidentStatus,
    Site,
)

logger = logging.getLogger("websentinel.alerts")

Sender = Callable[[Settings, Mail], None]

OPENED, REMINDER, RECOVERY = "opened", "reminder", "recovery"
SENT, FAILED, DEDUPLICATED = "sent", "failed", "deduplicated"
# A failed delivery is not retried at every worker round.
RETRY_AFTER = timedelta(minutes=5)
# Recoveries of incidents closed longer ago are not worth a mail any more.
RECOVERY_WINDOW = timedelta(hours=24)
RECOVERY_SCAN_LIMIT = 200
SEVERITY_TAGS = {"info": "INFO", "warning": "WARNING", "critical": "CRITICAL"}
SEVERITY_LABELS = {"info": "Informazione", "warning": "Attenzione", "critical": "Critico"}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _within_window(rule: AlertRule, now: datetime, timezone: str) -> bool:
    if rule.active_from is None or rule.active_to is None:
        return True
    local = now.astimezone(ZoneInfo(timezone)).time()
    return rule.active_from <= local < rule.active_to


def _logs(db: Session, incident: Incident, kinds: tuple[str, ...]) -> list[AlertLog]:
    return list(
        db.scalars(
            select(AlertLog)
            .where(AlertLog.incident_id == incident.id, AlertLog.kind.in_(kinds))
            .order_by(AlertLog.id)
        )
    )


def _last(logs: list[AlertLog], status: str) -> AlertLog | None:
    return next((log for log in reversed(logs) if log.status == status), None)


def _recently_failed(logs: list[AlertLog], now: datetime) -> bool:
    failed = _last(logs, FAILED)
    return failed is not None and now - _aware(failed.sent_at) < RETRY_AFTER


def _recipients(db: Session, incident: Incident) -> list[str]:
    rows = db.scalars(
        select(AlertRecipient.email).where(
            AlertRecipient.active,
            or_(AlertRecipient.site_id.is_(None), AlertRecipient.site_id == incident.site_id),
            or_(AlertRecipient.severity.is_(None), AlertRecipient.severity == incident.severity),
        )
    )
    return sorted(set(rows))


def _duration(start: datetime, end: datetime) -> str:
    minutes = max(int((end - start).total_seconds() // 60), 0)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = [f"{days} g" if days else "", f"{hours} h" if hours else "", f"{minutes} min"]
    return " ".join(part for part in parts if part)


def _subject(kind: str, incident: Incident, site: Site) -> str:
    tag = "RISOLTO" if kind == RECOVERY else SEVERITY_TAGS.get(incident.severity, "ALERT")
    suffix = " (promemoria)" if kind == REMINDER else ""
    return f"[{tag}] {site.name} – {incident.title}{suffix}"[:500]


def _context(
    db: Session, kind: str, incident: Incident, site: Site, now: datetime, settings: Settings
) -> dict[str, object]:
    zone = ZoneInfo(settings.app_timezone)

    def local(value: datetime | None) -> str:
        return _aware(value).astimezone(zone).strftime("%d/%m/%Y %H:%M") if value else "–"

    check = db.get(Check, incident.check_id) if incident.check_id else None
    result = None
    if check is not None:
        result = db.scalar(
            select(CheckResult)
            .where(CheckResult.check_id == check.id)
            .order_by(CheckResult.id.desc())
            .limit(1)
        )
    end = _aware(incident.closed_at) if incident.closed_at else now
    base = settings.app_base_url.rstrip("/")
    return {
        "kind": kind,
        "severity": incident.severity,
        "severity_label": SEVERITY_LABELS.get(incident.severity, incident.severity),
        "incident": incident,
        "site": site,
        "opened_at": local(incident.opened_at),
        "closed_at": local(incident.closed_at),
        "duration": _duration(_aware(incident.opened_at), end),
        "last_message": result.message if result else None,
        "last_checked_at": local(result.created_at) if result else None,
        "consecutive_failures": check.consecutive_failures if check else None,
        "events": [(local(event.created_at), event.message) for event in incident.events[-5:]],
        "incident_url": f"{base}/incidents/{incident.id}",
        "site_url": f"{base}/sites/{site.id}",
    }


def _deliver(
    db: Session,
    kind: str,
    incident: Incident,
    now: datetime,
    settings: Settings,
    sender: Sender,
) -> int:
    """Send one notification to every recipient and log each attempt. Returns mails sent."""
    site = db.get(Site, incident.site_id)
    if site is None:
        return 0
    subject = _subject(kind, incident, site)
    context = _context(db, kind, incident, site, now, settings)
    try:
        recipients = mailer.effective_recipients(settings, _recipients(db, incident))
    except mailer.DeliveryRefused as exc:
        recipients, refusal = [], str(exc)
    else:
        refusal = "Nessun destinatario attivo" if not recipients else ""
    if refusal:
        logger.error("alert not sent for incident %s: %s", incident.id, refusal)
        db.add(_log(incident, kind, "-", subject, FAILED, now, refusal))
        return 0

    sent = 0
    for recipient in recipients:
        try:
            sender(settings, mailer.render(subject, context, recipient))
        except Exception as exc:  # noqa: BLE001 - a mail problem must never stop the worker
            logger.exception("alert delivery failed for incident %s", incident.id)
            db.add(_log(incident, kind, recipient, subject, FAILED, now, f"{type(exc).__name__}"))
        else:
            sent += 1
            db.add(_log(incident, kind, recipient, subject, SENT, now))
    return sent


def _log(
    incident: Incident,
    kind: str,
    recipient: str,
    subject: str,
    status: str,
    now: datetime,
    error: str | None = None,
) -> AlertLog:
    return AlertLog(
        incident_id=incident.id,
        site_id=incident.site_id,
        severity=incident.severity,
        kind=kind,
        recipient=recipient,
        subject=subject,
        status=status,
        error=error,
        sent_at=now,
    )


def _same_problem_recently(db: Session, incident: Incident, minutes: int, now: datetime) -> bool:
    """True when the same check already produced a mail of this severity within the window."""
    if incident.check_id is None:
        return False
    earlier = db.scalar(
        select(AlertLog.sent_at)
        .join(Incident, Incident.id == AlertLog.incident_id)
        .where(
            Incident.check_id == incident.check_id,
            Incident.id != incident.id,
            AlertLog.kind == OPENED,
            AlertLog.status == SENT,
            AlertLog.severity == incident.severity,
        )
        .order_by(AlertLog.id.desc())
        .limit(1)
    )
    return earlier is not None and now - _aware(earlier) < timedelta(minutes=minutes)


def process(
    db: Session,
    now: datetime | None = None,
    settings: Settings | None = None,
    sender: Sender = mailer.send,
) -> int:
    """Send every alert that is due. Returns the number of mails sent."""
    now = now or datetime.now(UTC)
    settings = settings or get_settings()
    rules = {rule.severity: rule for rule in db.scalars(select(AlertRule))}
    sent = 0

    open_incidents = db.scalars(
        select(Incident).where(Incident.status != IncidentStatus.CLOSED).order_by(Incident.id)
    ).all()
    for incident in open_incidents:
        rule = rules.get(incident.severity)
        if rule is None or not rule.immediate:
            continue
        logs = _logs(db, incident, (OPENED, REMINDER))
        # After a change of severity the incident is announced again.
        announced = [
            log for log in logs if log.kind == OPENED and log.severity == incident.severity
        ]
        if not _last(announced, SENT) and not _last(announced, DEDUPLICATED):
            if _recently_failed(announced, now) or not _within_window(
                rule, now, settings.app_timezone
            ):
                continue
            if rule.dedup_minutes and _same_problem_recently(db, incident, rule.dedup_minutes, now):
                site = db.get(Site, incident.site_id)
                subject = _subject(OPENED, incident, site) if site else incident.title
                db.add(_log(incident, OPENED, "-", subject, DEDUPLICATED, now))
                continue
            sent += _deliver(db, OPENED, incident, now, settings, sender)
        elif rule.reminder_minutes and _last(announced, SENT):
            last_sent = _last(logs, SENT)
            due = last_sent is not None and now - _aware(last_sent.sent_at) >= timedelta(
                minutes=rule.reminder_minutes
            )
            reminders = [log for log in logs if log.kind == REMINDER]
            if due and not _recently_failed(reminders, now):
                sent += _deliver(db, REMINDER, incident, now, settings, sender)

    # Filtered here rather than in SQL: SQLite stores these timestamps without a time zone.
    closed = db.scalars(
        select(Incident)
        .where(Incident.status == IncidentStatus.CLOSED, Incident.closed_at.is_not(None))
        .order_by(Incident.id.desc())
        .limit(RECOVERY_SCAN_LIMIT)
    ).all()
    for incident in reversed(closed):
        if incident.closed_at is None or now - _aware(incident.closed_at) > RECOVERY_WINDOW:
            continue
        rule = rules.get(incident.severity)
        if rule is None or rule.recovery_mode != "auto":
            continue
        # A recovery is only worth a mail when the problem itself was announced.
        if not _last(_logs(db, incident, (OPENED,)), SENT):
            continue
        recoveries = _logs(db, incident, (RECOVERY,))
        if _last(recoveries, SENT) or _recently_failed(recoveries, now):
            continue
        if not _within_window(rule, now, settings.app_timezone):
            continue
        sent += _deliver(db, RECOVERY, incident, now, settings, sender)

    db.commit()
    return sent
