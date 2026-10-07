"""Opening, escalation and automatic closing of incidents from check results."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks import CHECK_LABELS
from app.checks.runner import Outcome
from app.config import get_settings
from app.db.models import (
    Check,
    CheckStatus,
    CheckType,
    Incident,
    IncidentEvent,
    IncidentStatus,
    Severity,
)

DEFAULT_TLS_ALERT_DAYS = 7

RECOMMENDED_ACTIONS = {
    (CheckType.HTTP, Severity.CRITICAL): (
        "Verificare che il sito risponda da un'altra rete, poi controllare web server e "
        "hosting. Se il sito risponde, verificare che l'indirizzo di Web Sentinel non sia "
        "bloccato da firewall o WAF."
    ),
    (CheckType.DNS, Severity.CRITICAL): (
        "Verificare i record DNS del dominio presso il gestore e lo stato della registrazione."
    ),
    (CheckType.TLS, Severity.CRITICAL): (
        "Rinnovare o correggere il certificato: i visitatori vedono un avviso di sicurezza."
    ),
    (CheckType.TLS, Severity.WARNING): (
        "Rinnovare il certificato prima della scadenza e verificare che il rinnovo automatico "
        "sia attivo."
    ),
}
DEFAULT_ACTION = "Verificare il controllo dalla scheda del sito e ripeterlo a mano."


def problem_severity(check: Check, outcome: Outcome, failure_threshold: int) -> str | None:
    """Severity the result calls for, or None when there is nothing to report.

    "pending" means a failure not yet confirmed: an open incident is left as it is.
    """
    if outcome.status == CheckStatus.FAIL:
        if check.consecutive_failures >= failure_threshold:
            return Severity.CRITICAL
        return "pending"
    # A slow answer is shown in the interface but never opens an incident.
    if check.type == CheckType.TLS and outcome.value is not None:
        alert_days = (check.thresholds or {}).get("alert_days", DEFAULT_TLS_ALERT_DAYS)
        if outcome.value < alert_days:
            return Severity.WARNING
    return None


def open_incident_for(db: Session, check: Check) -> Incident | None:
    return db.scalar(
        select(Incident)
        .where(Incident.check_id == check.id, Incident.status != IncidentStatus.CLOSED)
        .order_by(Incident.id.desc())
        .limit(1)
    )


def open_critical_for_site(db: Session, site_id: int) -> Incident | None:
    return db.scalar(
        select(Incident)
        .where(
            Incident.site_id == site_id,
            Incident.severity == Severity.CRITICAL,
            Incident.status != IncidentStatus.CLOSED,
        )
        .order_by(Incident.id)
        .limit(1)
    )


def _label(check: Check) -> str:
    return CHECK_LABELS.get(check.type, check.type)


def _title(check: Check, outcome: Outcome) -> str:
    return f"{_label(check)}: {outcome.message}"[:300]


def _close(incident: Incident, message: str, now: datetime) -> None:
    incident.status = IncidentStatus.CLOSED
    incident.closed_at = now
    incident.events.append(IncidentEvent(kind="recovered", message=message, created_at=now))


def evaluate(db: Session, check: Check, outcome: Outcome, now: datetime) -> Incident | None:
    """Apply one check result. The caller commits. Returns the incident it touched, if any.

    A site has at most one open critical incident: when several of its checks fail (a site
    that is down fails http, dns and tls together) the later ones are added to it as events,
    so that one problem produces one stream of mails.
    """
    threshold = get_settings().incident_failure_threshold
    severity = problem_severity(check, outcome, threshold)
    own = open_incident_for(db, check)
    if severity == "pending":
        return own

    if severity is None:
        if own is not None and own.severity != Severity.CRITICAL:
            _close(own, outcome.message, now)
        critical = open_critical_for_site(db, check.site_id)
        still_failing = any(
            other.enabled and other.consecutive_failures >= threshold for other in check.site.checks
        )
        if critical is not None and not still_failing:
            _close(critical, f"{_label(check)}: {outcome.message}", now)
        return critical or own

    action = RECOMMENDED_ACTIONS.get((CheckType(check.type), Severity(severity)), DEFAULT_ACTION)
    if severity == Severity.CRITICAL:
        critical = open_critical_for_site(db, check.site_id)
        if critical is not None and critical.check_id != check.id:
            prefix = f"{_label(check)}:"
            known = any(
                event.kind == "correlated" and event.message.startswith(prefix)
                for event in critical.events
            )
            if not known:
                critical.events.append(
                    IncidentEvent(
                        kind="correlated", message=f"{prefix} {outcome.message}", created_at=now
                    )
                )
            return critical

    if own is None:
        own = Incident(
            site_id=check.site_id,
            check_id=check.id,
            severity=severity,
            title=_title(check, outcome),
            status=IncidentStatus.OPEN,
            recommended_action=action,
            opened_at=now,
        )
        own.events.append(IncidentEvent(kind="opened", message=outcome.message, created_at=now))
        db.add(own)
    elif own.severity != severity:
        own.events.append(
            IncidentEvent(
                kind="severity_changed",
                message=f"Da {own.severity} a {severity}: {outcome.message}",
                created_at=now,
            )
        )
        own.severity = severity
        own.title = _title(check, outcome)
        own.recommended_action = action
    return own
