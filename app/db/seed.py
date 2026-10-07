"""Initial data: sites in management, alert rules, default recipient, first admin."""

from datetime import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.security import MIN_PASSWORD_LENGTH, hash_password
from app.checks import sync_default_checks
from app.config import Settings
from app.db.models import (
    AlertRecipient,
    AlertRule,
    ContactKind,
    Criticality,
    Role,
    Severity,
    Site,
    SiteContact,
    User,
)

# (name, url, criticality, domain check enabled)
# Example sites on the domains reserved for documentation (RFC 2606): replace them from the
# interface with the sites really under management. The domain check is off for the subdomain,
# as it should be for subdomains whose registration is managed by someone else.
SITES: list[tuple[str, str, Criticality, bool]] = [
    ("Sito Esempio", "https://example.com/", Criticality.HIGH, True),
    ("Portale Esempio", "https://www.example.org/", Criticality.HIGH, True),
    ("Vetrina Esempio", "https://example.net/", Criticality.MEDIUM, True),
    ("Servizi Esempio (sottodominio)", "https://www.example.com/", Criticality.HIGH, False),
]

ALERT_RULES: list[AlertRule] = [
    AlertRule(
        severity=Severity.INFO,
        immediate=False,
        digest_time=time(8, 0),
        recovery_mode="none",
    ),
    AlertRule(
        severity=Severity.WARNING,
        active_from=time(8, 0),
        active_to=time(20, 0),
        dedup_minutes=360,
        recovery_mode="auto",
    ),
    AlertRule(severity=Severity.CRITICAL, reminder_minutes=30, recovery_mode="auto"),
    AlertRule(severity=Severity.SECURITY, dedup_minutes=60, recovery_mode="manual"),
    AlertRule(severity=Severity.MALWARE, recovery_mode="manual", silenceable=False),
]


def seed(db: Session, settings: Settings) -> dict[str, int]:
    """Idempotent: existing rows are left untouched. Returns how many rows were created."""
    created = {"sites": 0, "alert_rules": 0, "alert_recipients": 0, "users": 0}

    existing_urls = set(db.scalars(select(Site.url)))
    for name, url, criticality, domain_check in SITES:
        if url in existing_urls:
            continue
        site = Site(
            name=name,
            url=url,
            criticality=criticality,
            active=True,
            domain_check_enabled=domain_check,
            contacts=[SiteContact(kind=kind) for kind in ContactKind],
        )
        sync_default_checks(site)
        db.add(site)
        created["sites"] += 1

    existing_severities = set(db.scalars(select(AlertRule.severity)))
    for rule in ALERT_RULES:
        if rule.severity not in existing_severities:
            db.add(
                AlertRule(
                    severity=rule.severity,
                    immediate=True if rule.immediate is None else rule.immediate,
                    active_from=rule.active_from,
                    active_to=rule.active_to,
                    digest_time=rule.digest_time,
                    dedup_minutes=rule.dedup_minutes,
                    reminder_minutes=rule.reminder_minutes,
                    recovery_mode=rule.recovery_mode,
                    silenceable=True if rule.silenceable is None else rule.silenceable,
                )
            )
            created["alert_rules"] += 1

    if not db.scalar(select(func.count()).select_from(AlertRecipient)):
        db.add(AlertRecipient(email=settings.alert_default_recipient))
        created["alert_recipients"] += 1

    if not db.scalar(select(func.count()).select_from(User)):
        # Short passwords are tolerated only outside production (local trials).
        min_length = MIN_PASSWORD_LENGTH if settings.environment == "production" else 1
        if not settings.admin_email or len(settings.admin_password) < min_length:
            raise ValueError(
                "ADMIN_EMAIL e ADMIN_PASSWORD (in produzione almeno "
                f"{MIN_PASSWORD_LENGTH} caratteri) devono essere impostati in .env"
            )
        db.add(
            User(
                email=settings.admin_email.strip().lower(),
                full_name="Amministratore",
                password_hash=hash_password(settings.admin_password),
                role=Role.ADMIN,
            )
        )
        created["users"] += 1

    db.commit()
    return created
