"""Check definitions: labels, defaults and the checks every site gets."""

from typing import Any
from urllib.parse import urlsplit

from app.db.models import Check, CheckType, Site

CHECK_LABELS = {
    "http": "HTTP/HTTPS",
    "dns": "DNS",
    "tls": "Certificato TLS",
    "domain": "Scadenza dominio",
    "endpoint": "Endpoint",
    "content": "Contenuto",
    "flow": "Flusso",
}

# type -> (interval seconds, timeout seconds, thresholds)
DEFAULTS: dict[CheckType, tuple[int, int, dict[str, Any]]] = {
    # Some managed sites answer very slowly: wait up to 2 minutes before calling it a failure.
    CheckType.HTTP: (300, 120, {"warn_ms": 30000}),
    CheckType.DNS: (600, 120, {"expected": []}),
    # Shown as a warning under warn_days; an alert is sent under alert_days.
    CheckType.TLS: (6 * 3600, 120, {"warn_days": 30, "alert_days": 7}),
    CheckType.DOMAIN: (24 * 3600, 120, {"warn_days": 30, "critical_days": 7}),
}


def hostname_of(url: str) -> str:
    return urlsplit(url).hostname or ""


def _target(site: Site, check_type: CheckType) -> str:
    if check_type == CheckType.HTTP:
        return site.url
    host = hostname_of(site.url)
    if check_type == CheckType.DOMAIN:
        # The check itself finds the registrable domain (see app.checks.domain).
        return host.removeprefix("www.")
    return host


def sync_default_checks(site: Site) -> None:
    """Ensure http/dns/tls checks exist and the domain check follows the site flag."""
    by_type = {check.type: check for check in site.checks}
    for check_type in (CheckType.HTTP, CheckType.DNS, CheckType.TLS, CheckType.DOMAIN):
        existing = by_type.get(check_type)
        if check_type == CheckType.DOMAIN and not site.domain_check_enabled:
            if existing is not None:
                existing.enabled = False
            continue
        if existing is None:
            interval, timeout, thresholds = DEFAULTS[check_type]
            site.checks.append(
                Check(
                    type=check_type,
                    target=_target(site, check_type),
                    interval_seconds=interval,
                    timeout_seconds=timeout,
                    thresholds=dict(thresholds),
                    enabled=True,
                )
            )
        else:
            existing.target = _target(site, check_type)
            if check_type == CheckType.DOMAIN:
                existing.enabled = True
