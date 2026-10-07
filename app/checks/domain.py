"""Domain expiry: RDAP first, WHOIS as a fallback. Plain lookups, nothing is sent to the site."""

import asyncio
import re
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from app.db.models import CheckStatus

RDAP_URL = "https://rdap.org/domain/{domain}"
IANA_WHOIS = "whois.iana.org"
WHOIS_PORT = 43
WHOIS_MAX_BYTES = 64_000
# Registries label the expiry date in many ways.
WHOIS_EXPIRY_RE = re.compile(
    r"^\s*(?:registry expiry date|registrar registration expiration date|expiration date|"
    r"expiry date|expire date|expires on|expires|paid-till|renewal date)\s*:\s*(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
WHOIS_REFER_RE = re.compile(r"^\s*(?:refer|whois)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
DATE_FORMATS = ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y.%m.%d", "%d.%m.%Y", "%d-%b-%Y", "%Y%m%d")


def candidates(host: str) -> list[str]:
    """Names to try, longest first: the registrable domain is the first one a registry knows.

    This avoids shipping the public suffix list: `www.example.co.uk` is tried as is, then as
    `example.co.uk`, which the registry answers for.
    """
    labels = [label for label in host.lower().strip(".").split(".") if label]
    return [".".join(labels[index:]) for index in range(max(len(labels) - 1, 1))]


def parse_date(value: str) -> datetime | None:
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
        for fmt in DATE_FORMATS:
            try:
                parsed = datetime.strptime(text[:11].rstrip("T"), fmt)  # noqa: DTZ007
            except ValueError:
                continue
            break
    if parsed is None:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


async def rdap_expiry(domain: str, timeout: int, user_agent: str) -> datetime | None:
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=timeout, headers={"User-Agent": user_agent}
    ) as client:
        try:
            response = await client.get(RDAP_URL.format(domain=domain))
        except httpx.HTTPError:
            return None
    if response.status_code != 200:
        return None
    try:
        events = response.json().get("events", [])
    except ValueError:
        return None
    for event in events:
        if event.get("eventAction") == "expiration" and event.get("eventDate"):
            return parse_date(str(event["eventDate"]))
    return None


async def whois_query(server: str, query: str, timeout: int) -> str:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(server, WHOIS_PORT), timeout=timeout
    )
    try:
        writer.write(f"{query}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(WHOIS_MAX_BYTES), timeout=timeout)
    finally:
        writer.close()
    return data.decode("utf-8", errors="replace")


async def whois_expiry(domain: str, timeout: int) -> datetime | None:
    try:
        referral = WHOIS_REFER_RE.search(await whois_query(IANA_WHOIS, domain, timeout))
        if referral is None:
            return None
        answer = await whois_query(referral.group(1), domain, timeout)
    except (OSError, TimeoutError):
        return None
    match = WHOIS_EXPIRY_RE.search(answer)
    return parse_date(match.group(1)) if match else None


async def find_expiry(host: str, timeout: int, user_agent: str) -> tuple[str, datetime] | None:
    for domain in candidates(host):
        expiry = await rdap_expiry(domain, timeout, user_agent)
        if expiry is None:
            expiry = await whois_expiry(domain, timeout)
        if expiry is not None:
            return domain, expiry
    return None


async def run_domain(target: str, timeout: int, thresholds: dict[str, Any]) -> tuple[Any, ...]:
    """Returns (status, value in days, message); wrapped into an Outcome by the runner."""
    from app.checks.runner import USER_AGENT

    # Several lookups may be needed: each gets a share of the time allowed.
    found = await find_expiry(target, max(timeout // 6, 5), USER_AGENT)
    if found is None:
        # Not a problem of the site: shown as a warning, never as a failure.
        return CheckStatus.WARN, None, "Scadenza del dominio non determinabile (RDAP e WHOIS)"
    domain, expiry = found
    days = int((expiry.timestamp() - time.time()) // 86400)
    when = expiry.strftime("%d/%m/%Y")
    if days < 0:
        return CheckStatus.FAIL, days, f"Dominio {domain} scaduto il {when}"
    if days < thresholds.get("warn_days", 30):
        return CheckStatus.WARN, days, f"Dominio {domain} in scadenza tra {days} giorni ({when})"
    return CheckStatus.OK, days, f"Dominio {domain} valido fino al {when} ({days} giorni)"
