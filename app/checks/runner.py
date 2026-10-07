"""Execution of the external checks: plain HTTP requests, DNS lookups and TLS handshakes."""

import asyncio
import socket
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from app.checks import domain
from app.db.models import CheckStatus, CheckType

USER_AGENT = "WebSentinel/1.0 (monitoraggio interno)"
MAX_REDIRECTS = 5
X509_CERT_HAS_EXPIRED = 10  # OpenSSL verify error code


@dataclass
class Outcome:
    status: CheckStatus
    value: float | None
    message: str
    duration_ms: int = 0


async def run_http(target: str, timeout: int, thresholds: dict[str, Any]) -> Outcome:
    async with httpx.AsyncClient(
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        started = time.monotonic()
        try:
            response = await client.get(target)
        except httpx.TimeoutException:
            return Outcome(CheckStatus.FAIL, None, f"Nessuna risposta entro {timeout} s")
        except httpx.TooManyRedirects:
            return Outcome(CheckStatus.FAIL, None, f"Più di {MAX_REDIRECTS} redirect")
        except httpx.HTTPError as exc:
            return Outcome(CheckStatus.FAIL, None, f"Sito non raggiungibile ({type(exc).__name__})")
        elapsed_ms = round((time.monotonic() - started) * 1000)
    message = f"HTTP {response.status_code} in {elapsed_ms} ms"
    if response.status_code >= 400:
        return Outcome(CheckStatus.FAIL, elapsed_ms, message)
    warn_ms = thresholds.get("warn_ms")
    if warn_ms and elapsed_ms > warn_ms:
        return Outcome(CheckStatus.WARN, elapsed_ms, f"{message}: risposta lenta")
    return Outcome(CheckStatus.OK, elapsed_ms, message)


async def resolve(host: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


async def run_dns(target: str, timeout: int, thresholds: dict[str, Any]) -> Outcome:
    try:
        addresses = await resolve(target)
    except socket.gaierror:
        addresses = []
    if not addresses:
        return Outcome(CheckStatus.FAIL, 0, "Il nome non risolve ad alcun indirizzo")
    message = "Risolve a " + ", ".join(addresses)
    expected = sorted(thresholds.get("expected") or [])
    if expected and addresses != expected:
        return Outcome(
            CheckStatus.WARN, len(addresses), f"{message} (attesi: {', '.join(expected)})"
        )
    return Outcome(CheckStatus.OK, len(addresses), message)


async def certificate_expiry(host: str, port: int = 443) -> float:
    """Complete a verified TLS handshake and return the certificate expiry (epoch seconds)."""
    _, writer = await asyncio.open_connection(
        host, port, ssl=ssl.create_default_context(), server_hostname=host
    )
    try:
        certificate = writer.get_extra_info("peercert")
    finally:
        writer.close()
    return float(ssl.cert_time_to_seconds(certificate["notAfter"]))


async def run_tls(target: str, timeout: int, thresholds: dict[str, Any]) -> Outcome:
    try:
        expires_at = await certificate_expiry(target)
    except ssl.SSLCertVerificationError as exc:
        if exc.verify_code == X509_CERT_HAS_EXPIRED:
            return Outcome(CheckStatus.FAIL, None, "Certificato scaduto")
        return Outcome(CheckStatus.FAIL, None, f"Certificato non valido: {exc.verify_message}")
    except (ssl.SSLError, OSError) as exc:
        return Outcome(
            CheckStatus.FAIL, None, f"Connessione TLS non riuscita ({type(exc).__name__})"
        )
    # An expiring certificate is only a warning; the check fails once it is expired or invalid.
    days = int((expires_at - time.time()) // 86400)
    if days < 0:
        return Outcome(CheckStatus.FAIL, days, "Certificato scaduto")
    if days < thresholds.get("warn_days", 30):
        return Outcome(CheckStatus.WARN, days, f"Certificato in scadenza tra {days} giorni")
    return Outcome(CheckStatus.OK, days, f"Certificato valido, scade tra {days} giorni")


async def run_domain(target: str, timeout: int, thresholds: dict[str, Any]) -> Outcome:
    status, value, message = await domain.run_domain(target, timeout, thresholds)
    return Outcome(status, value, message)


Runner = Callable[[str, int, dict[str, Any]], Awaitable[Outcome]]

RUNNERS: dict[str, Runner] = {
    CheckType.HTTP: run_http,
    CheckType.DNS: run_dns,
    CheckType.TLS: run_tls,
    CheckType.DOMAIN: run_domain,
}


async def execute(
    check_type: str, target: str, timeout: int, thresholds: dict[str, Any]
) -> Outcome:
    """Run one check. Never raises: any error or timeout becomes a failed outcome."""
    started = time.monotonic()
    try:
        outcome = await asyncio.wait_for(
            RUNNERS[check_type](target, timeout, thresholds), timeout=timeout + 2
        )
    except TimeoutError:
        outcome = Outcome(CheckStatus.FAIL, None, f"Nessuna risposta entro {timeout} s")
    except Exception as exc:  # noqa: BLE001 - one broken check must not stop the others
        outcome = Outcome(CheckStatus.FAIL, None, f"Errore del controllo ({type(exc).__name__})")
    outcome.duration_ms = round((time.monotonic() - started) * 1000)
    return outcome
