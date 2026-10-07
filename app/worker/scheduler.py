"""Selection of the checks that are due, their execution and the recording of results."""

import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.runner import RUNNERS, Outcome, execute
from app.db.models import Check, CheckResult, CheckStatus, Site


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def runnable_checks(site: Site) -> list[Check]:
    """Checks that may run now: none unless the site is active and authorized."""
    if not site.active or not site.is_authorized:
        return []
    return [check for check in site.checks if check.enabled and check.type in RUNNERS]


def due_checks(db: Session, now: datetime) -> list[Check]:
    due = []
    for site in db.scalars(select(Site).where(Site.active)):
        for check in runnable_checks(site):
            last = check.last_run_at
            if last is None or _aware(last) + timedelta(seconds=check.interval_seconds) <= now:
                due.append(check)
    return due


async def _run_all(checks: list[Check], max_concurrency: int) -> list[Outcome]:
    semaphore = asyncio.Semaphore(max_concurrency)

    async def run_one(check: Check) -> Outcome:
        async with semaphore:
            return await execute(
                check.type, check.target, check.timeout_seconds, check.thresholds or {}
            )

    return list(await asyncio.gather(*(run_one(check) for check in checks)))


async def run_and_record(db: Session, checks: list[Check], max_concurrency: int = 10) -> int:
    """Run the given checks concurrently and store one result per check."""
    if not checks:
        return 0
    outcomes = await _run_all(checks, max_concurrency)
    now = datetime.now(UTC)
    for check, outcome in zip(checks, outcomes, strict=True):
        db.add(
            CheckResult(
                check_id=check.id,
                site_id=check.site_id,
                status=outcome.status,
                value=outcome.value,
                message=outcome.message,
                duration_ms=outcome.duration_ms,
            )
        )
        check.last_status = outcome.status
        check.last_run_at = now
        failed = outcome.status == CheckStatus.FAIL
        check.consecutive_failures = check.consecutive_failures + 1 if failed else 0
    db.commit()
    return len(checks)
