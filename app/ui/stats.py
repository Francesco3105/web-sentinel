"""Figures shown in the dashboard: uptime, expiries and the response-time chart."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import Check, CheckResult, CheckStatus, CheckType, Site

UPTIME_DAYS = 30
EXPIRY_DAYS = 30
CHART_HOURS = 24
# Chart geometry, in SVG user units.
WIDTH, HEIGHT = 720, 190
LEFT, RIGHT, TOP, BOTTOM = 52, 12, 12, 28


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def uptime_by_site(db: Session, now: datetime | None = None) -> dict[int, float]:
    """Share of http checks that did not fail in the last 30 days, per site (0-100)."""
    since = (now or datetime.now(UTC)) - timedelta(days=UPTIME_DAYS)
    failed = func.sum(case((CheckResult.status == CheckStatus.FAIL, 1), else_=0))
    rows = db.execute(
        select(CheckResult.site_id, func.count(), failed)
        .join(Check, Check.id == CheckResult.check_id)
        .where(Check.type == CheckType.HTTP, CheckResult.created_at >= since)
        .group_by(CheckResult.site_id)
    )
    return {site_id: 100 * (total - (bad or 0)) / total for site_id, total, bad in rows if total}


def overall_uptime(db: Session, now: datetime | None = None) -> float | None:
    since = (now or datetime.now(UTC)) - timedelta(days=UPTIME_DAYS)
    failed = func.sum(case((CheckResult.status == CheckStatus.FAIL, 1), else_=0))
    total, bad = db.execute(
        select(func.count(), failed)
        .join(Check, Check.id == CheckResult.check_id)
        .where(Check.type == CheckType.HTTP, CheckResult.created_at >= since)
    ).one()
    return 100 * (total - (bad or 0)) / total if total else None


@dataclass
class Expiry:
    site: Site
    check: Check
    days: int


def expiries(db: Session, sites: list[Site]) -> list[Expiry]:
    """Certificates and domains expiring within 30 days, by the last result of each check."""
    found = []
    for site in sites:
        for check in site.checks:
            if not check.enabled or check.type not in (CheckType.TLS, CheckType.DOMAIN):
                continue
            value = db.scalar(
                select(CheckResult.value)
                .where(CheckResult.check_id == check.id)
                .order_by(CheckResult.id.desc())
                .limit(1)
            )
            if value is not None and value < EXPIRY_DAYS:
                found.append(Expiry(site, check, int(value)))
    return sorted(found, key=lambda item: item.days)


@dataclass
class Point:
    x: float
    y: float
    label: str


@dataclass
class Chart:
    width: int = WIDTH
    height: int = HEIGHT
    left: int = LEFT
    right: int = WIDTH - RIGHT
    top: int = TOP
    bottom: int = HEIGHT - BOTTOM
    # Each run of consecutive successful checks is one line.
    lines: list[str] = field(default_factory=list)
    points: list[Point] = field(default_factory=list)
    failures: list[Point] = field(default_factory=list)
    y_ticks: list[tuple[float, str]] = field(default_factory=list)
    x_ticks: list[tuple[float, str]] = field(default_factory=list)


def _nice_max(value: float) -> float:
    for step in (100, 200, 500, 1000, 2000, 5000, 10_000, 20_000, 30_000, 60_000, 120_000):
        if value <= step:
            return step
    return value


def _milliseconds(value: float) -> str:
    return f"{value / 1000:g} s".replace(".", ",") if value >= 1000 else f"{value:g} ms"


def _line(run: list[str]) -> str:
    """Points of one polyline; a lone point is doubled so that its round cap draws a dot."""
    if len(run) == 1:
        x, y = run[0].split(",")
        return f"{run[0]} {float(x) + 0.1},{y}"
    return " ".join(run)


def response_chart(db: Session, site: Site, now: datetime | None = None) -> Chart | None:
    """Response time of the http check over the last 24 hours, or None without data."""
    now = now or datetime.now(UTC)
    since = now - timedelta(hours=CHART_HOURS)
    check = next((item for item in site.checks if item.type == CheckType.HTTP), None)
    if check is None:
        return None
    results = db.scalars(
        select(CheckResult)
        .where(CheckResult.check_id == check.id, CheckResult.created_at >= since)
        .order_by(CheckResult.id)
    ).all()
    if not results:
        return None

    zone = ZoneInfo(get_settings().app_timezone)
    chart = Chart()
    span = (now - since).total_seconds()
    top_value = _nice_max(max((r.value or 0) for r in results) or 100)
    plot_width, plot_height = chart.right - chart.left, chart.bottom - chart.top

    def x_of(moment: datetime) -> float:
        offset = (_aware(moment) - since).total_seconds() / span
        return round(chart.left + min(max(offset, 0), 1) * plot_width, 1)

    run: list[str] = []
    for result in results:
        when = _aware(result.created_at).astimezone(zone).strftime("%d/%m %H:%M")
        x = x_of(result.created_at)
        if result.status == CheckStatus.FAIL or result.value is None:
            chart.failures.append(Point(x, chart.bottom, f"{when} – {result.message}"))
            if run:
                chart.lines.append(_line(run))
                run = []
            continue
        y = round(chart.bottom - min(result.value / top_value, 1) * plot_height, 1)
        chart.points.append(Point(x, y, f"{when} – {_milliseconds(result.value)}"))
        run.append(f"{x},{y}")
    if run:
        chart.lines.append(_line(run))

    for fraction in (0, 0.5, 1):
        y = round(chart.bottom - fraction * plot_height, 1)
        chart.y_ticks.append((y, _milliseconds(top_value * fraction)))
    for hours in (24, 18, 12, 6, 0):
        moment = now - timedelta(hours=hours)
        chart.x_ticks.append((x_of(moment), moment.astimezone(zone).strftime("%H:%M")))
    return chart
