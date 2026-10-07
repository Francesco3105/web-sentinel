"""Worker process: heartbeat and periodic execution of the checks that are due."""

import asyncio
import logging
import signal
import threading
from datetime import UTC, datetime
from types import FrameType

from sqlalchemy.orm import Session

from app.alerts import engine as alerts
from app.config import get_settings
from app.db.models import WorkerHeartbeat
from app.db.session import get_sessionmaker
from app.worker.scheduler import due_checks, run_and_record

logger = logging.getLogger("websentinel.worker")


def beat(db: Session, started_at: datetime, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    row = db.get(WorkerHeartbeat, 1)
    if row is None:
        db.add(WorkerHeartbeat(id=1, started_at=started_at, last_beat_at=now))
    else:
        row.started_at = started_at
        row.last_beat_at = now
    db.commit()


def tick(started_at: datetime, max_concurrency: int) -> None:
    with get_sessionmaker()() as db:
        beat(db, started_at)
        checks = due_checks(db, datetime.now(UTC))
        count = asyncio.run(run_and_record(db, checks, max_concurrency))
        if count:
            logger.info("ran %d checks", count)
        sent = alerts.process(db)
        if sent:
            logger.info("sent %d alert mails", sent)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    stop = threading.Event()

    def handle_signal(signum: int, frame: FrameType | None) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    started_at = datetime.now(UTC)
    logger.info("worker started")
    while not stop.is_set():
        try:
            tick(started_at, settings.worker_max_concurrency)
        except Exception:
            # The worker must never die because of one failed round.
            logger.exception("worker tick failed")
        stop.wait(settings.worker_tick_seconds)
    logger.info("worker stopped")


if __name__ == "__main__":
    main()
