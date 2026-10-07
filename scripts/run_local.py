"""Run Web Sentinel without Docker, on a local SQLite file. Development only.

Usage (from the project root, with the dependencies installed):
    python scripts/run_local.py
Reads SECRET_KEY, ADMIN_EMAIL and ADMIN_PASSWORD from .env.
"""

import os
import subprocess  # noqa: S404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

data_dir = ROOT / ".local"
data_dir.mkdir(exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(data_dir / 'websentinel.db').as_posix()}")
os.environ["SESSION_COOKIE_SECURE"] = "false"
os.environ["ENVIRONMENT"] = "development"
os.environ["PYTHONPATH"] = str(ROOT)


def main() -> None:
    import uvicorn
    from alembic import command
    from alembic.config import Config

    from app.config import get_settings
    from app.db.seed import seed
    from app.db.session import get_sessionmaker

    command.upgrade(Config("alembic.ini"), "head")
    with get_sessionmaker()() as db:
        seed(db, get_settings())

    worker = subprocess.Popen([sys.executable, "-m", "app.worker.main"])  # noqa: S603
    try:
        uvicorn.run("app.main:app", host="127.0.0.1", port=int(os.environ.get("WEB_PORT", "8000")))
    finally:
        worker.terminate()


if __name__ == "__main__":
    main()
