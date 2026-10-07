"""Load initial data. Usage: docker compose exec web python scripts/seed.py"""

from app.config import get_settings
from app.db.seed import seed
from app.db.session import get_sessionmaker


def main() -> None:
    with get_sessionmaker()() as db:
        created = seed(db, get_settings())
    print("Seed completato:", ", ".join(f"{name}: +{count}" for name, count in created.items()))


if __name__ == "__main__":
    main()
