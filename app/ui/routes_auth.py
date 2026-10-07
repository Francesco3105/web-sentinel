from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select

from app.auth import audit
from app.auth.deps import DbDep, UserDep, csrf_protect, csrf_token
from app.auth.security import (
    MIN_PASSWORD_LENGTH,
    LoginLimiter,
    hash_password,
    verify_password,
)
from app.config import get_settings
from app.db.models import User
from app.ui.rendering import render

router = APIRouter(dependencies=[Depends(csrf_protect)])

_settings = get_settings()
limiter = LoginLimiter(_settings.login_max_attempts, _settings.login_window_seconds)
# Per-address limit is looser: several operators may share the same office address.
ip_limiter = LoginLimiter(_settings.login_max_attempts * 4, _settings.login_window_seconds)

# Verified when the user does not exist, so that response time does not reveal it.
_DUMMY_HASH = hash_password("web-sentinel-dummy-password")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    if request.session.get("uid") is not None:
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html")


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    db: DbDep,
    email: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
) -> Response:
    email = email.strip().lower()
    client = request.client.host if request.client else "unknown"
    if limiter.is_blocked(email) or ip_limiter.is_blocked(client):
        return render(
            request,
            "login.html",
            {"error": "Troppi tentativi falliti. Riprovare tra qualche minuto.", "email": email},
            status_code=429,
        )

    user = db.scalar(select(User).where(User.email == email))
    valid = verify_password(user.password_hash if user else _DUMMY_HASH, password)
    if user is None or not valid or not user.active:
        limiter.register_failure(email)
        ip_limiter.register_failure(client)
        audit.record(db, user, "login_failed", "user", user.id if user else None, user_email=email)
        db.commit()
        return render(
            request,
            "login.html",
            {"error": "Credenziali non valide.", "email": email},
            status_code=401,
        )

    limiter.reset(email)
    # New session and CSRF token on login (prevents session fixation).
    request.session.clear()
    request.session["uid"] = user.id
    # Remembered so that every page can ask for a proper password (see base.html).
    request.session["weak_password"] = len(password) < MIN_PASSWORD_LENGTH
    csrf_token(request)
    user.last_login_at = datetime.now(UTC)
    audit.record(db, user, "login", "user", user.id)
    db.commit()
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request, db: DbDep, user: UserDep) -> Response:
    audit.record(db, user, "logout", "user", user.id)
    db.commit()
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
