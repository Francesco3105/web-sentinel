"""FastAPI application: server-rendered UI and (from phase 4) the agent API."""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.auth.deps import CsrfError, NotAuthenticated, PermissionDenied
from app.config import get_settings
from app.db.models import User
from app.db.session import get_sessionmaker
from app.ui import routes_admin, routes_auth, routes_incidents, routes_overview, routes_sites
from app.ui.rendering import UI_DIR, render

ERROR_MESSAGES = {
    403: "Non hai i permessi per questa operazione.",
    404: "Pagina non trovata.",
}


def render_error(request: Request, message: str, status_code: int) -> Response:
    """Error page; a logged-in user keeps the menu and the worker state."""
    user_id = request.session.get("uid")
    if user_id is None:
        return render(request, "error.html", {"message": message}, status_code=status_code)
    with get_sessionmaker()() as db:
        user = db.get(User, user_id)
        if user is None or not user.active:
            return render(request, "error.html", {"message": message}, status_code=status_code)
        context = {"message": message}
        return render(request, "error.html", context, db=db, user=user, status_code=status_code)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Web Sentinel", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        return response

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="ws_session",
        max_age=settings.session_max_age_seconds,
        same_site="lax",
        https_only=settings.session_cookie_secure,
    )
    app.mount("/static", StaticFiles(directory=UI_DIR / "static"), name="static")

    app.include_router(routes_auth.router)
    app.include_router(routes_overview.router)
    app.include_router(routes_sites.router)
    app.include_router(routes_incidents.router)
    app.include_router(routes_admin.router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.exception_handler(NotAuthenticated)
    async def not_authenticated(request: Request, exc: NotAuthenticated) -> Response:
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(PermissionDenied)
    async def permission_denied(request: Request, exc: PermissionDenied) -> Response:
        return render_error(request, ERROR_MESSAGES[403], 403)

    @app.exception_handler(CsrfError)
    async def csrf_error(request: Request, exc: CsrfError) -> Response:
        message = "Sessione scaduta o richiesta non valida. Ricaricare la pagina e riprovare."
        return render_error(request, message, 403)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        message = ERROR_MESSAGES.get(exc.status_code, "Si è verificato un errore.")
        return render_error(request, message, exc.status_code)

    return app


app = create_app()
