"""FastAPI dependencies for authentication, roles and CSRF protection."""

import hmac
import secrets
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.db.models import Role, User
from app.db.session import get_db

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class NotAuthenticated(Exception):
    pass


class PermissionDenied(Exception):
    pass


class CsrfError(Exception):
    pass


DbDep = Annotated[Session, Depends(get_db)]


def get_current_user(request: Request, db: DbDep) -> User:
    user_id = request.session.get("uid")
    if user_id is None:
        raise NotAuthenticated
    user = db.get(User, user_id)
    if user is None or not user.active:
        request.session.clear()
        raise NotAuthenticated
    return user


UserDep = Annotated[User, Depends(get_current_user)]


def require_role(*roles: Role) -> Callable[[User], User]:
    def dependency(user: UserDep) -> User:
        if user.role not in roles:
            raise PermissionDenied
        return user

    return dependency


AdminDep = Annotated[User, Depends(require_role(Role.ADMIN))]
OperatorDep = Annotated[User, Depends(require_role(Role.ADMIN, Role.OPERATOR))]


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


async def csrf_protect(request: Request) -> None:
    """Reject state-changing requests without the session's CSRF token."""
    if request.method in SAFE_METHODS:
        return
    expected = request.session.get("csrf")
    supplied = request.headers.get("x-csrf-token")
    if supplied is None:
        value = (await request.form()).get("csrf_token")
        supplied = value if isinstance(value, str) else None
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise CsrfError
