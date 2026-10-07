from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import audit
from app.auth.deps import AdminDep, DbDep, csrf_protect
from app.auth.security import hash_password
from app.db.models import AuditLog, Role, User
from app.ui.forms import UserForm
from app.ui.rendering import flash, render

router = APIRouter(prefix="/admin", dependencies=[Depends(csrf_protect)])

AUDIT_PAGE_SIZE = 100


def _get_user(db: Session, user_id: int) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404)
    return target


def _other_active_admins(db: Session, user_id: int) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.ADMIN, User.active, User.id != user_id)
        )
        or 0
    )


@router.get("/users", response_class=HTMLResponse)
def user_list(request: Request, db: DbDep, user: AdminDep) -> Response:
    users = db.scalars(select(User).order_by(User.email)).all()
    return render(request, "admin/users.html", {"users": users}, db=db, user=user)


@router.get("/users/new", response_class=HTMLResponse)
def user_new(request: Request, db: DbDep, user: AdminDep) -> Response:
    context = {"form": UserForm(), "target": None}
    return render(request, "admin/user_form.html", context, db=db, user=user)


@router.post("/users", response_class=HTMLResponse)
async def user_create(request: Request, db: DbDep, user: AdminDep) -> Response:
    form = UserForm.parse(await request.form(), password_required=True)
    if "email" not in form.errors and db.scalar(select(User.id).where(User.email == form.email)):
        form.errors["email"] = "Esiste già un utente con questa mail."
    if form.errors:
        context = {"form": form, "target": None}
        return render(request, "admin/user_form.html", context, db=db, user=user, status_code=422)
    target = User(
        email=form.email,
        full_name=form.full_name,
        role=form.role,
        active=form.active,
        password_hash=hash_password(form.password),
    )
    db.add(target)
    db.flush()
    details = {"email": target.email, "role": target.role, "active": target.active}
    audit.record(db, user, "user_create", "user", target.id, details)
    db.commit()
    flash(request, f"Utente {target.email} creato.")
    return RedirectResponse("/admin/users", status_code=303)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
def user_edit(user_id: int, request: Request, db: DbDep, user: AdminDep) -> Response:
    target = _get_user(db, user_id)
    form = UserForm(
        email=target.email, full_name=target.full_name, role=target.role, active=target.active
    )
    context = {"form": form, "target": target}
    return render(request, "admin/user_form.html", context, db=db, user=user)


@router.post("/users/{user_id}/edit", response_class=HTMLResponse)
async def user_update(user_id: int, request: Request, db: DbDep, user: AdminDep) -> Response:
    target = _get_user(db, user_id)
    form = UserForm.parse(await request.form(), password_required=False)
    if "email" not in form.errors and db.scalar(
        select(User.id).where(User.email == form.email, User.id != target.id)
    ):
        form.errors["email"] = "Esiste già un utente con questa mail."
    loses_admin = target.role == Role.ADMIN and (form.role != Role.ADMIN or not form.active)
    if loses_admin and target.active and _other_active_admins(db, target.id) == 0:
        form.errors["role"] = "Deve restare almeno un amministratore attivo."
    if form.errors:
        context = {"form": form, "target": target}
        return render(request, "admin/user_form.html", context, db=db, user=user, status_code=422)

    changes: dict[str, object] = {}
    for name in ("email", "full_name", "role", "active"):
        new_value = getattr(form, name)
        if getattr(target, name) != new_value:
            changes[name] = {"da": getattr(target, name), "a": new_value}
            setattr(target, name, new_value)
    if form.password:
        target.password_hash = hash_password(form.password)
        changes["password"] = "modificata"  # noqa: S105
        if target.id == user.id:
            request.session["weak_password"] = False
    if changes:
        audit.record(db, user, "user_update", "user", target.id, changes)
    db.commit()
    flash(request, f"Utente {target.email} aggiornato.")
    return RedirectResponse("/admin/users", status_code=303)


@router.get("/audit", response_class=HTMLResponse)
def audit_list(request: Request, db: DbDep, user: AdminDep, page: int = 1) -> Response:
    page = max(page, 1)
    entries = db.scalars(
        select(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(AUDIT_PAGE_SIZE + 1)
        .offset((page - 1) * AUDIT_PAGE_SIZE)
    ).all()
    context = {
        "entries": entries[:AUDIT_PAGE_SIZE],
        "page": page,
        "has_next": len(entries) > AUDIT_PAGE_SIZE,
    }
    return render(request, "admin/audit.html", context, db=db, user=user)
