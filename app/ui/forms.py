"""Parsing and validation of HTML forms."""

import re
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlsplit

from starlette.datastructures import FormData

from app.auth.security import MIN_PASSWORD_LENGTH
from app.db.models import ContactKind, Criticality, Role

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Users log in with a mail address or with a plain user name.
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def _text(form: FormData, name: str) -> str:
    value = form.get(name)
    return value.strip() if isinstance(value, str) else ""


def _checked(form: FormData, name: str) -> bool:
    return form.get(name) is not None


def normalize_url(raw: str) -> str | None:
    """Return the URL if it is a plain http(s) URL with a hostname, else None."""
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.username or parts.password:
        return None
    return raw


@dataclass
class ContactData:
    name: str = ""
    email: str = ""
    phone: str = ""


@dataclass
class SiteForm:
    name: str = ""
    url: str = ""
    criticality: str = Criticality.MEDIUM
    active: bool = True
    domain_check_enabled: bool = False
    authorized_by: str = ""
    authorized_at: str = ""
    notes: str = ""
    contacts: dict[str, ContactData] = field(
        default_factory=lambda: {kind.value: ContactData() for kind in ContactKind}
    )
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def authorized_date(self) -> date | None:
        return date.fromisoformat(self.authorized_at) if self.authorized_at else None

    @classmethod
    def parse(cls, form: FormData) -> "SiteForm":
        data = cls(
            name=_text(form, "name"),
            url=_text(form, "url"),
            criticality=_text(form, "criticality"),
            active=_checked(form, "active"),
            domain_check_enabled=_checked(form, "domain_check_enabled"),
            authorized_by=_text(form, "authorized_by"),
            authorized_at=_text(form, "authorized_at"),
            notes=_text(form, "notes"),
            contacts={
                kind.value: ContactData(
                    name=_text(form, f"{kind.value}_name"),
                    email=_text(form, f"{kind.value}_email"),
                    phone=_text(form, f"{kind.value}_phone"),
                )
                for kind in ContactKind
            },
        )
        if not data.name:
            data.errors["name"] = "Il nome è obbligatorio."
        if normalize_url(data.url) is None:
            data.errors["url"] = "Inserire un URL completo che inizi con http:// o https://."
        if data.criticality not in set(Criticality):
            data.errors["criticality"] = "Criticità non valida."
        if data.authorized_at:
            try:
                date.fromisoformat(data.authorized_at)
            except ValueError:
                data.errors["authorized_at"] = "Data non valida."
        if bool(data.authorized_by) != bool(data.authorized_at):
            data.errors["authorized_by"] = (
                "Per registrare l'autorizzazione servono sia chi l'ha data sia la data."
            )
        for kind, contact in data.contacts.items():
            if contact.email and not EMAIL_RE.match(contact.email):
                data.errors[f"{kind}_email"] = "Indirizzo mail non valido."
        return data


@dataclass
class UserForm:
    email: str = ""
    full_name: str = ""
    role: str = Role.VIEWER
    active: bool = True
    password: str = ""
    errors: dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, form: FormData, *, password_required: bool) -> "UserForm":
        raw_password = form.get("password")
        data = cls(
            email=_text(form, "email").lower(),
            full_name=_text(form, "full_name"),
            role=_text(form, "role"),
            active=_checked(form, "active"),
            password=raw_password if isinstance(raw_password, str) else "",
        )
        if not (EMAIL_RE.match(data.email) or USERNAME_RE.match(data.email)):
            data.errors["email"] = (
                "Inserire una mail oppure un nome utente (lettere, numeri, punto, trattino)."
            )
        if data.role not in set(Role):
            data.errors["role"] = "Ruolo non valido."
        if (password_required or data.password) and len(data.password) < MIN_PASSWORD_LENGTH:
            data.errors["password"] = (
                f"La password deve avere almeno {MIN_PASSWORD_LENGTH} caratteri."
            )
        return data
