"""Alert mails: rendering of the templates and delivery over SMTP."""

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import Settings

TEMPLATES = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
SMTP_TIMEOUT_SECONDS = 30
DEFAULT_FROM = "Web Sentinel <websentinel@localhost>"


class DeliveryRefused(Exception):
    """The configuration does not allow sending (nothing was attempted)."""


@dataclass
class Mail:
    recipient: str
    subject: str
    text: str
    html: str


def render(subject: str, context: dict[str, Any], recipient: str) -> Mail:
    return Mail(
        recipient=recipient,
        subject=subject,
        text=TEMPLATES.get_template("alert.txt").render(context),
        html=TEMPLATES.get_template("alert.html").render(context),
    )


def uses_sandbox(settings: Settings) -> bool:
    """Outside production mail stays in the local catcher unless real delivery is asked for."""
    return settings.environment != "production" and not settings.mail_real_delivery


def effective_recipients(settings: Settings, recipients: list[str]) -> list[str]:
    """Who really gets the mail: outside production, real delivery reaches the test address only."""
    if settings.environment == "production" or uses_sandbox(settings):
        return recipients
    if not settings.mail_test_recipient:
        raise DeliveryRefused("MAIL_REAL_DELIVERY richiede MAIL_TEST_RECIPIENT fuori produzione")
    return [settings.mail_test_recipient]


def send(settings: Settings, mail: Mail) -> None:
    """Deliver one mail. Raises on any failure; the caller records it and retries later."""
    message = EmailMessage()
    message["Subject"] = mail.subject
    message["From"] = settings.smtp_from or DEFAULT_FROM
    message["To"] = mail.recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain="websentinel")
    message.set_content(mail.text)
    message.add_alternative(mail.html, subtype="html")

    if uses_sandbox(settings):
        with smtplib.SMTP(
            settings.mail_sandbox_host, settings.mail_sandbox_port, timeout=SMTP_TIMEOUT_SECONDS
        ) as smtp:
            smtp.send_message(message)
        return

    if not settings.smtp_host:
        raise DeliveryRefused("SMTP_HOST non impostato")
    if settings.smtp_port == 465:
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_SECONDS
        )
    else:
        client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_SECONDS)
    with client as smtp:
        if settings.smtp_tls and settings.smtp_port != 465:
            smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(message)
