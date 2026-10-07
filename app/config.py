"""Application settings, loaded from environment variables (see .env.example)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "production"
    app_timezone: str = "Europe/Rome"

    database_url: str
    secret_key: str
    ip_hmac_key: str = ""

    session_cookie_secure: bool = True
    session_max_age_seconds: int = 28800
    login_max_attempts: int = 5
    login_window_seconds: int = 900

    admin_email: str = ""
    admin_password: str = ""

    alert_default_recipient: str = "alert@example.com"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_tls: bool = True
    smtp_from: str = ""
    # Outside production mail goes to a local catcher (Mailpit) unless real delivery is asked
    # for; even then every alert goes to the test recipient only.
    mail_real_delivery: bool = False
    mail_test_recipient: str = ""
    mail_sandbox_host: str = "localhost"
    mail_sandbox_port: int = 1025
    # Used for the links in the alert mails.
    app_base_url: str = "http://localhost:8000"

    incident_failure_threshold: int = 3
    # A failed check is repeated sooner, so that an incident is confirmed in minutes.
    failure_retry_seconds: int = 60

    worker_tick_seconds: int = 10
    worker_max_concurrency: int = 10
    worker_stale_seconds: int = 300


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
