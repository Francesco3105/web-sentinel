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

    worker_tick_seconds: int = 10
    worker_max_concurrency: int = 10
    worker_stale_seconds: int = 300


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
