"""Application configuration.

Everything is driven by environment variables so the same image can run in
Docker, behind systemd, or from a checkout.  A small ``.env`` loader keeps the
developer experience pleasant without adding a dependency.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
REPO_DIR = BASE_DIR.parent


def _load_dotenv() -> None:
    """Load ``.env`` from the repo or backend directory without overriding env."""
    if os.environ.get("APP_ENV", "").strip().lower() == "test":
        # Tests must never depend on the developer's or operator's .env file.
        return
    for candidate in (REPO_DIR / ".env", BASE_DIR / ".env"):
        if not candidate.is_file():
            continue
        try:
            content = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    env: str = "development"
    secret_key: str = "dev-insecure-secret-change-me"
    admin_username: str = "admin"
    admin_password: str = ""
    admin_password_hash: str = ""
    cookie_secure: bool = False
    session_max_age: int = 14 * 24 * 3600

    database_url: str = ""
    data_dir: Path = field(default_factory=lambda: REPO_DIR / "data")

    jmap_enabled: bool = False
    jmap_url: str = ""
    jmap_username: str = ""
    jmap_password: str = ""
    jmap_token: str = ""
    jmap_mailbox: str = "DMARC"
    jmap_from: str = ""
    jmap_poll_seconds: int = 300
    ingest_initial_days: int = 90
    helo_hostname: str = ""

    geoip_db: str = ""
    geoip_asn_db: str = ""
    monthly_message_alert: int = 10000

    #: Comma-separated resolver addresses; empty uses the system resolver.
    dns_nameservers: str = ""
    health_checks_enabled: bool = True
    health_interval_minutes: int = 360
    probe_interval_minutes: int = 360
    probe_timeout_seconds: float = 8.0
    http_timeout_seconds: float = 6.0
    ptr_enrichment_enabled: bool = True
    backup_keep: int = 14
    backup_enabled: bool = False
    backup_interval_hours: int = 24
    backup_webdav_url: str = ""
    backup_webdav_username: str = ""
    backup_webdav_password: str = ""
    backup_s3_endpoint: str = ""
    backup_s3_bucket: str = ""
    backup_s3_region: str = "us-east-1"
    backup_s3_access_key: str = ""
    backup_s3_secret_key: str = ""
    backup_s3_session_token: str = ""
    backup_s3_prefix: str = "dmarcview/"
    backup_s3_path_style: bool = True
    retention_days: int = 0  # 0 = keep forever
    audit_retention_days: int = 0  # 0 = keep audit events forever
    digest_enabled: bool = False
    digest_to: str = ""
    digest_days: int = 7
    email_transport: str = "auto"
    jobs_initial_delay_seconds: int = 25

    # Alerts
    alerts_enabled: bool = True
    alert_interval_minutes: int = 60
    alert_cooldown_minutes: int = 60
    alert_base_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"  # starttls | ssl | none
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    alert_to: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    signal_api_url: str = ""
    signal_number: str = ""
    signal_recipients: str = ""
    webhook_url: str = ""
    webhook_secret: str = ""

    frontend_dist: str = ""
    ingest_token: str = ""

    #: Set when the app is served under a path prefix (e.g. /dmarc).
    root_path: str = ""

    @property
    def db_path(self) -> Path | None:
        url = self.database_url
        if not url:
            return self.data_dir / "dmarc.db"
        if url.startswith("sqlite"):
            _, _, path = url.partition(":///")
            return Path(path)
        return None

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{self.data_dir / 'dmarc.db'}"

    @property
    def dist_dir(self) -> Path:
        if self.frontend_dist:
            return Path(self.frontend_dist)
        return REPO_DIR / "frontend" / "dist"

    @property
    def has_credentials(self) -> bool:
        return bool(self.admin_password or self.admin_password_hash)


def _build_settings() -> Settings:
    _load_dotenv()
    data_dir = Path(_env("DATA_DIR") or (REPO_DIR / "data"))
    return Settings(
        env=_env("APP_ENV", "development"),
        secret_key=_env("SECRET_KEY", "dev-insecure-secret-change-me"),
        admin_username=_env("ADMIN_USERNAME", "admin"),
        admin_password=_env("ADMIN_PASSWORD"),
        admin_password_hash=_env("ADMIN_PASSWORD_HASH"),
        cookie_secure=_env_bool("COOKIE_SECURE", False),
        session_max_age=_env_int("SESSION_MAX_AGE", 14 * 24 * 3600),
        database_url=_env("DATABASE_URL"),
        data_dir=data_dir,
        jmap_enabled=_env_bool("JMAP_ENABLED", False),
        jmap_url=_env("JMAP_URL"),
        jmap_username=_env("JMAP_USERNAME"),
        jmap_password=_env("JMAP_PASSWORD"),
        jmap_token=_env("JMAP_TOKEN"),
        jmap_mailbox=_env("JMAP_MAILBOX", "DMARC"),
        jmap_from=_env("JMAP_FROM") or _env("SMTP_FROM"),
        jmap_poll_seconds=max(30, _env_int("JMAP_POLL_SECONDS", 300)),
        ingest_initial_days=max(1, _env_int("INGEST_INITIAL_DAYS", 90)),
        helo_hostname=_env("HELO_HOSTNAME").strip().lower().rstrip("."),
        geoip_db=_env("GEOIP_DB"),
        geoip_asn_db=_env("GEOIP_ASN_DB"),
        monthly_message_alert=_env_int("MONTHLY_MESSAGE_ALERT", 10000),
        dns_nameservers=_env("DNS_NAMESERVERS"),
        health_checks_enabled=_env_bool("HEALTH_CHECKS_ENABLED", True),
        health_interval_minutes=max(15, _env_int("HEALTH_INTERVAL_MINUTES", 360)),
        probe_interval_minutes=max(15, _env_int("PROBE_INTERVAL_MINUTES", 360)),
        probe_timeout_seconds=float(_env("PROBE_TIMEOUT_SECONDS", "8") or 8),
        http_timeout_seconds=float(_env("HTTP_TIMEOUT_SECONDS", "6") or 6),
        ptr_enrichment_enabled=_env_bool("PTR_ENRICHMENT_ENABLED", True),
        backup_keep=max(0, _env_int("BACKUP_KEEP", 14)),
        backup_enabled=_env_bool("BACKUP_ENABLED", False),
        backup_interval_hours=max(1, min(168, _env_int("BACKUP_INTERVAL_HOURS", 24))),
        backup_webdav_url=_env("BACKUP_WEBDAV_URL").rstrip("/"),
        backup_webdav_username=_env("BACKUP_WEBDAV_USERNAME"),
        backup_webdav_password=_env("BACKUP_WEBDAV_PASSWORD"),
        backup_s3_endpoint=_env("BACKUP_S3_ENDPOINT").rstrip("/"),
        backup_s3_bucket=_env("BACKUP_S3_BUCKET"),
        backup_s3_region=_env("BACKUP_S3_REGION", "us-east-1"),
        backup_s3_access_key=_env("BACKUP_S3_ACCESS_KEY"),
        backup_s3_secret_key=_env("BACKUP_S3_SECRET_KEY"),
        backup_s3_session_token=_env("BACKUP_S3_SESSION_TOKEN"),
        backup_s3_prefix=_env("BACKUP_S3_PREFIX", "dmarcview/"),
        backup_s3_path_style=_env_bool("BACKUP_S3_PATH_STYLE", True),
        digest_enabled=_env_bool("DIGEST_ENABLED", False),
        digest_to=_env("DIGEST_TO"),
        digest_days=max(1, min(31, _env_int("DIGEST_DAYS", 7))),
        email_transport=(_env("EMAIL_TRANSPORT", "auto").lower() or "auto"),
        jobs_initial_delay_seconds=max(5, _env_int("JOBS_INITIAL_DELAY_SECONDS", 25)),
        alerts_enabled=_env_bool("ALERTS_ENABLED", True),
        alert_interval_minutes=max(5, _env_int("ALERT_INTERVAL_MINUTES", 60)),
        alert_cooldown_minutes=max(0, _env_int("ALERT_COOLDOWN_MINUTES", 60)),
        alert_base_url=_env("ALERT_BASE_URL").rstrip("/"),
        smtp_host=_env("SMTP_HOST"),
        smtp_port=_env_int("SMTP_PORT", 587),
        smtp_security=_env("SMTP_SECURITY", "starttls").lower(),
        smtp_username=_env("SMTP_USERNAME"),
        smtp_password=_env("SMTP_PASSWORD"),
        smtp_from=_env("SMTP_FROM"),
        alert_to=_env("ALERT_TO"),
        telegram_bot_token=_env("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=_env("TELEGRAM_CHAT_ID"),
        signal_api_url=_env("SIGNAL_API_URL").rstrip("/"),
        signal_number=_env("SIGNAL_NUMBER"),
        signal_recipients=_env("SIGNAL_RECIPIENTS"),
        webhook_url=_env("WEBHOOK_URL"),
        webhook_secret=_env("WEBHOOK_SECRET"),
        frontend_dist=_env("FRONTEND_DIST"),
        ingest_token=_env("INGEST_TOKEN"),
        root_path=_env("ROOT_PATH").rstrip("/"),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return _build_settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
