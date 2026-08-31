"""Application configuration.

All settings are read from environment variables with sensible defaults so the
application runs out of the box for development and can be configured for
production (see DEPLOYMENT.md).
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "SentinelSOC"
    api_prefix: str = "/api"
    environment: str = "development"

    # --- Database ---------------------------------------------------------
    # PostgreSQL is the supported production database (docker-compose.yml).
    # SQLite is used automatically when no DATABASE_URL is provided, which is
    # convenient for local development and the test-suite.
    database_url: str = "sqlite:///./sentinel.db"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False

    # --- Security ----------------------------------------------------------
    secret_key: str = "CHANGE_ME_dev_secret_do_not_use_in_production"
    access_token_expire_minutes: int = 60
    jwt_algorithm: str = "HS256"
    # Maximum number of authentication attempts allowed per window before the
    # client is rate limited (defensive, not offensive).
    auth_rate_limit: int = 10
    auth_rate_window_seconds: int = 300
    # Global API rate limit (requests / window) applied to authenticated APIs.
    api_rate_limit: int = 600
    api_rate_window_seconds: int = 300
    # Master switch for rate limiting (disabled in tests).
    rate_limit_enabled: bool = True

    # --- Logging -----------------------------------------------------------
    log_level: str = "INFO"
    secure_logging: bool = True  # redact secrets / tokens from logs

    # --- Frontend ----------------------------------------------------------
    frontend_origin: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # --- Threat intelligence ------------------------------------------------
    # Threat-intel providers are extensible. They are disabled by default and
    # never require external API keys for development. We do not fabricate
    # indicators of compromise.
    threatintel_enabled: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
