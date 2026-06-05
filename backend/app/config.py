from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SOC Alert Triage"
    app_version: str = "1.0.0"
    database_url: str = "sqlite+aiosqlite:///./data/triage.db"
    cors_origins: str = "*"
    secret_key: str = "change-me-in-production-use-openssl-rand-hex-32"
    static_dir: str | None = None
    investigation_poll_ms: int = 800


@lru_cache
def get_settings() -> Settings:
    return Settings()
