"""Environment-driven application settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPO_ROOT / "backend"

LogLevel = Literal["debug", "info", "warning", "error", "critical"]


class Settings(BaseSettings):
    """Settings loaded from the process environment, then `.env` files.

    Every optional integration defaults to "not configured" so the core
    product runs without any API key.
    """

    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./sentinelx.db"
    log_level: LogLevel = "info"
    cors_origins: str = "http://localhost:3000"
    # Largest request body accepted; scoring 100 flows needs about 70 KB.
    max_request_bytes: int = Field(default=1_048_576, gt=0)
    # Downloaded datasets live here; the folder is never committed.
    data_dir: Path = REPO_ROOT / "data"
    # The trained network detector is saved here; the folder is never committed.
    model_dir: Path = BACKEND_ROOT / "artifacts" / "network"
    # The trained phishing classifier is saved here; the folder is never committed.
    phishing_model_dir: Path = BACKEND_ROOT / "artifacts" / "phishing"

    # Optional known-bad lists (bad_ips.txt, bad_domains.txt); defaults to <data_dir>/blocklists.
    blocklist_dir: Path | None = None

    llm_provider: str = "groq"
    groq_api_key: SecretStr | None = None
    threat_intel_api_key: SecretStr | None = None

    @field_validator("groq_api_key", "threat_intel_api_key", mode="before")
    @classmethod
    def _blank_secret_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value

    @property
    def sqlite_path(self) -> Path:
        """File behind DATABASE_URL; only sqlite:/// URLs are supported."""
        prefix = "sqlite:///"
        if not self.database_url.startswith(prefix):
            raise ValueError("DATABASE_URL must start with sqlite:///")
        return Path(self.database_url[len(prefix) :])

    @property
    def blocklist_path(self) -> Path:
        return self.blocklist_dir or self.data_dir / "blocklists"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def llm_configured(self) -> bool:
        return self.llm_provider == "groq" and self.groq_api_key is not None

    @property
    def threat_intel_configured(self) -> bool:
        return self.threat_intel_api_key is not None


@lru_cache
def get_settings() -> Settings:
    return Settings()
