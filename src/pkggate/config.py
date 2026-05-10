"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PKGGATE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8080

    upstream_npm: str = "https://registry.npmjs.org"
    osv_api: str = "https://api.osv.dev/v1/query"
    osv_bundle_npm: str = "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip"
    osv_bundle_pypi: str = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"

    policy_file: Path = Field(default=Path("config/policy.yaml"))
    audit_log: Path = Field(default=Path("audit.log"))
    policy_hot_reload_enabled: bool = True
    policy_hot_reload_interval_seconds: float = 1.0

    # Mirror storage and refresh
    mirror_db: Path = Field(default=Path("mirror.db"))
    mirror_refresh_seconds: int = 3600
    mirror_enabled: bool = True
    # Fall back to the live API when the mirror reports clean.
    live_fallback_enabled: bool = False
    # Use incremental updates via OSV API to reduce bandwidth (~90% savings)
    mirror_incremental_enabled: bool = True
    # Full refresh interval: run full bundle download every N refreshes (reduces drift)
    mirror_full_refresh_interval: int = 168  # weekly (24 hours * 7 / 1 hour refresh)

    # PyPI proxy
    pypi_enabled: bool = True
    pypi_upstream_simple: str = "https://pypi.org/simple/"
    pypi_upstream_files: str = "https://files.pythonhosted.org/"
    pypi_public_base_url: str = "http://127.0.0.1:8080"
    pypi_verify_integrity: bool = True
    pypi_max_buffer_bytes: int = 200 * 1024 * 1024

    # HTTP client tuning
    upstream_timeout_seconds: float = 30.0
    intel_timeout_seconds: float = 5.0
