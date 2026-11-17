"""Runtime configuration loaded from environment variables.

The same image runs both roles; behaviour is selected with ``DNS_ROLE``
(``primary`` or ``backup``). Each container gets its own SQLite file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env(key: str, default: str) -> str:
    value = os.environ.get(key)
    return value if value not in (None, "") else default


def _env_int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    role: str = _env("DNS_ROLE", "primary")
    # Fixed intranet zone served by this deployment.
    dns_zone: str = _env("DNS_ZONE", "internal.local")
    dns_host: str = _env("DNS_HOST", "0.0.0.0")
    dns_port: int = _env_int("DNS_PORT", 5053)
    api_host: str = _env("API_HOST", "0.0.0.0")
    api_port: int = _env_int("API_PORT", 8000)
    db_path: str = _env("DB_PATH", "/data/dns.db")
    # Backup only: base URL of the primary HTTP API.
    primary_api_url: str = _env("PRIMARY_API_URL", "http://primary:8000")
    # Backup background synchronisation interval (seconds).
    sync_interval: float = float(_env_int("SYNC_INTERVAL", 5))
    http_timeout: float = float(_env_int("HTTP_TIMEOUT", 10))
    max_records: int = _env_int("MAX_RECORDS", 8)
    # --- UDP admission control (applies to both roles) -------------------
    # When enabled, in-zone UDP queries are admitted per source before any
    # worker thread is touched; excess queries get an immediate SERVFAIL.
    admission_enabled: bool = _env_bool("ADMISSION_ENABLED", True)
    # Per-source sustained query rate (tokens/sec) and burst size.
    rate_per_source: int = _env_int("RATE_LIMIT_PER_SOURCE", 20)
    burst_per_source: int = _env_int("RATE_BURST_PER_SOURCE", 40)
    # Max queries from one source that may be processed concurrently.
    inflight_per_source: int = _env_int("INFLIGHT_PER_SOURCE", 4)
    # Hard ceiling of concurrently processed queries across ALL sources.
    inflight_global: int = _env_int("INFLIGHT_GLOBAL", 32)
    # Bounded table of tracked sources (LRU); state can never grow past it.
    max_sources: int = _env_int("MAX_TRACKED_SOURCES", 1024)
    # Fixed worker pool size; no thread is ever created per datagram.
    dns_workers: int = _env_int("DNS_WORKERS", 8)

    @property
    def is_primary(self) -> bool:
        return self.role == "primary"


settings = Settings()
