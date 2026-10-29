"""Environment-driven configuration for the B-Hunters platform.

The legacy B-Hunters deployment is driven by an INI file
(``/etc/b-hunters/b-hunters.ini``).  That file is still honoured for the
infrastructure coordinates it carries (mongo/redis/s3/webhooks) so that
existing deployments keep working untouched.  Everything that the new
platform needs on top of that is expressed as environment variables so
that container images can be configured without baking values into images.

Precedence, highest first:

1. Explicit keyword arguments to :func:`get_settings`.
2. Environment variables (``BHUNTERS_*``).
3. Values discovered in the legacy INI file.
4. The defaults declared on :class:`Settings`.
"""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field, fields
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = "/etc/b-hunters/b-hunters.ini"

_TRUTHY = {"1", "true", "yes", "on", "y"}
_FALSY = {"0", "false", "no", "off", "n"}


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUTHY:
        return True
    if text in _FALSY:
        return False
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    return [chunk.strip() for chunk in text.split(",") if chunk.strip()]


@dataclass
class Settings:
    """Runtime configuration for the platform."""

    # --- identity -----------------------------------------------------
    environment: str = "development"
    base_url: str = "http://127.0.0.1:8080"

    # --- persistence --------------------------------------------------
    mongo_uri: str = "mongodb://127.0.0.1:27017"
    mongo_db: str = "b-hunters"
    mongo_timeout_ms: int = 5000

    # --- Karton / Redis ------------------------------------------------
    karton_config_path: str = DEFAULT_CONFIG_PATH
    karton_identity: str = "B-Hunters-Platform"

    # --- S3 / MinIO artifact store ------------------------------------
    s3_endpoint: str = ""
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_bucket: str = "bhunters"
    s3_secure: bool = False

    # --- web server ----------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8080
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = field(default_factory=list)
    trusted_proxy_headers: list[str] = field(default_factory=list)

    # --- sessions / auth ------------------------------------------------
    session_cookie_name: str = "bh_session"
    session_ttl_seconds: int = 60 * 60 * 12
    session_cookie_secure: bool = False
    session_cookie_samesite: str = "Lax"
    csrf_cookie_name: str = "bh_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    login_max_attempts: int = 5
    login_lockout_seconds: int = 300
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""

    # --- LLM providers ---------------------------------------------------
    llm_default_base_url: str = ""
    llm_default_model: str = ""
    llm_default_api_key: str = ""
    llm_timeout_seconds: float = 120.0
    llm_max_retries: int = 4
    llm_max_output_tokens: int = 4096
    llm_max_context_tokens: int = 128000
    llm_concurrency: int = 4

    # --- agents -----------------------------------------------------------
    #: The round budget of a single agent task.  Zero means the budget
    #: the role declares.
    agent_max_rounds: int = 0
    agent_max_tokens_per_scan: int = 400000
    agent_max_task_budget: int = 60
    agent_wall_clock_seconds: int = 1800
    #: The token budget of a single agent task.  Zero means the budget the
    #: role declares.  A reasoning model needs more than a plain one: it
    #: spends a large part of every turn on reasoning and the prompt grows
    #: with every tool result, so a round costs far more.
    agent_max_tokens_per_task: int = 0
    #: The tool call budget of a single agent task.  Zero means the budget
    #: the role declares.
    agent_max_tool_calls_per_task: int = 0
    agent_workspace_root: str = "/var/lib/b-hunters/workspaces"
    #: Whether a scan runs the independent verifier by default.  The
    #: verifier re-checks every candidate finding, which costs a request
    #: each, and the adjudicator judges the findings anyway, so it is off
    #: unless it is asked for.  A scan that names the role still gets it.
    agent_verification_enabled: bool = False

    # --- scope enforcement defaults ----------------------------------------
    scope_allow_private_network: bool = False
    scope_allow_http: bool = True
    scope_allow_state_changing: bool = False
    scope_max_requests_per_second: float = 10.0
    scope_max_concurrency: int = 16
    scope_max_response_bytes: int = 8 * 1024 * 1024
    scope_default_timeout: float = 20.0
    scope_max_duration_seconds: int = 3600

    # --- artefact retention -------------------------------------------------
    artifact_retention_days: int = 30
    event_retention_days: int = 90

    # --- misc ----------------------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = False
    enable_agents: bool = True
    trusted_artifact_hosts: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def cookie_samesite(self) -> str:
        value = (self.session_cookie_samesite or "Lax").strip().lower()
        return value if value in {"lax", "strict", "none"} else "Lax"

    def redacted(self) -> dict[str, Any]:
        """Return a log/UI safe view of the settings (no secrets)."""
        secret_markers = ("password", "secret", "api_key", "access_key", "secret_key", "uri")
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            lowered = f.name.lower()
            if any(marker in lowered for marker in secret_markers):
                out[f.name] = "***redacted***" if value else ""
            else:
                out[f.name] = value
        return out


_ENV_PREFIX = "BHUNTERS_"


def _load_ini(path: str) -> dict[str, dict[str, str]]:
    if not path or not Path(path).exists():
        return {}
    parser = configparser.ConfigParser()
    try:
        parser.read(path)
    except configparser.Error:
        return {}
    return {section: dict(parser.items(section)) for section in parser.sections()}


def _ini_to_overrides(ini: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Map the legacy INI sections onto the new settings names."""
    overrides: dict[str, Any] = {}
    mongo = ini.get("mongo", {})
    if mongo:
        host = mongo.get("host", "127.0.0.1")
        port = mongo.get("port", "27017")
        user = mongo.get("user", "")
        password = mongo.get("password", "")
        db = mongo.get("db", "b-hunters")
        if user and password:
            overrides["mongo_uri"] = f"mongodb://{user}:{password}@{host}:{port}/?authSource=admin"
        else:
            overrides["mongo_uri"] = f"mongodb://{host}:{port}/"
        overrides["mongo_db"] = db

    s3 = ini.get("s3", {})
    if s3:
        overrides["s3_endpoint"] = s3.get("address", "")
        overrides["s3_access_key"] = s3.get("access_key", "")
        overrides["s3_secret_key"] = s3.get("secret_key", "")
        overrides["s3_bucket"] = s3.get("bucket", "bhunters")

    return overrides


def load_settings(
    config_path: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> Settings:
    """Build a :class:`Settings` instance from env + legacy INI + overrides."""
    config_path = config_path or os.environ.get(f"{_ENV_PREFIX}CONFIG", DEFAULT_CONFIG_PATH)
    ini = _load_ini(config_path)
    values = _ini_to_overrides(ini)

    for f in fields(Settings):
        env_key = f"{_ENV_PREFIX}{f.name.upper()}"
        if env_key in os.environ:
            raw = os.environ[env_key]
            if f.type is bool or f.name in {
                "s3_secure",
                "session_cookie_secure",
                "scope_allow_private_network",
                "scope_allow_http",
                "scope_allow_state_changing",
                "enable_agents",
                "log_json",
                "agent_verification_enabled",
            }:
                values[f.name] = _as_bool(raw, getattr(Settings, f.name, False))
            elif f.name in {
                "mongo_timeout_ms",
                "port",
                "session_ttl_seconds",
                "login_max_attempts",
                "login_lockout_seconds",
                "llm_max_retries",
                "llm_max_output_tokens",
                "llm_max_context_tokens",
                "llm_concurrency",
                "agent_max_rounds",
                "agent_max_tokens_per_scan",
                "agent_max_task_budget",
                "agent_wall_clock_seconds",
                "agent_max_tokens_per_task",
                "agent_max_tool_calls_per_task",
                "scope_max_concurrency",
                "scope_max_response_bytes",
                "scope_max_duration_seconds",
                "artifact_retention_days",
                "event_retention_days",
            }:
                values[f.name] = _as_int(raw, getattr(Settings, f.name))
            elif f.name in {
                "llm_timeout_seconds",
                "scope_max_requests_per_second",
                "scope_default_timeout",
            }:
                values[f.name] = _as_float(raw, getattr(Settings, f.name))
            elif f.name in {"cors_origins", "trusted_proxy_headers", "trusted_artifact_hosts"}:
                values[f.name] = _as_list(raw)
            else:
                values[f.name] = raw

    if overrides:
        values.update({k: v for k, v in overrides.items() if v is not None})

    known = {f.name for f in fields(Settings)}
    return Settings(**{k: v for k, v in values.items() if k in known})


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings."""
    return load_settings()
