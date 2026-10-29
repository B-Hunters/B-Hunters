"""Builds the orchestrator and the scan context from a stored scan.

The API and the runner both need the same orchestrator and the same
context, and they must be built the same way: a scan that the API
started and a scan that a runner picked up have to behave identically.
The construction therefore lives here instead of in the API router, and
the router imports it.

The module imports the service container under ``TYPE_CHECKING`` only:
the container imports the repositories, and a runtime import would make
a cycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..db.repositories import ScanRecord
from ..settings import Settings
from .orchestrator import ScanContext, ScanOrchestrator, ScanProfile, agent_roles_for
from .provider import ProviderConfig

if TYPE_CHECKING:
    from ..api.deps import Services


def build_orchestrator(services: Services) -> ScanOrchestrator:
    """Build the orchestrator that runs a scan for the given services."""
    from ..scanners.fingerprint_adapter import service_fingerprint_executor
    from ..scanners.graphql_adapter import graphql_analysis_executor
    from ..scanners.karton_bridge import build_worker_bridge
    from ..scanners.native import (
        dependency_analysis_executor,
        openapi_discovery_executor,
        secret_scan_executor,
        security_headers_executor,
        tls_configuration_executor,
    )
    from ..scanners.registry import build_default_registry
    from ..tools.builtin import build_tool_registry
    from .provider import Provider

    registry = build_default_registry(
        {
            "security_headers": security_headers_executor,
            "service_fingerprint": service_fingerprint_executor,
            "tls_configuration": tls_configuration_executor,
            "secret_scan": secret_scan_executor,
            "openapi_discovery": openapi_discovery_executor,
            "graphql_analysis": graphql_analysis_executor,
            "dependency_analysis": dependency_analysis_executor,
        }
    )

    def provider_factory(provider_name: str = "") -> Provider:
        config = provider_config_for(services, provider_name)
        return Provider(config)

    return ScanOrchestrator(
        database=services.db,
        settings=services.settings,
        provider_factory=provider_factory,
        tool_registry=build_tool_registry(),
        scanner_registry=registry,
        worker_bridge=build_worker_bridge(settings=services.settings, database=services.db),
    )


def provider_config_for(services: Services, provider_name: str = "") -> ProviderConfig:
    """Return the configuration of a stored provider, or the environment default."""
    from .provider import provider_config_from_env

    if provider_name:
        document = services.providers.get(provider_name)
        if document:
            return ProviderConfig(
                name=document.get("name", provider_name),
                base_url=document.get("base_url", ""),
                # The key is stored encrypted: it is decrypted here, at
                # the moment the provider is used.
                api_key=services.providers.secret_for(provider_name),
                model=document.get("model", ""),
                role_models=document.get("role_models", {}) or {},
                temperature=float(document.get("temperature", 0.0)),
                max_output_tokens=int(document.get("max_output_tokens", 4096)),
                max_context_tokens=int(document.get("max_context_tokens", 128000)),
                timeout_seconds=float(document.get("timeout_seconds", 120.0)),
                max_retries=int(document.get("max_retries", 2)),
                concurrency=int(document.get("concurrency", 4)),
                extra_headers=document.get("extra_headers", {}) or {},
                enabled=bool(document.get("enabled", True)),
            )
    return provider_config_from_env()


def build_scan_context(scan: ScanRecord, settings: Settings) -> ScanContext:
    """Rebuild the context of a stored scan.

    The scan document holds the definition and the scope; the context is
    what the orchestrator runs.  Rebuilding it from the stored scan is
    what lets a runner take over a scan that the API enqueued.
    """
    definition = scan.definition or {}
    scope = scan.scope or {}
    profile_data = definition.get("profile") or {}
    profile = ScanProfile.from_dict(profile_data) if profile_data else ScanProfile.default()
    if not profile_data and settings.agent_verification_enabled:
        profile.agent_roles = agent_roles_for(profile, verification_enabled=True)

    return ScanContext(
        scan_id=scan.scan_id,
        name=scan.name,
        targets=list(definition.get("targets", [])),
        authorized_hosts=list(scope.get("authorized_hosts", [])),
        excluded_paths=list(scope.get("excluded_paths", [])),
        profile=profile,
        test_accounts=list(definition.get("test_accounts", [])),
        artifacts=list(definition.get("artifacts", [])),
        schema_artifacts=list(definition.get("schema_artifacts", [])),
        safe_mode=bool(definition.get("safe_mode", True)),
        allow_private_network=bool(scope.get("allow_private_network", False)),
        allow_state_changing=bool(scope.get("allow_state_changing", False)),
        max_duration_seconds=int(scope.get("max_duration_seconds", 3600)),
        max_requests_per_second=float(scope.get("max_requests_per_second", 10.0)),
        request_timeout=float(scope.get("request_timeout", 20.0)),
        workspace_root=settings.agent_workspace_root,
        options={"provider": definition.get("provider", "")},
    )
