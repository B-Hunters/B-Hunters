"""Making a scan out of a definition.

The API creates a scan when the operator asks for one, and the runner
creates a scan when a schedule comes due.  The two have to produce the
same thing, or a scheduled scan would not be comparable with a
requested one — and the diff would have nothing to say.

This module holds that one way of making a scan.  Both callers use it.
"""

from __future__ import annotations

from typing import Any

from .agents.orchestrator import ScanProfile
from .scan_keys import compute_comparison_key, compute_target_key


def create_scan_from_template(
    services: Any,
    *,
    template: dict[str, Any],
    name: str,
) -> Any:
    """Create a scan out of a template.

    A template is the payload of a scan request, stored as it was
    given.  It is what a schedule carries, and what an operator saves
    for reuse.
    """
    from .api.routers.scans import _profile_for, _validate_scope

    payload = dict(template or {})
    targets = payload.get("targets") or {}
    urls = list(targets.get("urls") or [])
    result = _validate_scope(
        urls=urls,
        authorized_hosts=list(targets.get("authorized_hosts") or []),
        excluded_paths=list(targets.get("excluded_paths") or []),
        allow_private_network=bool(payload.get("test_environment", False)),
        allow_state_changing=bool(payload.get("allow_state_changing", False)),
    )
    profile = _profile_for(
        payload.get("profile", "standard"),
        {
            "agent_roles": payload.get("agent_roles") or [],
            "scanners": payload.get("scanners") or [],
            "max_concurrency": payload.get("max_concurrency", 4),
            "max_requests_per_second": payload.get("max_requests_per_second", 10.0),
            "request_timeout": payload.get("request_timeout", 20.0),
            "max_duration_seconds": payload.get("max_duration_seconds", 3600),
            "allow_state_changing": bool(payload.get("allow_state_changing", False)),
            "safe_mode": bool(payload.get("safe_mode", True)),
        },
        verification_enabled=services.settings.agent_verification_enabled,
    )
    document = build_scan(
        name=name,
        payload=payload,
        profile=profile,
        accepted_urls=result["accepted_urls"],
        authorized_hosts=result["authorized_hosts"],
        description=str(payload.get("description", "")),
        created_by="schedule",
    )
    return services.scans.create(document)


def build_scan(
    *,
    name: str,
    payload: dict[str, Any],
    profile: ScanProfile,
    accepted_urls: list[str],
    authorized_hosts: list[str],
    description: str = "",
    created_by: str = "",
    created_by_id: str = "",
) -> dict[str, Any]:
    """The document of a scan: its definition, its scope and its keys.

    The two keys say whether two scans may be compared with each other:
    the target key says whether they looked at the same thing, and the
    comparison key says whether they asked the same question.
    """
    targets = payload.get("targets") or {}
    excluded_paths = list(targets.get("excluded_paths") or [])
    test_environment = bool(payload.get("test_environment", False))
    identity_ids = list(payload.get("identity_ids") or [])

    definition: dict[str, Any] = {
        "description": description or payload.get("description", ""),
        "targets": list(accepted_urls),
        "start_paths": list(targets.get("start_paths") or []),
        "url_lists": list(targets.get("url_lists") or []),
        "artifacts": list(payload.get("artifacts") or []),
        "schema_artifacts": list(payload.get("schema_artifacts") or []),
        "test_accounts": [
            {"username": account.get("username", "")} for account in (payload.get("test_accounts") or [])
        ],
        "identity_ids": identity_ids,
        "on_login_failure": payload.get("on_login_failure", "fail"),
        "profile": profile.to_dict() if hasattr(profile, "to_dict") else {},
        "provider": payload.get("provider", ""),
        "test_environment": test_environment,
        "safe_mode": bool(payload.get("safe_mode", True)),
    }
    scope: dict[str, Any] = {
        "authorized_hosts": list(authorized_hosts),
        "excluded_paths": excluded_paths,
        "allow_private_network": test_environment,
        "allow_state_changing": bool(payload.get("allow_state_changing", False)),
        "max_requests_per_second": float(payload.get("max_requests_per_second", 10.0)),
        "max_concurrency": int(payload.get("max_concurrency", 4)),
        "request_timeout": float(payload.get("request_timeout", 20.0)),
        "max_duration_seconds": int(payload.get("max_duration_seconds", 3600)),
    }
    target_key = compute_target_key(
        authorized_hosts=list(authorized_hosts),
        targets=list(accepted_urls),
    )
    comparison_key = compute_comparison_key(
        target_key=target_key,
        excluded_paths=excluded_paths,
        profile=profile.name,
        scanners=profile.scanners,
        agent_roles=profile.agent_roles,
        identity_ids=identity_ids,
    )
    return {
        "name": name,
        "status": "queued",
        "created_by": created_by,
        "created_by_id": created_by_id,
        "definition": definition,
        "scope": scope,
        "stats": {},
        "target_key": target_key,
        "comparison_key": comparison_key,
    }
