"""The independent verifier is an option.

It re-checks every candidate finding, which costs a request each, and the
adjudicator judges the findings anyway - so it is left out of a scan
unless it is asked for.  The reporting role always runs: it reconciles
the findings and records a verdict for each of them.
"""

from __future__ import annotations

from typing import Any

from b_hunters.platform.agents.orchestrator import REPORTING_ROLES, VERIFICATION_ROLES
from b_hunters.platform.api.routers.scans import _profile_for


def _profile(overrides: dict[str, Any] | None = None, *, enabled: bool = False):
    return _profile_for("standard", overrides or {}, verification_enabled=enabled)


def test_the_verifier_is_off_by_default() -> None:
    profile = _profile()
    assert "verifier" not in profile.agent_roles


def test_the_verifier_runs_when_it_is_enabled() -> None:
    profile = _profile(enabled=True)
    assert "verifier" in profile.agent_roles


def test_the_reporting_role_always_runs() -> None:
    for enabled in (False, True):
        profile = _profile(enabled=enabled)
        for role in REPORTING_ROLES:
            assert role in profile.agent_roles


def test_a_scan_that_names_the_verifier_gets_it() -> None:
    profile = _profile({"agent_roles": ["vuln_xss", "verifier"]})
    assert "verifier" in profile.agent_roles
    assert "vuln_xss" in profile.agent_roles


def test_a_scan_that_names_its_roles_keeps_them() -> None:
    profile = _profile({"agent_roles": ["vuln_xss"]})
    assert "vuln_xss" in profile.agent_roles
    assert "recon" not in profile.agent_roles
    for role in REPORTING_ROLES:
        assert role in profile.agent_roles


def test_the_verification_roles_are_the_ones_that_are_opt_in() -> None:
    profile = _profile()
    for role in VERIFICATION_ROLES:
        assert role not in profile.agent_roles
