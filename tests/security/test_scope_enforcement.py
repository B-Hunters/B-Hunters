"""Scope enforcement regression tests.

These are the highest-value tests in the suite: scope enforcement is the
control that keeps an authorised assessment from becoming an unauthorised
one.  They are written as regressions so that a future change that loosens
the policy fails loudly.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.security.scope import (
    METADATA_ADDRESSES,
    ScopeEnforcer,
    ScopePolicy,
    ScopeViolation,
    build_policy_from_scan,
    is_blocked_ip,
)


# ----------------------------------------------------------------------
# Address range checks
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.10.20.30",
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.170.2",
        "100.64.0.1",
        "100.127.255.255",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "fc00::1",
        "fd00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "2001:db8::1",
    ],
)
def test_blocked_addresses_are_refused(address: str) -> None:
    """Loopback, private, link-local, CGNAT and metadata ranges are blocked."""
    assert is_blocked_ip(address) is True


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "100.128.0.1", "2606:4700::1111"],
)
def test_public_addresses_are_allowed(address: str) -> None:
    assert is_blocked_ip(address) is False


def test_every_metadata_address_is_blocked() -> None:
    for address in METADATA_ADDRESSES:
        assert is_blocked_ip(address) is True, address


def test_invalid_address_is_treated_as_blocked() -> None:
    assert is_blocked_ip("not-an-ip") is True


# ----------------------------------------------------------------------
# Host matching
# ----------------------------------------------------------------------
def test_wildcard_matches_subdomains_but_not_the_apex() -> None:
    policy = ScopePolicy(authorized_hosts=("*.example.com",))
    assert policy.matches_host("api.example.com") is True
    assert policy.matches_host("deep.api.example.com") is True
    assert policy.matches_host("example.com") is False
    assert policy.matches_host("evil-example.com") is False


def test_exact_host_matches_only_itself() -> None:
    policy = ScopePolicy(authorized_hosts=("example.com",))
    assert policy.matches_host("example.com") is True
    assert policy.matches_host("other.com") is False


def test_denied_host_overrides_a_wildcard() -> None:
    policy = ScopePolicy(authorized_hosts=("*.example.com",), denied_hosts=("admin.example.com",))
    assert policy.matches_host("api.example.com") is True
    assert policy.matches_host("admin.example.com") is False


def test_idn_hosts_are_normalised() -> None:
    policy = ScopePolicy(authorized_hosts=("xn--bcher-kva.example",))
    assert policy.matches_host("bücher.example") is True


# ----------------------------------------------------------------------
# URL evaluation
# ----------------------------------------------------------------------
def _enforcer(**kwargs) -> ScopeEnforcer:
    policy = build_policy_from_scan(authorized_hosts=("example.com",), **kwargs)
    return ScopeEnforcer(policy, resolver=lambda host: ["93.184.216.34"])


def test_in_scope_url_is_allowed() -> None:
    decision = _enforcer().evaluate_url("https://example.com/path")
    assert decision.allowed is True
    assert decision.host == "example.com"


def test_out_of_scope_host_is_refused() -> None:
    decision = _enforcer().evaluate_url("https://evil.test/path")
    assert decision.allowed is False
    assert "not in the authorised scope" in decision.reason


def test_discovered_host_is_not_implicitly_authorised() -> None:
    """A host found during crawling must not become authorised by itself."""
    enforcer = _enforcer()
    # Simulate a crawl discovering a new host.
    discovered = "cdn.other.test"
    decision = enforcer.evaluate_url(f"https://{discovered}/asset.js")
    assert decision.allowed is False


def test_non_http_scheme_is_refused() -> None:
    for url in ["file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/"]:
        decision = _enforcer().evaluate_url(url)
        assert decision.allowed is False


def test_excluded_path_is_refused() -> None:
    enforcer = _enforcer(excluded_paths=["/admin"])
    assert enforcer.evaluate_url("https://example.com/admin/users").allowed is False
    assert enforcer.evaluate_url("https://example.com/public").allowed is True


def test_private_destination_is_refused_when_the_host_resolves_there() -> None:
    """DNS rebinding: the hostname is in scope but resolves to loopback."""
    enforcer = ScopeEnforcer(
        ScopePolicy(authorized_hosts=("rebind.test",)),
        resolver=lambda host: ["127.0.0.1"],
    )
    decision = enforcer.evaluate_url("https://rebind.test/")
    assert decision.allowed is False
    assert "blocked range" in decision.reason


def test_every_resolved_address_is_validated() -> None:
    """A host resolving to both a public and a private address is refused."""
    enforcer = ScopeEnforcer(
        ScopePolicy(authorized_hosts=("mixed.test",)),
        resolver=lambda host: ["93.184.216.34", "169.254.169.254"],
    )
    decision = enforcer.evaluate_url("https://mixed.test/")
    assert decision.allowed is False


def test_metadata_endpoint_is_refused_via_dns() -> None:
    enforcer = ScopeEnforcer(
        ScopePolicy(authorized_hosts=("metadata.test",)),
        resolver=lambda host: ["169.254.169.254"],
    )
    assert enforcer.evaluate_url("http://metadata.test/latest/meta-data/").allowed is False


def test_state_changing_method_is_refused_by_default() -> None:
    enforcer = _enforcer()
    for method in ["POST", "PUT", "PATCH", "DELETE"]:
        decision = enforcer.evaluate_url("https://example.com/api", method=method)
        assert decision.allowed is False, method
        assert "state" in decision.reason


def test_state_changing_method_is_allowed_when_policy_permits() -> None:
    enforcer = _enforcer(allow_state_changing=True)
    assert enforcer.evaluate_url("https://example.com/api", method="POST").allowed is True


def test_plain_http_can_be_disabled() -> None:
    enforcer = _enforcer(allow_http=False)
    assert enforcer.evaluate_url("http://example.com/").allowed is False
    assert enforcer.evaluate_url("https://example.com/").allowed is True


def test_private_network_can_be_enabled_for_a_lab() -> None:
    enforcer = ScopeEnforcer(
        ScopePolicy(authorized_hosts=("lab.test",), allow_private_network=True),
        resolver=lambda host: ["127.0.0.1"],
    )
    assert enforcer.evaluate_url("http://lab.test/").allowed is True


def test_port_allow_list_is_enforced() -> None:
    enforcer = _enforcer(authorized_ports=[443])
    assert enforcer.evaluate_url("https://example.com/").allowed is True
    assert enforcer.evaluate_url("https://example.com:8443/").allowed is False


# ----------------------------------------------------------------------
# Redirects
# ----------------------------------------------------------------------
def test_redirect_to_out_of_scope_host_is_refused() -> None:
    enforcer = _enforcer()
    decision = enforcer.validate_redirect_chain(["https://example.com/login", "https://evil.test/steal"])
    assert decision.allowed is False


def test_redirect_chain_within_scope_is_allowed() -> None:
    enforcer = _enforcer()
    decision = enforcer.validate_redirect_chain(
        ["https://example.com/login", "https://example.com/dashboard"]
    )
    assert decision.allowed is True


def test_redirect_chain_length_is_bounded() -> None:
    enforcer = _enforcer()
    chain = [f"https://example.com/hop{index}" for index in range(20)]
    decision = enforcer.validate_redirect_chain(chain)
    assert decision.allowed is False
    assert "redirect chain longer" in decision.reason


# ----------------------------------------------------------------------
# Budgets and auditing
# ----------------------------------------------------------------------
def test_duration_budget_exhaustion_stops_new_work() -> None:
    enforcer = ScopeEnforcer(ScopePolicy(authorized_hosts=("example.com",), max_duration_seconds=0))
    assert enforcer.budget_exhausted is True
    decision = enforcer.evaluate_url("https://example.com/", resolve=False)
    assert decision.allowed is False
    assert "duration budget" in decision.reason


def test_violations_are_recorded_for_audit() -> None:
    enforcer = _enforcer()
    enforcer.evaluate_url("https://evil.test/")
    enforcer.evaluate_url("https://another.test/")
    assert enforcer.violation_count() == 2
    entries = enforcer.recent_violations()
    assert {entry["host"] for entry in entries} == {"evil.test", "another.test"}


def test_concurrency_slots_are_bounded() -> None:
    enforcer = ScopeEnforcer(ScopePolicy(authorized_hosts=("example.com",), max_concurrency=1))
    assert enforcer.acquire_slot() is True
    # The second acquire must not block indefinitely.
    assert enforcer.acquire_slot(timeout=0.2) is False
    enforcer.release_slot()
    assert enforcer.acquire_slot(timeout=0.5) is True
    enforcer.release_slot()


def test_rate_limiter_throttles() -> None:
    enforcer = ScopeEnforcer(ScopePolicy(authorized_hosts=("example.com",), max_requests_per_second=1.0))
    assert enforcer.throttle("example.com") is True
    assert enforcer.throttle("example.com", timeout=0.2) is False


def test_resolve_target_raises_for_a_blocked_destination() -> None:
    enforcer = ScopeEnforcer(
        ScopePolicy(authorized_hosts=("rebind.test",)), resolver=lambda host: ["127.0.0.1"]
    )
    with pytest.raises(ScopeViolation):
        enforcer.resolve_target("https://rebind.test/")
