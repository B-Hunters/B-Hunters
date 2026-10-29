"""The stable identities of a scan.

Two scans of the same target are the same target, even when the
operator wrote the hosts in another order.  The *target key* is that
identity; the *comparison key* adds what the scan does, so that two
scans of the same target can be compared only when they did the same
work.
"""

from __future__ import annotations

from b_hunters.platform.scan_keys import compute_comparison_key, compute_target_key


def test_the_target_key_is_stable_and_order_independent():
    first = compute_target_key(
        authorized_hosts=["demo.test", "api.demo.test"],
        targets=["https://api.demo.test/"],
    )
    second = compute_target_key(
        authorized_hosts=["api.demo.test", "demo.test"],
        targets=["https://api.demo.test/"],
    )
    assert first == second
    assert len(first) == 32


def test_a_different_target_has_a_different_key():
    assert compute_target_key(authorized_hosts=["demo.test"], targets=[]) != compute_target_key(
        authorized_hosts=["other.test"], targets=[]
    )


def test_the_comparison_key_changes_with_the_scanner_set():
    base = compute_comparison_key(
        target_key="k",
        excluded_paths=[],
        profile="standard",
        scanners=["nuclei"],
        agent_roles=["recon"],
        identity_ids=[],
    )
    changed = compute_comparison_key(
        target_key="k",
        excluded_paths=[],
        profile="standard",
        scanners=["nuclei", "katana"],
        agent_roles=["recon"],
        identity_ids=[],
    )
    assert base != changed


def test_the_comparison_key_changes_with_the_identities():
    without = compute_comparison_key(
        target_key="k",
        excluded_paths=[],
        profile="standard",
        scanners=[],
        agent_roles=[],
        identity_ids=[],
    )
    with_identity = compute_comparison_key(
        target_key="k",
        excluded_paths=[],
        profile="standard",
        scanners=[],
        agent_roles=[],
        identity_ids=["id-1"],
    )
    assert without != with_identity
