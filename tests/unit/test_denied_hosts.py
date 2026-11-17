"""The hosts a scan excludes are hosts nobody scans.

A bug bounty programme names the assets that are out of scope, and a
wildcard is the usual way of covering a domain - so the exclusions have
to be said separately.  They have to reach the workers too: the
discovery worker hands every subdomain it finds to the rest of the
fleet, and a worker that scanned an out-of-scope asset would be
attacking a host nobody authorised.
"""

from __future__ import annotations

import pytest

from b_hunters.bhunter import BHunters, ScopeViolation
from b_hunters.platform.security.scope import host_matches


class _Task:
    """A task that carries the exclusions of the scan."""

    def __init__(self, denied_hosts):
        self.payload_persistent = {"denied_hosts": list(denied_hosts)}


class _Worker(BHunters):
    """A worker that is not going to be initialised.

    The base class opens a database connection when it is built, and
    these tests are about the scope check alone.
    """

    def __init__(self, denied_hosts=()):  # noqa: D107 - deliberately not calling super
        self.current_task = _Task(denied_hosts)

    def process(self, task):  # pragma: no cover - never called
        raise NotImplementedError


def test_a_denied_host_is_recognised():
    worker = _Worker(["community.example.net", "support.example.net"])

    assert worker.is_denied_host("community.example.net")
    assert worker.is_denied_host("https://community.example.net/path")
    assert worker.is_denied_host("COMMUNITY.example.net")


def test_a_host_that_is_not_denied_is_allowed():
    worker = _Worker(["community.example.net"])

    assert not worker.is_denied_host("www.example.net")
    assert not worker.is_denied_host("example.net")


def test_a_wildcard_denial_matches_the_subdomains():
    worker = _Worker(["*.support.example.net"])

    assert worker.is_denied_host("a.support.example.net")
    assert not worker.is_denied_host("support.example.net")


def test_the_worker_refuses_to_scan_a_denied_host():
    worker = _Worker(["community.example.net"])

    with pytest.raises(ScopeViolation) as raised:
        worker.assert_in_scope("community.example.net")

    assert "out of scope" in str(raised.value)


def test_a_worker_with_no_exclusions_scans_what_it_is_given():
    worker = _Worker()

    assert worker.assert_in_scope("anything.example.net") is True


def test_the_exclusions_are_inherited_by_the_subtree():
    """The task carries them, so every worker in the chain inherits them."""
    worker = _Worker(["community.example.net"])

    assert worker.denied_hosts() == ("community.example.net",)


def test_the_matcher_agrees_with_the_policy():
    """The rule is the platform's rule, not a second one."""
    assert host_matches("a.example.com", "*.example.com")
    assert not host_matches("example.com", "*.example.com")
    assert host_matches("example.com", "example.com")
