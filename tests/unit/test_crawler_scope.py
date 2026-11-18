"""The crawler follows what the scan is authorised to fetch.

The crawler used to treat a reference on another origin as third-party
whatever the scope said.  A scan that covers ``*.example.com`` is
authorised for every subdomain of it - including one that does not share
an origin with the page the reference was found on - so the crawl stopped
at the apex of the domain and left the rest of the site unfetched.

The test is the scope.  A reference outside it is recorded, never
fetched.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.assets import is_external
from b_hunters.platform.scanners import native


def test_a_subdomain_of_an_authorised_wildcard_is_not_third_party():
    hosts = ["*.example.com", "example.com"]

    assert not is_external("https://www.example.com/x", hosts)
    assert not is_external("https://api.example.com/x", hosts)


def test_a_host_outside_the_scope_is_third_party():
    hosts = ["*.example.com", "example.com"]

    assert is_external("https://booking.com/", hosts)


def test_the_crawler_follows_an_in_scope_subdomain():
    """The reference is on another host; the scope covers it."""
    scope = native.ScanRequest(
        scan_id="s",
        targets=["https://example.com/"],
        scope=type("S", (), {"policy": type("P", (), {"authorized_hosts": ("*.example.com",)})()})(),
    )
    hosts = native._authorized_hosts(scope)

    assert hosts == ["*.example.com"]
    assert not native.is_external("https://www.example.com/x", hosts)


def test_the_crawler_records_a_reference_it_may_not_fetch():
    """A reference outside the scope is recorded, with its scope marked."""
    hosts = ["*.example.com"]

    assert native.is_external("https://cdn.elsewhere.test/lib.js", hosts)
