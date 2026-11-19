"""A host that says when it will take requests again is believed.

The scan of a live target found this out the hard way.  The edge of
the target answered ``429`` and, in the header, said how long it wanted
to be left alone: ``retry-after: 51804`` - fourteen hours.  The scanner
read the ``429``, drained its token bucket and carried on asking, and
every question it asked extended the block.

So the answer is kept.  The host is not asked again until the moment it
named, and when the moment is further away than a scan lasts, the crawl
leaves the host alone and says so in its report.
"""

from __future__ import annotations

import time

import pytest

from b_hunters.platform.scanners import native
from b_hunters.platform.security.scope import ScopeEnforcer, ScopePolicy


# ----------------------------------------------------------------------
# The header
# ----------------------------------------------------------------------
def test_the_header_in_seconds_is_read():
    assert native.parse_retry_after("120") == 120.0
    assert native.parse_retry_after("  45 ") == 45.0


def test_the_header_as_a_moment_is_read():
    # The 19th of November 2026, 23:00 UTC.
    now = 1795129200.0
    assert native.parse_retry_after("Thu, 19 Nov 2026 23:00:00 GMT", now=now) == pytest.approx(
        0.0, abs=1.0
    )
    later = native.parse_retry_after("Fri, 20 Nov 2026 03:00:00 GMT", now=now)
    assert 14000 < later < 14500


def test_a_header_that_says_nothing_is_worth_nothing():
    assert native.parse_retry_after("") == 0.0
    assert native.parse_retry_after("soon") == 0.0
    assert native.parse_retry_after("-5") == 0.0


def test_a_moment_in_the_past_asks_for_no_wait():
    assert native.parse_retry_after("Thu, 19 Nov 2026 00:00:00 GMT", now=time.time()) == 0.0


# ----------------------------------------------------------------------
# The pause
# ----------------------------------------------------------------------
def _enforcer() -> ScopeEnforcer:
    return ScopeEnforcer(ScopePolicy(authorized_hosts=("demo.test",)))


def test_a_host_that_asked_to_wait_is_paused():
    enforcer = _enforcer()
    assert not enforcer.is_paused("demo.test")

    enforcer.pause_host("demo.test", 60.0)

    assert enforcer.is_paused("demo.test")
    assert 55.0 < enforcer.paused_seconds("demo.test") <= 60.0
    assert "demo.test" in enforcer.paused_hosts()


def test_a_pause_that_runs_out_is_no_pause():
    enforcer = _enforcer()
    enforcer.pause_host("demo.test", 0.01)

    time.sleep(0.02)

    assert not enforcer.is_paused("demo.test")
    assert enforcer.paused_seconds("demo.test") == 0.0


def test_a_second_pause_does_not_shorten_the_first():
    enforcer = _enforcer()
    enforcer.pause_host("demo.test", 600.0)
    enforcer.pause_host("demo.test", 1.0)

    assert enforcer.paused_seconds("demo.test") > 500.0


def test_the_pause_is_kept_per_host():
    enforcer = _enforcer()
    enforcer.pause_host("demo.test", 60.0)

    assert not enforcer.is_paused("other.test")


# ----------------------------------------------------------------------
# The crawl
# ----------------------------------------------------------------------
class _Scope:
    """A scope that authorises the host and holds no pause."""

    policy = type("P", (), {"authorized_hosts": ("demo.test",)})()

    def evaluate_url(self, url, method="GET", resolve=True):
        allowed = "demo.test" in url
        return type(
            "D",
            (),
            {"allowed": allowed, "reason": "" if allowed else "out of scope", "url": url, "host": ""},
        )()

    def violation_count(self):
        return 0


@pytest.mark.asyncio
async def test_the_crawl_stops_asking_a_host_that_asked_to_wait(monkeypatch):
    asked: list[str] = []

    async def fetch(raw, request):
        asked.append(raw)
        return type(
            "D",
            (),
            {
                "allowed": True,
                "error": "",
                "status_code": 429,
                "content_type": "text/plain",
                "size_bytes": 5,
                "text": "slow down",
                "retry_after_seconds": 51804.0,
            },
        )()

    monkeypatch.setattr(native, "_fetch_document", fetch)
    request = native.ScanRequest(
        scan_id="s",
        targets=["https://demo.test/", "https://demo.test/second"],
        scope=_Scope(),
    )

    result = await native.asset_crawl_executor(request)

    # The first request is answered with a rate limit; the second is
    # never made, because the host has said how long it wants to be
    # left alone.
    assert len(asked) == 1
    assert result.metadata["fetched"] == 1
    assert "slow down" in result.error


@pytest.mark.asyncio
async def test_the_pause_is_kept_by_the_scope(monkeypatch):
    """The scope remembers the pause, so the other adapters keep it too."""

    class _PausingScope(_Scope):
        def __init__(self):
            self.paused: dict[str, float] = {}

        def evaluate_url(self, url, method="GET", resolve=True):
            decision = _Scope.evaluate_url(self, url, method=method, resolve=resolve)
            decision.host = url.split("//", 1)[-1].split("/", 1)[0]
            return decision

        def pause_host(self, host, seconds):
            self.paused[host] = seconds
            return seconds

        def is_paused(self, host):
            return host in self.paused

        def paused_seconds(self, host):
            return self.paused.get(host, 0.0)

    scope = _PausingScope()

    class _Response:
        status_code = 429
        headers = {"retry-after": "51804", "content-type": "text/plain"}
        encoding = "utf-8"

        async def aiter_bytes(self):
            yield b"slow down"

    class _Stream:
        async def __aenter__(self):
            return _Response()

        async def __aexit__(self, *args):
            return False

    class _Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, method, url):
            return _Stream()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    request = native.ScanRequest(scan_id="s", targets=["https://demo.test/"], scope=scope)

    document = await native._fetch_document("https://demo.test/", request)

    assert document.status_code == 429
    assert document.retry_after_seconds == 51804.0
    assert scope.paused.get("demo.test") == 51804.0
