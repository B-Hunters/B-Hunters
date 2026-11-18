"""A host that asks for less traffic is given less traffic.

The policy has a token bucket per host and a way to drain it, written for
exactly this.  Nothing called it: a scan that is answered with 429 and
carries on at the same speed is how a host ends up blocking the scanner
outright.

The scan of a live target found this out - the edge of the target began
answering with 429 part way through, and the platform treated it as an
ordinary response.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.scanners import native


class _CountingScope:
    """A scope that counts how much traffic it was asked to give up."""

    def __init__(self):
        self.penalised: list[str] = []
        self.policy = type("P", (), {"authorized_hosts": ("demo.test",)})()

    def evaluate_url(self, url, method="GET", resolve=True):
        return type(
            "D",
            (),
            {"allowed": True, "reason": "", "url": url, "host": "demo.test"},
        )()

    def penalise(self, host):
        self.penalised.append(host)

    async def throttle(self, host, timeout=30.0):
        return True

    async def acquire_slot(self, timeout=30.0):
        return True

    def release_slot(self):
        return None

    def violation_count(self):
        return 0


def _fake_client(status_code: int):
    """A stand-in for ``httpx.AsyncClient`` that answers *status_code*."""

    class _Response:
        def __init__(self):
            self.status_code = status_code
            self.headers = {"content-type": "text/html"}
            self.encoding = "utf-8"

        async def aiter_bytes(self):
            yield b"body"

        async def __aenter__(self):
            return self

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
            return _Response()

    return _Client


@pytest.mark.asyncio
async def test_a_429_drains_the_host_bucket(monkeypatch):
    import httpx

    scope = _CountingScope()
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(429))
    request = native.ScanRequest(scan_id="s", targets=["https://demo.test/"], scope=scope)

    document = await native._fetch_document("https://demo.test/", request)

    assert document.status_code == 429
    assert scope.penalised == ["demo.test"]


@pytest.mark.asyncio
async def test_a_200_does_not_drain_the_host_bucket(monkeypatch):
    import httpx

    scope = _CountingScope()
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(200))
    request = native.ScanRequest(scan_id="s", targets=["https://demo.test/"], scope=scope)

    await native._fetch_document("https://demo.test/", request)

    assert scope.penalised == []
