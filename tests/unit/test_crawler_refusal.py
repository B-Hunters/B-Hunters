"""The crawler stops asking a host that has refused it.

A 403 is an edge that has said no.  The scan of a live target found
that out the hard way: after an hour of scanning, the target's edge
started answering every request with 403, and the crawler recorded the
refusal and carried on to the next URL.

Asking again is the traffic that turns a refusal into a block, and a
scan that keeps going against a refusal is a scan that is not being
careful.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.scanners import native


class _RefusingScope:
    """A scope that authorises the host and nothing else."""

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


class _RefusingWeb:
    """A server that answers 403 to everything."""

    def __init__(self):
        self.requested: list[str] = []

    def handler(self, request):
        self.requested.append(str(request.url))
        return type("R", (), {"status_code": 403, "headers": {}, "text": "forbidden"})()


@pytest.mark.asyncio
async def test_the_crawl_stops_asking_a_host_that_refused(monkeypatch):
    web = _RefusingWeb()

    class _Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, **kwargs):
            raise RuntimeError("the crawler must not fetch a host that refused")

    monkeypatch.setattr(native, "_fetch_document", _refusing_fetch(web))
    request = native.ScanRequest(
        scan_id="s",
        targets=["https://demo.test/", "https://demo.test/second"],
        scope=_RefusingScope(),
    )

    result = await native.asset_crawl_executor(request)

    # The first request is answered with a refusal; the second is never
    # made, because the host has already said no.
    assert len(web.requested) == 1
    assert result.metadata["fetched"] == 1
    assert "refused" in result.error


def _refusing_fetch(web):
    async def fetch(raw, request):
        web.requested.append(raw)
        return type(
            "D",
            (),
            {
                "allowed": True,
                "error": "",
                "status_code": 403,
                "content_type": "text/html",
                "size_bytes": 9,
                "text": "forbidden",
            },
        )()

    return fetch


def test_the_refusal_codes_are_the_ones_that_mean_no():
    assert 403 in native.REFUSAL_STATUS_CODES
    assert 401 in native.REFUSAL_STATUS_CODES
    assert 200 not in native.REFUSAL_STATUS_CODES
    assert 404 not in native.REFUSAL_STATUS_CODES
