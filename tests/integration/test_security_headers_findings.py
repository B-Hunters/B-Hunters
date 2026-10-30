"""Every missing header is its own finding.

The fingerprint of a finding is its class, host, path and parameter.  A
target that is missing four security headers produced **one** finding,
because all four had the same fingerprint and the repository merged
them.  The platform reported one missing header and said nothing about
the other three.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.scanners.native import security_headers_executor

pytestmark = pytest.mark.integration


class _Response:
    def __init__(self, headers: dict[str, str]):
        self.headers = headers
        self.status_code = 200


class _Client:
    def __init__(self, headers):
        self._headers = headers

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def get(self, url, **kwargs):
        return _Response(self._headers)


def _patch_httpx(monkeypatch, headers):
    import httpx

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return _Client(headers)

        async def __aexit__(self, *args):
            return None

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)


def _findings(result):
    """The findings of a scanner result."""
    for item in result.items:
        if isinstance(item, dict) and isinstance(item.get("findings"), list):
            return item["findings"]
    return []


def _request():
    from b_hunters.platform.scanners.base import ScanRequest

    return ScanRequest(scan_id="s1", targets=["http://demo.test/"], options={})


@pytest.mark.asyncio
async def test_every_missing_header_is_reported(monkeypatch):
    # A target that sends none of the checked headers.
    _patch_httpx(monkeypatch, {"content-type": "text/html"})

    result = await security_headers_executor(_request())

    missing = {finding["title"] for finding in _findings(result) if finding["title"].startswith("Missing")}
    assert len(missing) >= 4
    assert "Missing strict-transport-security header" in missing
    assert "Missing content-security-policy header" in missing


@pytest.mark.asyncio
async def test_the_findings_of_two_headers_have_different_fingerprints(monkeypatch):
    from b_hunters.platform.db.repositories import compute_fingerprint

    _patch_httpx(monkeypatch, {"content-type": "text/html"})

    result = await security_headers_executor(_request())

    fingerprints = {
        compute_fingerprint(
            vuln_class=finding["vuln_class"],
            host=finding.get("host", ""),
            path=finding.get("path", ""),
            extra=finding.get("extra_key", ""),
        )
        for finding in _findings(result)
    }
    # Two findings that share a fingerprint would be merged into one.
    assert len(fingerprints) == len(_findings(result))


@pytest.mark.asyncio
async def test_a_header_that_is_present_is_not_reported(monkeypatch):
    _patch_httpx(
        monkeypatch,
        {
            "content-type": "text/html",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        },
    )

    result = await security_headers_executor(_request())

    assert not [f for f in _findings(result) if f["title"].startswith("Missing")]
