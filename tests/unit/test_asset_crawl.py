"""Tests for the asset crawler.

The crawler is the only adapter that walks the target, so two properties
matter more than anything else it does: it follows the links the target
serves, and it never fetches a reference to a host the operator did not
authorise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from b_hunters.platform.scanners import native  # noqa: E402
from b_hunters.platform.scanners.base import ScanRequest  # noqa: E402
from b_hunters.platform.scanners.native import asset_crawl_executor  # noqa: E402
from b_hunters.platform.security.scope import ScopeDecision  # noqa: E402

#: The content type a page is served with, by extension.
CONTENT_TYPES = {
    ".js": "application/javascript",
    ".css": "text/css",
    ".png": "image/png",
    ".json": "application/json",
}


class RecordingScope:
    """A scope that records the URLs it was asked about."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []
        self.policy = None

    def evaluate_url(self, url, resolve=True):
        self.requested.append(url)
        return ScopeDecision(allowed=url in self.pages, reason="test", url=url, host="")

    def violation_count(self):
        return 0


class MockWeb:
    """A tiny web server that answers from a dictionary of pages."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def handler(self, request):
        url = str(request.url)
        self.requested.append(url)
        body = self.pages.get(url)
        if body is None:
            return httpx.Response(404, text="not found")
        return httpx.Response(
            200,
            content=body.encode("utf-8"),
            headers={"content-type": _content_type(url)},
        )

    def install(self, monkeypatch):
        """Make every httpx client answer from this server."""
        original = httpx.AsyncClient
        handler = self.handler

        class _Client(original):
            def __init__(self, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _Client)


def _content_type(url: str) -> str:
    path = urlsplit(url).path
    for extension, content_type in CONTENT_TYPES.items():
        if path.endswith(extension):
            return content_type
    return "text/html"


def _request(scope, targets):
    return ScanRequest(scan_id="scan", targets=list(targets), scope=scope)


def _values(result):
    return {item["value"] for item in result.items}


@pytest.mark.asyncio
async def test_the_crawl_follows_same_origin_links(monkeypatch):
    pages = {
        "https://demo.test/": '<a href="/app.js">js</a><img src="/logo.png">',
        "https://demo.test/app.js": "var a = 1;",
    }
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/"])

    result = await asset_crawl_executor(request)

    urls = _values(result)
    assert "https://demo.test/app.js" in urls
    assert "https://demo.test/logo.png" in urls


@pytest.mark.asyncio
async def test_an_external_reference_is_recorded_but_never_fetched(monkeypatch):
    pages = {
        "https://demo.test/": '<script src="https://cdn.example.com/lib.js"></script>',
    }
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/"])

    result = await asset_crawl_executor(request)

    items = {item["value"]: item for item in result.items}
    assert "https://cdn.example.com/lib.js" in items
    assert items["https://cdn.example.com/lib.js"]["scope"] == "external"
    assert "https://cdn.example.com/lib.js" not in scope.requested
    assert "https://cdn.example.com/lib.js" not in web.requested


@pytest.mark.asyncio
async def test_a_fetched_asset_carries_its_metadata(monkeypatch):
    pages = {"https://demo.test/app.js": "var a = 1;"}
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/app.js"])

    result = await asset_crawl_executor(request)

    item = {entry["value"]: entry for entry in result.items}["https://demo.test/app.js"]
    assert item["kind"] == "js"
    assert item["scope"] == "first_party"
    assert item["status_code"] == 200
    assert item["size_bytes"] == len("var a = 1;")
    assert item["depth"] == 0
    assert item["discovered_from"] == ""


@pytest.mark.asyncio
async def test_a_reference_records_where_it_was_found(monkeypatch):
    pages = {
        "https://demo.test/": '<a href="/app.js">js</a>',
        "https://demo.test/app.js": "var a = 1;",
    }
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/"])

    result = await asset_crawl_executor(request)

    item = {entry["value"]: entry for entry in result.items}["https://demo.test/app.js"]
    assert item["discovered_from"] == "https://demo.test/"
    assert item["depth"] == 1


@pytest.mark.asyncio
async def test_the_body_is_never_stored(monkeypatch):
    pages = {"https://demo.test/": "<html>a-credential-marker</html>"}
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/"])

    result = await asset_crawl_executor(request)

    assert "a-credential-marker" not in json.dumps(result.items)


@pytest.mark.asyncio
async def test_a_credential_in_the_query_is_redacted(monkeypatch):
    pages = {"https://demo.test/x?token=secret": "ok"}
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/x?token=secret"])

    result = await asset_crawl_executor(request)

    assert "https://demo.test/x?token=[REDACTED]" in _values(result)


@pytest.mark.asyncio
async def test_a_fetch_target_in_a_script_is_recorded(monkeypatch):
    pages = {"https://demo.test/": "<script>fetch('/api/data.json')</script>"}
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/"])

    result = await asset_crawl_executor(request)

    assert "https://demo.test/api/data.json" in _values(result)


@pytest.mark.asyncio
async def test_the_crawl_does_not_go_deeper_than_three(monkeypatch):
    pages = {
        "https://demo.test/a": '<a href="/b">b</a>',
        "https://demo.test/b": '<a href="/c">c</a>',
        "https://demo.test/c": '<a href="/d">d</a>',
        "https://demo.test/d": '<a href="/e">e</a>',
        "https://demo.test/e": "e",
    }
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/a"])

    result = await asset_crawl_executor(request)

    assert "https://demo.test/e" in _values(result)
    assert "https://demo.test/e" not in web.requested


@pytest.mark.asyncio
async def test_the_crawl_stops_at_the_asset_limit(monkeypatch):
    pages = {
        "https://demo.test/": "".join(f'<a href="/p{index}">x</a>' for index in range(5)),
    }
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    monkeypatch.setattr(native, "ASSET_LIMIT", 2)
    request = _request(scope, targets=["https://demo.test/"])

    result = await asset_crawl_executor(request)

    assert len(result.items) == 2


@pytest.mark.asyncio
async def test_the_crawler_is_registered():
    from b_hunters.platform.scanners.registry import default_all_adapters

    specs = {spec.name: spec for spec in default_all_adapters()}
    assert "asset_crawl" in specs
    assert specs["asset_crawl"].kind == "native"
    assert specs["asset_crawl"].description


@pytest.mark.asyncio
async def test_the_routes_a_bundle_names_are_recorded(monkeypatch):
    """The routes of a single-page application are not links.

    A crawler follows links; the API surface of a single-page
    application is in its script.  The body is read for the references
    anyway, so the routes are read out of it in the same place.
    """
    bundle = (
        'search(t){return this.http.get('
        '`${this.hostServer}/rest/products/search?q=${t}`)}'
    )
    pages = {"https://demo.test/main.js": bundle}
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/main.js"])

    result = await asset_crawl_executor(request)

    items = {entry["value"]: entry for entry in result.items}
    assert "https://demo.test/rest/products/search?q=" in items
    assert items["https://demo.test/rest/products/search?q="]["kind"] == "api"
    assert items["https://demo.test/rest/products/search?q="]["discovered_from"] == (
        "https://demo.test/main.js"
    )


@pytest.mark.asyncio
async def test_a_route_is_not_counted_against_the_asset_limit(monkeypatch):
    """The routes are not pages, so the crawl does not stop for them."""
    bundle = "".join(f'get("/api/r{index}");' for index in range(10))
    pages = {"https://demo.test/main.js": bundle}
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    monkeypatch.setattr(native, "ASSET_LIMIT", 1)
    request = _request(scope, targets=["https://demo.test/main.js"])

    result = await asset_crawl_executor(request)

    assert result.metadata["api_routes"] == 10


@pytest.mark.asyncio
async def test_a_page_is_not_read_for_routes(monkeypatch):
    """Only a script carries routes."""
    pages = {"https://demo.test/": '<a href="/x">x</a> get("/api/y");'}
    web = MockWeb(pages)
    web.install(monkeypatch)
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/"])

    result = await asset_crawl_executor(request)

    assert result.metadata["api_routes"] == 0


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
