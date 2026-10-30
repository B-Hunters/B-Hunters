"""The browser crawler.

The HTTP crawler sees the server's answers.  The browser crawler sees
what the *page* asks for: the routes a single-page application defines
in JavaScript, the endpoints it fetches, the hash routes it navigates
to.

Two rules keep it honest:

* a reference to another host is **recorded and never fetched** — the
  target is not covered by the authorised scope, and fetching it would
  be the crawler going somewhere it was not sent;
* only metadata is recorded.  A body is read to find the references and
  is never stored.
"""

from __future__ import annotations

from b_hunters.platform.scanners.browser_adapter import _absolute, _item


def test_a_link_is_made_absolute():
    assert _absolute("https://demo.test/app/", "/api/x") == "https://demo.test/api/x"
    assert _absolute("https://demo.test/app/", "next") == "https://demo.test/app/next"


def test_a_hash_route_keeps_the_page_it_is_on():
    """A hash route is a link whose fragment is the route."""
    assert _absolute("https://demo.test/app/", "#/basket") == "https://demo.test/app/#/basket"


def test_a_reference_that_is_not_a_url_is_dropped():
    assert _absolute("https://demo.test/", "javascript:void(0)") == ""
    assert _absolute("https://demo.test/", "mailto:a@b.test") == ""
    assert _absolute("https://demo.test/", "") == ""


def test_an_item_names_the_url_it_is():
    item = _item("https://demo.test/app/", depth=2)

    assert item["url"] == "https://demo.test/app/"
    assert item["host"] == "demo.test"
    assert item["path"] == "/app/"
    assert item["depth"] == 2
    assert item["scope"] == "internal"
    assert item["discovered_by"] == "browser_crawl"
