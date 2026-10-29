"""Tests for URL normalisation and classification.

The asset inventory stores one row per URL.  Two spellings of the same
resource have to collapse into one row, and every row has to say what it
is, so that the inventory can be grouped by kind and counted.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from b_hunters.platform.assets import (  # noqa: E402
    ASSET_KINDS,
    classify,
    extension_of,
    is_external,
    normalise_url,
    redact_query,
)


def test_a_url_is_normalised():
    assert normalise_url("HTTPS://Demo.test:443/app.js?b=2&a=1#frag") == "https://demo.test/app.js?a=1&b=2"


def test_a_credential_in_the_query_is_redacted():
    assert (
        normalise_url("https://demo.test/x?token=abcdef123456&page=2")
        == "https://demo.test/x?page=2&token=[REDACTED]"
    )


def test_a_javascript_file_is_classified_by_extension():
    assert classify(url="https://demo.test/app.js") == "js"


def test_a_content_type_wins_over_the_extension():
    assert classify(content_type="text/html", url="https://demo.test/app.js") == "page"


def test_an_image_is_classified():
    assert classify(content_type="image/png", url="https://demo.test/logo.png") == "image"


def test_an_api_path_is_classified():
    assert classify(path="/api/v1/users") == "api"


def test_a_third_party_host_is_external():
    assert is_external("https://cdn.example.com/app.js", ["demo.test"]) is True
    assert is_external("https://demo.test/app.js", ["demo.test"]) is False


def test_the_kinds_are_the_six_the_inventory_knows():
    assert ASSET_KINDS == ("page", "js", "image", "css", "api", "other")


def test_the_default_http_port_is_dropped():
    assert normalise_url("http://demo.test:80/a") == "http://demo.test/a"


def test_a_non_default_port_is_kept():
    assert normalise_url("https://demo.test:8443/a") == "https://demo.test:8443/a"


def test_an_empty_path_becomes_a_root():
    assert normalise_url("https://demo.test") == "https://demo.test/"


def test_the_query_is_sorted_by_name():
    assert normalise_url("https://demo.test/x?c=3&a=1&b=2") == "https://demo.test/x?a=1&b=2&c=3"


def test_a_credential_parameter_is_redacted_by_name():
    assert redact_query("api_key=abc123&page=2") == "api_key=[REDACTED]&page=2"


def test_a_password_parameter_is_redacted():
    assert normalise_url("https://demo.test/x?password=hunter2") == "https://demo.test/x?password=[REDACTED]"


def test_a_stylesheet_is_classified():
    assert classify(url="https://demo.test/site.css") == "css"


def test_a_json_document_is_classified_as_an_api():
    assert classify(url="https://demo.test/data.json") == "api"


def test_an_unknown_url_is_other():
    assert classify(url="https://demo.test/download.bin") == "other"


def test_the_content_type_suffix_is_ignored():
    assert classify(content_type="text/html; charset=utf-8", url="https://demo.test/") == "page"


def test_a_javascript_content_type_is_classified():
    assert classify(content_type="application/javascript", url="https://demo.test/x") == "js"


def test_an_unknown_content_type_is_other():
    assert classify(content_type="application/octet-stream", url="https://demo.test/app.js") == "other"


def test_the_extension_of_a_url():
    assert extension_of("https://demo.test/app.min.js") == "js"
    assert extension_of("https://demo.test/app.js?v=2") == "js"
    assert extension_of("https://demo.test/") == ""
    assert extension_of("https://demo.test/archive.tar.gz") == "gz"


def test_a_wildcard_authorises_the_subdomains_but_not_the_apex():
    assert is_external("https://cdn.demo.test/app.js", ["*.demo.test"]) is False
    assert is_external("https://demo.test/app.js", ["*.demo.test"]) is True


def test_an_unauthorised_host_is_external():
    assert is_external("https://demo.test/app.js", []) is True


if __name__ == "__main__":  # pragma: no cover
    import pytest

    pytest.main([__file__])
