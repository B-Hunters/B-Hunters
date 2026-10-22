"""Tests for the service fingerprinting.

The fingerprinting has to be *precise*: a fingerprint that reports a stack
that is not there is worse than no fingerprint at all, because it sends
the operator after a vulnerability that does not exist.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.scanners.fingerprint import (
    CONFIDENCE_CERTAIN,
    CONFIDENCE_HIGH,
    Service,
    VERSION_PATTERN,
    detect_from_body,
    detect_from_cookies,
    detect_from_favicon,
    detect_from_headers,
    detect_from_meta,
    detect_from_tls,
    extract_version,
    favicon_hash,
    mmh3_hash,
    title_of,
)


# ----------------------------------------------------------------------
# MurmurHash3
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "data,expected",
    [
        (b"", 0x00000000),
        (b"a", 0x3C2569B2),
        (b"abc", 0xB3DD93FA),
        (b"hello", 0x248BFA47),
        (b"The quick brown fox jumps over the lazy dog", 0x2E4FF723),
    ],
)
def test_murmurhash3_matches_the_reference_vectors(data: bytes, expected: int) -> None:
    """The MurmurHash3 x86_32 implementation is the one the search engines use."""
    assert mmh3_hash(data) & 0xFFFFFFFF == expected


def test_the_favicon_hash_uses_the_base64_encoding() -> None:
    """The favicon hash is the hash of the *base64 encoded* favicon.

    Hashing the raw bytes gives a different value, which is the mistake
    that makes a fingerprint database lookup silently fail.
    """
    import base64

    content = b"\x00\x01\x02fake favicon bytes"
    encoded = base64.encodebytes(content)
    assert favicon_hash(content) == mmh3_hash(encoded)
    assert favicon_hash(content) != mmh3_hash(content)


# ----------------------------------------------------------------------
# Version extraction
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "banner,expected",
    [
        ("nginx/1.25.3", "1.25.3"),
        ("Apache/2.4.58 (Ubuntu)", "2.4.58"),
        ("Microsoft-IIS/10.0", "10.0"),
        ("PHP/8.2.7", "8.2.7"),
    ],
)
def test_the_version_is_read_out_of_the_banner(banner: str, expected: str) -> None:
    assert extract_version(banner, VERSION_PATTERN) == expected


def test_a_banner_without_a_version_yields_nothing() -> None:
    assert extract_version("nginx", VERSION_PATTERN) == ""
    assert extract_version("cloudflare", VERSION_PATTERN) == ""


# ----------------------------------------------------------------------
# Detection
# ----------------------------------------------------------------------
def test_the_server_banner_is_read() -> None:
    services: list[Service] = []
    detect_from_headers({"Server": "nginx/1.25.3"}, services)
    assert len(services) == 1
    assert services[0].name == "Web server"
    assert services[0].version == "1.25.3"
    assert services[0].confidence == CONFIDENCE_CERTAIN


def test_the_session_cookie_names_the_runtime() -> None:
    services: list[Service] = []
    detect_from_cookies("JSESSIONID=ABC123; Path=/; HttpOnly", services)
    assert any(service.name == "Java Servlet" for service in services)


def test_the_generator_meta_tag_names_the_cms() -> None:
    services: list[Service] = []
    detect_from_meta(
        '<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>',
        services,
    )
    assert any(service.name == "WordPress" for service in services)


def test_the_body_markers_are_found() -> None:
    services: list[Service] = []
    detect_from_body('<link href="/wp-content/themes/x/style.css">', services)
    assert any(service.name == "WordPress" for service in services)


def test_the_certificate_issuer_names_the_appliance() -> None:
    services: list[Service] = []
    detect_from_tls({"issuer": "CN=weblogic.example"}, services)
    assert any(service.name == "Oracle WebLogic" for service in services)


def test_a_wildcard_cors_policy_is_noticed() -> None:
    services: list[Service] = []
    detect_from_headers({"Access-Control-Allow-Origin": "*"}, services)
    assert any(service.name == "Permissive CORS policy" for service in services)


def test_the_graphql_ide_is_noticed() -> None:
    services: list[Service] = []
    detect_from_cookies("env=graphiql:disable; Path=/", services)
    assert any(service.name == "GraphQL IDE enabled" for service in services)


def test_a_plain_response_identifies_nothing() -> None:
    """A response with no stack signals must not produce a finding.

    This is the precision requirement: no signal means no claim.
    """
    services: list[Service] = []
    detect_from_headers({"Content-Type": "text/html", "Date": "now"}, services)
    detect_from_cookies("session=abc", services)
    detect_from_body("<html><body>hello</body></html>", services)
    detect_from_meta("<html><head></head></html>", services)
    detect_from_tls({"issuer": "CN=some-ca"}, services)
    assert services == []


def test_the_same_service_is_not_reported_twice() -> None:
    services: list[Service] = []
    detect_from_headers({"Server": "nginx/1.25.3"}, services)
    detect_from_headers({"server": "nginx/1.25.3"}, services)
    assert len(services) == 1


def test_a_service_without_a_version_is_upgraded_when_the_version_appears() -> None:
    services: list[Service] = []
    detect_from_headers({"X-Powered-By": "Express"}, services)
    detect_from_headers({"X-Powered-By": "Express/4.18.2"}, services)
    assert len(services) == 1
    assert services[0].version == "4.18.2"


def test_the_favicon_hash_is_matched() -> None:
    services: list[Service] = []
    detect_from_favicon(1265477436, services)
    assert any(service.name == "GitLab" for service in services)


def test_an_unknown_favicon_hash_identifies_nothing() -> None:
    services: list[Service] = []
    detect_from_favicon(1, services)
    assert services == []


def test_the_title_is_extracted() -> None:
    assert title_of("<html><head><title>  OWASP   Juice Shop </title>") == "OWASP Juice Shop"
    assert title_of("<html><body>no title</body></html>") == ""
