"""The out-of-band callbacks.

A blind vulnerability — an SSRF, a blind XSS, a command injection that
answers on another host — cannot be confirmed by looking at the
response.  It is confirmed by the target reaching back.

The platform runs its own callback service.  An agent asks it for a
token, uses the address that belongs to the token in the request it is
testing, and then asks the service what came back.  A finding that was
a guess becomes a finding that was reproduced.

The service is the only part of the platform that is exposed to the
outside world, and it answers on one path only: every other path is a
404, so it cannot be used as a general proxy.
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _only_this_test_s_callbacks(services):
    """The shared test database keeps the callbacks of every run."""
    services.db.collection("platform_callback_tokens").delete_many({})
    services.db.collection("platform_callbacks").delete_many({})
    yield
    services.db.collection("platform_callback_tokens").delete_many({})
    services.db.collection("platform_callbacks").delete_many({})


def test_a_token_is_unguessable(services):
    token = services.callbacks.create_token(label="the ssrf test", scan_id="s1")

    assert len(token["token"]) >= 32
    assert token["token"] != services.callbacks.create_token(label="another", scan_id="s1")["token"]


def test_a_token_has_an_expiry(services):
    token = services.callbacks.create_token(label="the ssrf test", scan_id="s1")

    assert token["expires_at"] > 0


def test_an_expired_token_is_not_accepted(services):
    token = services.callbacks.create_token(
        label="the ssrf test", scan_id="s1", expires_at=1.0
    )

    assert services.callbacks.token_is_live(token["token"]) is False


def test_a_callback_is_recorded(services):
    token = services.callbacks.create_token(label="the ssrf test", scan_id="s1")

    services.callbacks.record(
        token=token["token"],
        method="GET",
        path="/probe",
        headers={"User-Agent": "curl"},
        body=b"",
        source="10.0.0.1",
    )

    hits = services.callbacks.list_for_scan("s1")
    assert len(hits) == 1
    assert hits[0]["method"] == "GET"
    assert hits[0]["path"] == "/probe"
    assert hits[0]["source"] == "10.0.0.1"
    assert hits[0]["token"] == token["token"]


def test_the_body_is_bounded(services):
    token = services.callbacks.create_token(label="the ssrf test", scan_id="s1")

    services.callbacks.record(
        token=token["token"],
        method="POST",
        path="/probe",
        headers={},
        body=b"x" * 100_000,
        source="10.0.0.1",
    )

    hits = services.callbacks.list_for_scan("s1")
    assert len(hits[0]["body"]) <= 4096


def test_an_unknown_token_records_nothing(services):
    services.callbacks.record(
        token="not-a-token",
        method="GET",
        path="/probe",
        headers={},
        body=b"",
        source="10.0.0.1",
    )

    assert services.callbacks.list_for_scan("s1") == []


def test_the_callbacks_are_found_by_their_label(services):
    token = services.callbacks.create_token(label="the ssrf test", scan_id="s1")
    services.callbacks.record(
        token=token["token"],
        method="GET",
        path="/probe",
        headers={},
        body=b"",
        source="10.0.0.1",
    )

    hits = services.callbacks.list_for_token(token["token"])

    assert len(hits) == 1


def test_a_callback_is_not_reported_twice(services):
    """The same token and the same path is one callback."""
    token = services.callbacks.create_token(label="the ssrf test", scan_id="s1")
    for _ in range(3):
        services.callbacks.record(
            token=token["token"],
            method="GET",
            path="/probe",
            headers={},
            body=b"",
            source="10.0.0.1",
        )

    hits = services.callbacks.list_for_scan("s1")
    assert len(hits) == 1
    assert hits[0]["count"] == 3


@pytest.fixture
def callback_client(services):
    """A client of the callback service itself."""
    from fastapi.testclient import TestClient

    from b_hunters.platform.callbacks import create_callback_app

    app = create_callback_app(services.callbacks)
    with TestClient(app) as test_client:
        yield test_client


def test_the_service_answers_on_the_callback_path_only(callback_client, services):
    token = services.callbacks.create_token(label="the ssrf test", scan_id="s1")

    response = callback_client.get(f"/cb/{token['token']}")

    assert response.status_code == 200, response.text
    assert "B-Hunters" in response.text


def test_the_service_refuses_any_other_path(callback_client):
    assert callback_client.get("/cb/not-a-token").status_code == 404
    assert callback_client.get("/").status_code == 404
    assert callback_client.get("/health").status_code == 404
