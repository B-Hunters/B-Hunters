"""A pipeline authenticates with a token.

A token is for a program, not a browser: it goes in the
``Authorization`` header, it carries scopes rather than a role, and it
is not subject to the CSRF check — a token is put in the request by the
caller and never by the browser automatically, so there is nothing for a
third-party page to forge.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def _token(services, user_id: str = "", scopes=None) -> str:
    _document, plaintext = services.tokens.create(
        name="the pipeline",
        scopes=list(scopes or ["scans:read"]),
        user_id=user_id,
    )
    return plaintext


def test_a_token_authenticates_a_request(client, services, admin_user):
    plaintext = _token(services, user_id=admin_user["user_id"])

    response = client.get("/api/v1/scans", headers={"Authorization": f"Bearer {plaintext}"})

    assert response.status_code == 200, response.text


def test_a_wrong_token_does_not_authenticate(client, services):
    response = client.get("/api/v1/scans", headers={"Authorization": "Bearer not-a-token"})

    assert response.status_code == 401


def test_a_token_may_write_without_a_csrf_token(client, services, admin_user):
    plaintext = _token(services, user_id=admin_user["user_id"], scopes=["scans:write"])

    response = client.post(
        "/api/v1/scans",
        json={
            "name": "from the pipeline",
            "targets": {"urls": ["https://demo.test/"], "authorized_hosts": ["demo.test"]},
            "profile": "standard",
        },
        headers={"Authorization": f"Bearer {plaintext}"},
    )

    assert response.status_code in (200, 201), response.text


def test_a_session_still_needs_the_csrf_token(client, auth_headers, services):
    """The CSRF protection is not weakened for the browser."""
    response = client.post("/api/v1/scans", json={"name": "no token"})

    assert response.status_code in (401, 403)


def test_a_revoked_token_stops_working(client, services, admin_user):
    document, plaintext = services.tokens.create(
        name="the pipeline", scopes=["scans:read"], user_id=admin_user["user_id"]
    )
    assert client.get(
        "/api/v1/scans", headers={"Authorization": f"Bearer {plaintext}"}
    ).status_code == 200

    services.tokens.revoke(document["token_id"])
    client.cookies.clear()

    assert client.get(
        "/api/v1/scans", headers={"Authorization": f"Bearer {plaintext}"}
    ).status_code == 401


def test_a_token_is_created_through_the_api(client, auth_headers):
    response = client.post(
        "/api/v1/tokens",
        json={"name": "the pipeline", "scopes": ["scans:read"]},
        headers=auth_headers,
    )

    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["token"]
    assert payload["scopes"] == ["scans:read"]


def test_the_plaintext_of_a_token_is_returned_only_once(client, auth_headers):
    created = client.post(
        "/api/v1/tokens",
        json={"name": "the pipeline", "scopes": ["scans:read"]},
        headers=auth_headers,
    ).json()

    listed = client.get("/api/v1/tokens", headers=auth_headers).json()
    for token in listed["tokens"]:
        assert "token" not in token
        assert "token_hash" not in token
    assert created["token_id"] in {token["token_id"] for token in listed["tokens"]}


def test_a_token_is_revoked_through_the_api(client, auth_headers, services, admin_user):
    created = client.post(
        "/api/v1/tokens",
        json={"name": "the pipeline", "scopes": ["scans:read"]},
        headers=auth_headers,
    ).json()

    response = client.delete(f"/api/v1/tokens/{created['token_id']}", headers=auth_headers)

    assert response.status_code == 200, response.text

    # The browser session would authenticate the request on its own, so
    # it is dropped: what is being tested is the token.
    client.cookies.clear()
    assert client.get(
        "/api/v1/scans", headers={"Authorization": f"Bearer {created['token']}"}
    ).status_code == 401


def test_a_notification_is_created_through_the_api(client, auth_headers):
    response = client.post(
        "/api/v1/notifications",
        json={
            "name": "the webhook",
            "kind": "webhook",
            "target": "https://example.test/hook",
            "events": ["scan.completed"],
        },
        headers=auth_headers,
    )

    assert response.status_code == 201, response.text
    assert response.json()["events"] == ["scan.completed"]


def test_a_notification_of_an_unknown_event_is_refused(client, auth_headers):
    response = client.post(
        "/api/v1/notifications",
        json={
            "name": "the webhook",
            "kind": "webhook",
            "target": "https://example.test/hook",
            "events": ["scan.exploded"],
        },
        headers=auth_headers,
    )

    assert response.status_code == 400


def test_a_webhook_target_of_another_scheme_is_refused(client, auth_headers):
    """A ``file:`` target would make the platform read a local file."""
    response = client.post(
        "/api/v1/notifications",
        json={
            "name": "the webhook",
            "kind": "webhook",
            "target": "file:///etc/passwd",
            "events": ["scan.completed"],
        },
        headers=auth_headers,
    )

    assert response.status_code == 400


def test_the_secret_of_a_notification_is_not_returned(client, auth_headers):
    client.post(
        "/api/v1/notifications",
        json={
            "name": "the webhook",
            "kind": "webhook",
            "target": "https://example.test/hook",
            "events": ["scan.completed"],
            "secret": "the shared secret",
        },
        headers=auth_headers,
    )

    listed = client.get("/api/v1/notifications", headers=auth_headers).json()

    for notification in listed["notifications"]:
        assert "secret" not in notification
