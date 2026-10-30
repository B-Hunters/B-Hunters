"""The notifications and the API tokens.

Two things a single operator needs that a browser session cannot give:
a way to be told when something happens while nobody is looking, and a
way for a pipeline to ask the platform for something without a browser.

The token is stored as a hash, so the database never holds the thing
that authenticates.  The webhook is signed when it has a secret, so the
receiver can tell that the payload came from this platform.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _only_this_test_s_notifications(services):
    """The shared test database keeps the notifications of every run."""
    services.db.collection("platform_notifications").delete_many({})
    services.db.collection("platform_notification_deliveries").delete_many({})
    yield
    services.db.collection("platform_notifications").delete_many({})
    services.db.collection("platform_notification_deliveries").delete_many({})


# ----------------------------------------------------------------------
# The repository
# ----------------------------------------------------------------------
def test_a_notification_is_stored(services):
    notification = services.notifications.create(
        name="the webhook",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )

    assert notification["name"] == "the webhook"
    assert notification["events"] == ["scan.completed"]
    assert notification["enabled"] is True


def test_a_notification_without_a_target_is_refused(services):
    with pytest.raises(ValueError):
        services.notifications.create(
            name="the webhook", kind="webhook", target="", events=["scan.completed"]
        )


def test_a_notification_of_an_unknown_event_is_refused(services):
    with pytest.raises(ValueError):
        services.notifications.create(
            name="the webhook",
            kind="webhook",
            target="https://example.test/hook",
            events=["scan.exploded"],
        )


def test_the_notifications_are_listed(services):
    services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )

    assert services.notifications.list()


def test_a_notification_is_deleted(services):
    notification = services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )

    assert services.notifications.delete(notification["notification_id"]) is True
    assert services.notifications.get(notification["notification_id"]) is None


def test_only_the_notifications_that_want_the_event_are_due(services):
    services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )
    services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.failed"],
    )

    due = services.notifications.due("scan.completed")

    assert len(due) == 1
    assert due[0]["events"] == ["scan.completed"]


def test_a_disabled_notification_is_not_due(services):
    notification = services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )
    services.notifications.update(notification["notification_id"], {"enabled": False})

    assert services.notifications.due("scan.completed") == []


# ----------------------------------------------------------------------
# The delivery
# ----------------------------------------------------------------------
def test_the_webhook_receives_the_payload(services, monkeypatch):
    sent: list[dict] = []

    def fake_post(url, *, headers, json_body, timeout):
        sent.append({"url": url, "headers": headers, "json": json_body})
        return 200

    monkeypatch.setattr(services.notifications, "post", fake_post, raising=False)
    notification = services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )

    result = services.notifications.deliver(
        notification,
        event="scan.completed",
        payload={"scan_id": "s1", "findings": 3},
    )

    assert result["delivered"] is True
    assert sent
    assert sent[0]["url"] == "https://example.test/hook"
    assert sent[0]["json"]["event"] == "scan.completed"
    assert sent[0]["json"]["payload"]["scan_id"] == "s1"


def test_the_payload_is_signed_when_there_is_a_secret(services, monkeypatch):
    sent: list[dict] = []

    def fake_post(url, *, headers, json_body, timeout):
        sent.append({"headers": headers, "json": json_body})
        return 200

    monkeypatch.setattr(services.notifications, "post", fake_post, raising=False)
    notification = services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
        secret="the shared secret",
    )

    services.notifications.deliver(
        notification, event="scan.completed", payload={"scan_id": "s1"}
    )

    headers = sent[0]["headers"]
    assert "X-BHunters-Signature" in headers
    expected = hmac.new(
        b"the shared secret",
        json.dumps(sent[0]["json"], sort_keys=True).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert headers["X-BHunters-Signature"] == f"sha256={expected}"


def test_an_unsigned_webhook_is_not_signed(services, monkeypatch):
    sent: list[dict] = []

    def fake_post(url, *, headers, json_body, timeout):
        sent.append({"headers": headers})
        return 200

    monkeypatch.setattr(services.notifications, "post", fake_post, raising=False)
    notification = services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )

    services.notifications.deliver(
        notification, event="scan.completed", payload={"scan_id": "s1"}
    )

    assert "X-BHunters-Signature" not in sent[0]["headers"]


def test_a_failed_delivery_is_recorded(services, monkeypatch):
    def fake_post(url, *, headers, json_body, timeout):
        raise OSError("the host is down")

    monkeypatch.setattr(services.notifications, "post", fake_post, raising=False)
    notification = services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )

    result = services.notifications.deliver(
        notification, event="scan.completed", payload={"scan_id": "s1"}
    )

    assert result["delivered"] is False
    assert result["error"]
    deliveries = services.notifications.deliveries(notification["notification_id"])
    assert deliveries
    assert deliveries[-1]["delivered"] is False


def test_a_successful_delivery_is_recorded(services, monkeypatch):
    def fake_post(url, *, headers, json_body, timeout):
        return 200

    monkeypatch.setattr(services.notifications, "post", fake_post, raising=False)
    notification = services.notifications.create(
        name=f"hook-{uuid.uuid4().hex[:6]}",
        kind="webhook",
        target="https://example.test/hook",
        events=["scan.completed"],
    )

    services.notifications.deliver(
        notification, event="scan.completed", payload={"scan_id": "s1"}
    )

    deliveries = services.notifications.deliveries(notification["notification_id"])
    assert deliveries
    assert deliveries[-1]["delivered"] is True


# ----------------------------------------------------------------------
# The tokens
# ----------------------------------------------------------------------
def test_a_token_is_returned_once_and_stored_as_a_hash(services):
    document, plaintext = services.tokens.create(
        name="the pipeline", scopes=["scans:read"], user_id="u1"
    )

    assert plaintext
    assert document["token_hash"] != plaintext
    stored = services.tokens.get(document["token_id"])
    assert stored["token_hash"] == hashlib.sha256(plaintext.encode()).hexdigest()


def test_the_plaintext_is_not_in_the_stored_document(services):
    document, plaintext = services.tokens.create(
        name="the pipeline", scopes=["scans:read"], user_id="u1"
    )

    assert plaintext not in json.dumps(document, default=str)


def test_a_token_authenticates(services):
    _document, plaintext = services.tokens.create(
        name="the pipeline", scopes=["scans:read"], user_id="u1"
    )

    resolved = services.tokens.authenticate(plaintext)

    assert resolved is not None
    assert resolved["user_id"] == "u1"
    assert resolved["scopes"] == ["scans:read"]


def test_a_wrong_token_authenticates_nothing(services):
    assert services.tokens.authenticate("not-a-token") is None


def test_a_revoked_token_authenticates_nothing(services):
    document, plaintext = services.tokens.create(
        name="the pipeline", scopes=["scans:read"], user_id="u1"
    )
    services.tokens.revoke(document["token_id"])

    assert services.tokens.authenticate(plaintext) is None


def test_an_expired_token_authenticates_nothing(services):
    import time

    _document, plaintext = services.tokens.create(
        name="the pipeline",
        scopes=["scans:read"],
        user_id="u1",
        expires_at=time.time() - 10,
    )

    assert services.tokens.authenticate(plaintext) is None


def test_the_tokens_are_listed_without_their_secret(services):
    services.tokens.create(name="the pipeline", scopes=["scans:read"], user_id="u1")

    listed = services.tokens.list()

    assert listed
    assert "token_hash" not in listed[0]
