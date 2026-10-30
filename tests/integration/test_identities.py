"""The identity vault and the session it gives the workers.

A credential is the target's secret.  It goes into the vault encrypted
and it comes out only in the process that needs it: the API returns a
mask, and the task the workers receive carries the session.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import Services
from b_hunters.platform.db.identities import IdentityRepository

pytestmark = pytest.mark.integration


@pytest.fixture
def keyed_services(settings, database) -> Services:
    """A container whose deployment has a secret key."""
    keyed = replace(settings, secret_key=base64.b64encode(b"k" * 32).decode())
    return Services(database, keyed)


@pytest.fixture
def keyed_client(keyed_services):
    """A client over the container that has the key."""
    from fastapi.testclient import TestClient

    from b_hunters.platform.api.app import create_app

    with TestClient(create_app(keyed_services.settings, keyed_services)) as client:
        yield client


@pytest.fixture
def keyed_csrf(keyed_client, keyed_services):
    """A session on the keyed client, and its CSRF token."""
    username = f"op_{uuid.uuid4().hex[:8]}"
    keyed_services.users.create(
        username=username,
        password="CorrectHorseBatteryStaple9!",
        role="admin",
    )
    response = keyed_client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "CorrectHorseBatteryStaple9!"},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def test_a_password_is_stored_encrypted(keyed_services) -> None:
    identity = keyed_services.identities.create(
        name="webgoat", kind="form", username="admin", password="hunter2"
    )

    stored = keyed_services.identities.get(identity["identity_id"])
    assert stored["password_ciphertext"].startswith("bh1.")
    assert "hunter2" not in str(stored)
    # The public view says the identity has a password and not what it is.
    public = keyed_services.identities.public(stored)
    assert public["has_password"] is True
    assert "hunter2" not in str(public)


def test_the_secrets_come_back_only_to_the_runner(keyed_services) -> None:
    identity = keyed_services.identities.create(
        name="webgoat", kind="form", username="admin", password="hunter2"
    )

    secrets = keyed_services.identities.secrets_for(identity["identity_id"])

    assert secrets["password"] == "hunter2"


def test_a_deployment_without_a_key_refuses_a_credential(settings, database) -> None:
    repository = IdentityRepository(database, secret_box=None)

    with pytest.raises(RuntimeError):
        repository.create(name="webgoat", kind="form", password="hunter2")


def test_the_session_reaches_the_workers(keyed_services) -> None:
    identity = keyed_services.identities.create(
        name="webgoat",
        kind="cookie",
        cookies={"JSESSIONID": "abc123"},
        headers={"X-Test": "1"},
    )

    payload = keyed_services.identities.auth_payload(identity["identity_id"])

    assert payload["cookies"] == {"JSESSIONID": "abc123"}
    assert payload["headers"] == {"X-Test": "1"}


def test_the_task_carries_the_session(keyed_services) -> None:
    from b_hunters.platform.scanners.karton_bridge import WorkerTarget

    identity = keyed_services.identities.create(
        name="webgoat", kind="cookie", cookies={"JSESSIONID": "abc123"}
    )
    payload = keyed_services.identities.auth_payload(identity["identity_id"])

    target = WorkerTarget(
        url="https://demo.test/",
        domain="demo.test",
        legacy_scan_id="1",
        platform_scan_id="s1",
        auth=payload,
    )

    assert target.auth["cookies"]["JSESSIONID"] == "abc123"


def test_an_identity_is_never_returned_with_its_secret(keyed_client, keyed_csrf, keyed_services) -> None:
    response = keyed_client.post(
        "/api/v1/identities",
        json={"name": "webgoat", "kind": "form", "username": "admin", "password": "hunter2"},
        headers={"X-CSRF-Token": keyed_csrf},
    )

    assert response.status_code == 201, response.text
    assert "hunter2" not in response.text
    assert response.json()["has_password"] is True

    listing = keyed_client.get("/api/v1/identities", headers={"X-CSRF-Token": keyed_csrf})
    assert listing.status_code == 200
    assert "hunter2" not in listing.text


def test_the_login_is_queued_as_a_job(keyed_client, keyed_csrf, keyed_services) -> None:
    created_response = keyed_client.post(
        "/api/v1/identities",
        json={"name": "webgoat", "kind": "form", "username": "admin", "password": "hunter2"},
        headers={"X-CSRF-Token": keyed_csrf},
    )
    assert created_response.status_code == 201, created_response.text
    created = created_response.json()

    response = keyed_client.post(
        f"/api/v1/identities/{created['identity_id']}/login",
        headers={"X-CSRF-Token": keyed_csrf},
    )

    assert response.status_code == 202
    job = keyed_services.jobs.get(response.json()["job_id"])
    assert job["kind"] == "identity_login"
    assert job["payload"]["identity_id"] == created["identity_id"]


def test_an_identity_can_be_removed(keyed_client, keyed_csrf, keyed_services) -> None:
    created = keyed_client.post(
        "/api/v1/identities",
        json={"name": "webgoat", "kind": "form", "password": "hunter2"},
        headers={"X-CSRF-Token": keyed_csrf},
    ).json()

    response = keyed_client.delete(
        f"/api/v1/identities/{created['identity_id']}", headers={"X-CSRF-Token": keyed_csrf}
    )

    assert response.status_code == 200
    assert keyed_services.identities.get(created["identity_id"]) is None
