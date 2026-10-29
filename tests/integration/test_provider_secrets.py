"""The provider credentials, encrypted at rest.

The platform stores the model provider keys in MongoDB.  A database dump
must not hand out working credentials, so the deployment key encrypts
them before they are written, and the key is only decrypted when a
provider is actually used.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import replace

import pytest

from b_hunters.platform.agents.factory import provider_config_for
from b_hunters.platform.api.deps import Services, set_services
from b_hunters.platform.db.client import Database
from b_hunters.platform.db.repositories import migrate_provider_secrets

#: The deployment key of the tests: a base64 encoded 32 byte value.
SECRET_KEY = base64.b64encode(bytes([7]) * 32).decode()


@pytest.fixture(scope="module")
def provider_settings(settings):
    """The settings of the provider tests: a database and a key of their own."""
    return replace(settings, mongo_db=f"{settings.mongo_db}-issues", secret_key=SECRET_KEY)


@pytest.fixture(scope="module")
def services(provider_settings):
    """A service container with a secret key, on a database of its own."""
    db = Database(provider_settings)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {provider_settings.mongo_uri}")
    db.ensure_indexes()
    container = Services(db, provider_settings)
    yield container
    db.collection("platform_providers").delete_many({})
    db.close()


@pytest.fixture(scope="module")
def plain_services(settings):
    """A service container without a secret key.

    A deployment that has not configured a key yet stores the credentials
    in the clear; the tests need to see that behaviour.
    """
    db = Database(replace(settings, mongo_db=f"{settings.mongo_db}-issues"))
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    container = Services(db, replace(settings, mongo_db=f"{settings.mongo_db}-issues"))
    yield container
    db.close()


@pytest.fixture(autouse=True)
def _clean(services):
    """Start every test with no provider at all."""
    services.db.collection("platform_providers").delete_many({})
    yield


@pytest.fixture
def client(services):
    """A test client bound to the container of the provider tests."""
    from fastapi.testclient import TestClient

    from b_hunters.platform.api.app import create_app

    app = create_app(services.settings, services)
    with TestClient(app) as test_client:
        yield test_client
    set_services(None)


@pytest.fixture
def csrf(client, services) -> str:
    """Log an administrator in and return the CSRF token."""
    username = f"admin_{uuid.uuid4().hex[:8]}"
    password = "CorrectHorseBatteryStaple9!"
    services.users.create(username=username, password=password, role="admin")
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def test_a_provider_key_is_stored_encrypted(services):
    services.providers.upsert({"name": "p1", "base_url": "https://x", "model": "m", "api_key": "sk-secret"})
    document = services.providers.get("p1")
    assert document.get("api_key") in (None, "")
    assert document["api_key_ciphertext"].startswith("bh1.")
    assert services.providers.secret_for("p1") == "sk-secret"


def test_the_api_never_returns_the_provider_key(client, csrf, services):
    services.providers.upsert({"name": "p1", "base_url": "https://x", "model": "m", "api_key": "sk-secret"})
    response = client.get("/api/v1/admin/providers", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert "sk-secret" not in response.text


def test_migrate_secrets_encrypts_an_existing_provider(services):
    services.db.collection("platform_providers").insert_one(
        {"name": "legacy", "base_url": "https://x", "model": "m", "api_key": "sk-legacy"}
    )
    migrated = migrate_provider_secrets(services)
    assert migrated == 1
    document = services.providers.get("legacy")
    assert document.get("api_key") in (None, "")
    assert services.providers.secret_for("legacy") == "sk-legacy"


def test_the_public_view_masks_the_ciphertext(services):
    services.providers.upsert({"name": "p1", "base_url": "https://x", "model": "m", "api_key": "sk-secret"})
    public = services.providers.public(services.providers.get("p1"))
    assert public["api_key_ciphertext"] == "***"
    assert "sk-secret" not in str(public)


def test_the_provider_configuration_decrypts_the_key(services):
    services.providers.upsert({"name": "p1", "base_url": "https://x", "model": "m", "api_key": "sk-secret"})
    config = provider_config_for(services, "p1")
    assert config.api_key == "sk-secret"


def test_a_deployment_without_a_key_stores_the_key_in_the_clear(plain_services):
    plain_services.providers.upsert(
        {"name": "plain", "base_url": "https://x", "model": "m", "api_key": "sk-plain"}
    )
    document = plain_services.providers.get("plain")
    assert document["api_key"] == "sk-plain"
    assert plain_services.providers.secret_for("plain") == "sk-plain"


def test_migrate_secrets_refuses_without_a_key(plain_services):
    with pytest.raises(RuntimeError):
        migrate_provider_secrets(plain_services)


def test_migrate_secrets_leaves_an_encrypted_provider_alone(services):
    services.providers.upsert({"name": "p1", "base_url": "https://x", "model": "m", "api_key": "sk-secret"})
    assert migrate_provider_secrets(services) == 0
    assert services.providers.secret_for("p1") == "sk-secret"
