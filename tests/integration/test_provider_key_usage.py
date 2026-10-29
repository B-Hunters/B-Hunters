"""The provider's stored key must reach the places that use it.

The key is stored encrypted when the deployment has a secret key.  Every
path that builds a provider from a stored document — the admin health
check, the dashboard and the update that keeps the existing key — has to
read it back through the repository.  Reading the plaintext field
instead sends an empty credential, and the provider then looks broken.
"""

from __future__ import annotations

import asyncio
import base64
import uuid
from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import CurrentUser, Services

pytestmark = pytest.mark.integration


class FakeProvider:
    """A provider that records the key it was given."""

    seen: dict[str, str] = {}

    def __init__(self, config):
        FakeProvider.seen["api_key"] = config.api_key
        FakeProvider.seen["base_url"] = config.base_url

    async def health_check(self):
        return {"reachable": True, "name": "fake"}

    async def aclose(self):
        return None


@pytest.fixture
def keyed_services(settings, database) -> Services:
    """A service container whose deployment has a secret key."""
    keyed = replace(settings, secret_key=base64.b64encode(b"k" * 32).decode())
    return Services(database, keyed)


@pytest.fixture
def provider(monkeypatch):
    import b_hunters.platform.agents.provider as provider_module

    monkeypatch.setattr(provider_module, "Provider", FakeProvider)
    FakeProvider.seen = {}
    return FakeProvider


def _provider(services: Services, name: str) -> None:
    services.providers.upsert(
        {"name": name, "base_url": "https://provider.test/v1", "model": "m", "api_key": "sk-secret"}
    )


def _admin() -> CurrentUser:
    return CurrentUser(user_id="u1", username="admin", role="admin")


class _FakeRequest:
    client = None


def test_the_stored_key_is_never_in_the_clear(keyed_services) -> None:
    name = f"p-key-{uuid.uuid4().hex[:8]}"
    _provider(keyed_services, name)
    document = keyed_services.providers.get(name)
    assert document.get("api_key") in (None, "")
    assert document["api_key_ciphertext"].startswith("bh1.")
    assert keyed_services.providers.secret_for(name) == "sk-secret"


def test_the_admin_health_check_uses_the_decrypted_key(keyed_services, provider) -> None:
    from b_hunters.platform.api.routers import admin as admin_router

    name = f"p-health-{uuid.uuid4().hex[:8]}"
    _provider(keyed_services, name)
    asyncio.run(admin_router.provider_health(name=name, user=_admin(), services=keyed_services))
    assert provider.seen["api_key"] == "sk-secret"


def test_the_dashboard_health_check_uses_the_decrypted_key(keyed_services, provider) -> None:
    from b_hunters.platform.api.routers import dashboard as dashboard_router

    _provider(keyed_services, f"p-dash-{uuid.uuid4().hex[:8]}")
    asyncio.run(dashboard_router._provider_health(keyed_services))
    assert provider.seen["api_key"] == "sk-secret"


def test_updating_a_provider_without_a_key_keeps_the_stored_one(keyed_services) -> None:
    from b_hunters.platform.api.routers import admin as admin_router

    name = f"p-update-{uuid.uuid4().hex[:8]}"
    _provider(keyed_services, name)
    asyncio.run(
        admin_router.upsert_provider(
            payload=admin_router.ProviderRequest(
                name=name, base_url="https://provider.test/v1", model="m2", api_key=""
            ),
            request=_FakeRequest(),
            user=_admin(),
            services=keyed_services,
            csrf=None,
        )
    )
    assert keyed_services.providers.secret_for(name) == "sk-secret"
    assert keyed_services.providers.get(name)["model"] == "m2"
