"""Shared test fixtures.

The integration tests run against a real MongoDB when one is available
(``BHUNTERS_TEST_MONGO_URI`` or a MongoDB on localhost) and are skipped
otherwise.  Unit tests never need a database.
"""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from b_hunters.platform.api.deps import Services, set_services  # noqa: E402
from b_hunters.platform.db.client import Database  # noqa: E402
from b_hunters.platform.settings import load_settings  # noqa: E402

DEFAULT_TEST_MONGO = "mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"


def _mongo_uri() -> str:
    return os.environ.get("BHUNTERS_TEST_MONGO_URI", DEFAULT_TEST_MONGO)


@pytest.fixture(scope="session")
def mongo_uri() -> str:
    return _mongo_uri()


@pytest.fixture(scope="session")
def settings(mongo_uri: str):
    return load_settings(
        overrides={
            "mongo_uri": mongo_uri,
            "mongo_db": os.environ.get("BHUNTERS_TEST_MONGO_DB", "b-hunters-test"),
            "environment": "test",
            "session_cookie_secure": False,
            "agent_workspace_root": "/tmp/b-hunters-test-workspaces",
        }
    )


@pytest.fixture(scope="session")
def database(settings) -> Iterator[Database]:
    db = Database(settings)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    db.close()


@pytest.fixture(scope="session")
def services(database, settings) -> Services:
    container = Services(database, settings)
    set_services(container)
    yield container
    set_services(None)


@pytest.fixture
def client(services):
    from fastapi.testclient import TestClient

    from b_hunters.platform.api.app import create_app

    app = create_app(services.settings, services)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_user(services) -> dict:
    """Create an administrator and return its credentials."""
    username = f"admin_{uuid.uuid4().hex[:8]}"
    password = "CorrectHorseBatteryStaple9!"
    user = services.users.create(username=username, password=password, role="admin")
    return {"username": username, "password": password, "user_id": user["user_id"]}


@pytest.fixture
def operator_user(services) -> dict:
    username = f"op_{uuid.uuid4().hex[:8]}"
    password = "CorrectHorseBatteryStaple9!"
    user = services.users.create(username=username, password=password, role="operator")
    return {"username": username, "password": password, "user_id": user["user_id"]}


@pytest.fixture
def viewer_user(services) -> dict:
    username = f"viewer_{uuid.uuid4().hex[:8]}"
    password = "CorrectHorseBatteryStaple9!"
    user = services.users.create(username=username, password=password, role="viewer")
    return {"username": username, "password": password, "user_id": user["user_id"]}


def login(client, credentials: dict) -> dict:
    """Log a user in and return the response payload."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": credentials["username"], "password": credentials["password"]},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def authenticated(client, admin_user) -> dict:
    """Log the administrator in and return the login payload."""
    return login(client, admin_user)


@pytest.fixture
def csrf(client, admin_user) -> str:
    """Log the administrator in and return the CSRF token."""
    return login(client, admin_user)["csrf_token"]


@pytest.fixture
def auth_headers(client, admin_user) -> dict:
    """Log the administrator in and return the headers for unsafe requests."""
    payload = login(client, admin_user)
    return {"X-CSRF-Token": payload["csrf_token"]}
