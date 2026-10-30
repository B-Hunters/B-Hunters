"""A scan that names an identity hands the session to the workers.

The workers scan the authenticated surface only if the session travels
with the task they receive.  The session is the target's secret, so it
is encrypted in the vault, decrypted in the runner, and it never reaches
the report.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import Services
from b_hunters.platform.db.identities import IdentityRepository
from b_hunters.platform.scanners.karton_bridge import KartonWorkerBridge

pytestmark = pytest.mark.integration


@pytest.fixture
def keyed_services(settings, database) -> Services:
    keyed = replace(settings, secret_key=base64.b64encode(b"k" * 32).decode())
    return Services(database, keyed)


def test_the_scan_keeps_the_identity_it_names(keyed_services) -> None:
    from b_hunters.platform.agents.factory import build_scan_context

    scan = keyed_services.scans.create(
        {
            "name": "authenticated scan",
            "status": "queued",
            "created_by": "test",
            "definition": {
                "targets": ["https://demo.test/"],
                "identity_ids": ["id-one", "id-two"],
            },
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    context = build_scan_context(scan, keyed_services.settings)

    assert context.options["identity_id"] == "id-one"


def test_the_task_carries_the_session_of_the_identity(keyed_services) -> None:
    """The bridge publishes the session with the task."""
    identity = keyed_services.identities.create(
        name="webgoat", kind="cookie", cookies={"JSESSIONID": "abc123"}
    )
    payload = keyed_services.identities.auth_payload(identity["identity_id"])

    bridge = KartonWorkerBridge.__new__(KartonWorkerBridge)
    bridge.db = keyed_services.db
    bridge._counters = {}
    bridge._findings = {}
    bridge._analyses = {}

    sent: list = []

    class FakeProducer:
        def send_task(self, task):
            sent.append(task)

    bridge.producer = FakeProducer()

    target = bridge.prepare(url="https://demo.test/", platform_scan_id="s1")
    target.auth = payload
    bridge.dispatch(target)

    task = sent[0]
    assert task.payload["auth"]["cookies"]["JSESSIONID"] == "abc123"


def test_a_scan_without_an_identity_sends_no_session(keyed_services) -> None:
    from b_hunters.platform.agents.factory import build_scan_context

    scan = keyed_services.scans.create(
        {
            "name": "plain scan",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    context = build_scan_context(scan, keyed_services.settings)

    assert context.options["identity_id"] == ""


def test_the_vault_never_stores_a_credential_in_the_clear(keyed_services) -> None:
    repository: IdentityRepository = keyed_services.identities
    identity = repository.create(name="x", kind="bearer", password="tok-secret")

    stored = repository.get(identity["identity_id"])
    assert "tok-secret" not in str(stored)
    assert repository.secrets_for(identity["identity_id"])["password"] == "tok-secret"
    # The identity is removed with its secrets.
    assert repository.delete(identity["identity_id"])
    assert repository.get(identity["identity_id"]) is None


def test_an_identity_is_unique_per_name_and_usable(keyed_services) -> None:
    repository = keyed_services.identities
    name = f"id-{uuid.uuid4().hex[:6]}"
    first = repository.create(name=name, kind="form", username="a")
    second = repository.create(name=name, kind="form", username="b")

    assert first["identity_id"] != second["identity_id"]
    assert len(repository.list()) >= 2
