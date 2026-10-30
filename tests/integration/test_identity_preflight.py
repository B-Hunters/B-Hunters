"""The session is checked before the scan starts.

A scan that names an identity and finds out in the worker phase that
the session has expired spends the whole worker phase on a target it
cannot reach.  The session is therefore checked *before* the scan runs:
if it is missing, expired or failing, it is refreshed through the login
recorder.

A refresh that fails fails the scan — unless the template says
``on_login_failure: continue_unauthenticated``, in which case the scan
runs without a session and says so.  Either way a notification is
sent: an operator who asked for an authenticated scan has to hear that
it did not get one.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest

pytestmark = pytest.mark.integration


class _Identity:
    """The part of an identity the preflight uses."""

    def __init__(self, identity_id: str = "i1", verify_url: str = "https://demo.test/account"):
        self.identity_id = identity_id
        self.verify_url = verify_url
        self.name = "the test account"
        self.username = "alice"
        self.session_expires_at = 0.0

    def as_document(self) -> dict:
        return {
            "identity_id": self.identity_id,
            "name": self.name,
            "username": self.username,
            "verify_url": self.verify_url,
            "login_url": "https://demo.test/login",
            "session_expires_at": self.session_expires_at,
        }


def _identity(services, identity_id: str = "i1") -> str:
    """An identity of the scan, stored without a session."""
    services.db.collection("platform_identities").delete_many({"identity_id": identity_id})
    services.db.collection("platform_identities").insert_one(
        {
            "identity_id": identity_id,
            "name": "the test account",
            "kind": "form",
            "login_url": "https://demo.test/login",
            "username": "alice",
            "username_field": "email",
            "password_field": "password",
            "verify_url": "https://demo.test/account",
            "status": "ready",
            "session_expires_at": None,
            "last_login_at": None,
            "last_used_at": None,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
    )
    return identity_id


def _scan(services, **overrides) -> dict:
    """A scan of its own."""
    _identity(services)
    scan_id = f"s-{uuid.uuid4().hex[:8]}"
    document = {
        "scan_id": scan_id,
        "name": "the scan",
        "status": "pending",
        "definition": {
            "name": "the scan",
            "targets": {"urls": ["https://demo.test/"], "authorized_hosts": ["demo.test"]},
            "identity_ids": ["i1"],
            "profile": {"name": "standard"},
            **overrides,
        },
        "scope": {"authorized_hosts": ["demo.test"], "allow_private_network": False},
    }
    services.db.collection("platform_scans").insert_one(dict(document))
    # The runner works on the stored scan, not on the raw document.
    record = services.scans.get(scan_id)
    assert record is not None
    return record


def test_a_scan_with_no_identity_needs_no_preflight(services):
    from b_hunters.platform.runner import ScanJobExecutor

    executor = ScanJobExecutor(services)

    outcome = asyncio.run(executor.preflight_identity(_scan(services, identity_ids=[])))

    assert outcome["status"] == "not_needed"


def test_a_missing_session_is_refreshed(services, monkeypatch):
    from b_hunters.platform import runner as runner_module

    refreshed: list[str] = []

    async def fake_record_login(*, identity, secrets, authorized_hosts=None, timeout_seconds=90):
        refreshed.append(identity["identity_id"])
        return {"status": "verified", "reason": "", "storage_state": {"cookies": []}}

    monkeypatch.setattr(runner_module, "record_login", fake_record_login, raising=False)

    executor = runner_module.ScanJobExecutor(services)
    outcome = asyncio.run(executor.preflight_identity(_scan(services)))

    assert outcome["status"] == "verified"
    assert refreshed == ["i1"]


def test_a_failed_refresh_fails_the_scan(services, monkeypatch):
    from b_hunters.platform import runner as runner_module

    async def fake_record_login(*, identity, secrets, authorized_hosts=None, timeout_seconds=90):
        return {"status": "failed", "reason": "the password was refused", "storage_state": None}

    monkeypatch.setattr(runner_module, "record_login", fake_record_login, raising=False)

    executor = runner_module.ScanJobExecutor(services)
    outcome = asyncio.run(executor.preflight_identity(_scan(services)))

    assert outcome["status"] == "failed"
    assert "refused" in outcome["reason"]


def test_a_failed_refresh_can_be_allowed_to_continue(services, monkeypatch):
    from b_hunters.platform import runner as runner_module

    async def fake_record_login(*, identity, secrets, authorized_hosts=None, timeout_seconds=90):
        return {"status": "failed", "reason": "the password was refused", "storage_state": None}

    monkeypatch.setattr(runner_module, "record_login", fake_record_login, raising=False)

    executor = runner_module.ScanJobExecutor(services)
    outcome = asyncio.run(
        executor.preflight_identity(_scan(services, on_login_failure="continue_unauthenticated"))
    )

    assert outcome["status"] == "continued_unauthenticated"


def test_a_failed_refresh_sends_a_notification(services, monkeypatch):
    from b_hunters.platform import runner as runner_module

    sent: list[tuple[str, dict]] = []

    async def fake_record_login(*, identity, secrets, authorized_hosts=None, timeout_seconds=90):
        return {"status": "failed", "reason": "the password was refused", "storage_state": None}

    monkeypatch.setattr(runner_module, "record_login", fake_record_login, raising=False)
    monkeypatch.setattr(
        runner_module.ScanJobExecutor,
        "notify",
        lambda self, event, payload: sent.append((event, payload)),
        raising=False,
    )

    executor = runner_module.ScanJobExecutor(services)
    asyncio.run(executor.preflight_identity(_scan(services)))

    assert sent
    event, payload = sent[0]
    assert "login" in event
    assert payload["reason"]
