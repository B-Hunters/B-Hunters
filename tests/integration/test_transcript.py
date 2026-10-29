"""The full tool output and the transcript.

The transcript is what the scan did, in the order it did it: every
message and every tool call, merged into one stream and paginated.
The stored tool call carries the full output next to the summary, and
a tool call that could not be stored is visible rather than absent.
"""

from __future__ import annotations

import time
from dataclasses import replace

import pytest

from b_hunters.platform.api.deps import Services, set_services
from b_hunters.platform.db.client import Database

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database(settings):
    """A database of this test's own.

    The other agents work against the same MongoDB, so the rows of this
    test live in a database of their own and only its own collections are
    cleaned.
    """
    scoped = replace(settings, mongo_db=f"{settings.mongo_db}-transcript")
    db = Database(scoped)
    if not db.ping():
        pytest.skip(f"MongoDB is not reachable at {settings.mongo_uri}")
    db.ensure_indexes()
    yield db
    for name in (
        "platform_scans",
        "platform_messages",
        "platform_tool_calls",
        "platform_scan_events",
    ):
        db.collection(name).delete_many({})
    db.close()


@pytest.fixture
def services(database, settings):
    """The service container of this test's own database."""
    container = Services(database, replace(settings, mongo_db=database.settings.mongo_db))
    set_services(container)
    yield container
    set_services(None)


def _scan(client, csrf):
    payload = {
        "name": f"transcript scan {int(time.time() * 1000)}",
        "targets": {
            "urls": ["https://demo.test/"],
            "authorized_hosts": ["demo.test"],
            "excluded_paths": [],
        },
        "profile": "standard",
        "scanners": [],
        "agent_roles": [],
        "test_accounts": [],
    }
    response = client.post("/api/v1/scans", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def _messages(services, scan_id, count=5, role="recon", start=0.0):
    """Store the messages of a role, oldest first."""
    for index in range(count):
        services.messages.append(
            {
                "scan_id": scan_id,
                "task_id": f"{scan_id}:{role}",
                "sender_role": role,
                "kind": "observation",
                "hypothesis": f"message {index}",
                "at": start + index,
            }
        )


def _tool_calls(services, scan_id, count=5, role="recon", start=0.0, output="the output"):
    """Store the tool calls of a role, oldest first."""
    for index in range(count):
        services.db.collection("platform_tool_calls").insert_one(
            {
                "scan_id": scan_id,
                "task_id": f"{scan_id}:{role}",
                "agent_role": role,
                "tool": "http_request",
                "call_id": f"call-{index}",
                "status": "ok",
                "output": output,
                "output_summary": output[:2000],
                "at": start + index + 0.5,
            }
        )


def _transcript(client, csrf, scan_id, query=""):
    response = client.get(
        f"/api/v1/scans/{scan_id}/transcript{query}",
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.text
    return response.json()


# ----------------------------------------------------------------------
# The stream
# ----------------------------------------------------------------------
def test_the_transcript_is_chronological_and_paginated(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _messages(services, scan_id, count=5)
    _tool_calls(services, scan_id, count=5)

    payload = _transcript(client, csrf, scan_id, "?limit=3")

    assert len(payload["messages"]) + len(payload["tool_calls"]) == 3
    assert payload["next_cursor"]
    assert payload["truncated"] is True


def test_the_stream_is_ordered_by_the_time_it_happened(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _messages(services, scan_id, count=3)
    _tool_calls(services, scan_id, count=3)

    payload = _transcript(client, csrf, scan_id, "?limit=100")

    # The messages and the tool calls are one stream: the page holds
    # the first three messages and the first three tool calls, and the
    # two kinds interleave by the time they happened.
    times = sorted(
        [float(item.get("at", 0)) for item in payload["messages"]]
        + [float(item.get("at", 0)) for item in payload["tool_calls"]]
    )
    assert times == [0.0, 0.5, 1.0, 1.5, 2.0, 2.5]


def test_the_next_page_continues_the_stream(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _messages(services, scan_id, count=5)
    _tool_calls(services, scan_id, count=5)

    first = _transcript(client, csrf, scan_id, "?limit=4")
    second = _transcript(client, csrf, scan_id, f"?limit=4&cursor={first['next_cursor']}")

    assert len(second["messages"]) + len(second["tool_calls"]) == 4
    first_ids = {item.get("message_id") for item in first["messages"]}
    first_ids |= {item.get("call_id") for item in first["tool_calls"]}
    second_ids = {item.get("message_id") for item in second["messages"]}
    second_ids |= {item.get("call_id") for item in second["tool_calls"]}
    assert not (first_ids & second_ids)


def test_the_last_page_says_that_there_is_no_more(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _messages(services, scan_id, count=2)

    payload = _transcript(client, csrf, scan_id, "?limit=10")

    assert payload["truncated"] is False
    assert payload["next_cursor"] == ""


def test_the_transcript_of_one_role_holds_only_that_role(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _messages(services, scan_id, count=2, role="recon")
    _messages(services, scan_id, count=3, role="api", start=10.0)
    _tool_calls(services, scan_id, count=2, role="recon")

    payload = _transcript(client, csrf, scan_id, "?role=recon&limit=100")

    assert len(payload["messages"]) == 2
    assert len(payload["tool_calls"]) == 2
    assert {item["sender_role"] for item in payload["messages"]} == {"recon"}


def test_the_transcript_of_one_task_holds_only_that_task(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _messages(services, scan_id, count=2)
    services.messages.append(
        {
            "scan_id": scan_id,
            "task_id": f"{scan_id}:api",
            "sender_role": "api",
            "kind": "observation",
            "hypothesis": "another task",
            "at": 99.0,
        }
    )

    payload = _transcript(client, csrf, scan_id, f"?task_id={scan_id}:recon&limit=100")

    assert len(payload["messages"]) == 2


def test_the_transcript_carries_the_full_output_of_a_tool_call(client, csrf, services) -> None:
    scan_id = _scan(client, csrf)
    _tool_calls(services, scan_id, count=1, output="x" * 5000)

    payload = _transcript(client, csrf, scan_id, "?limit=10")

    call = payload["tool_calls"][0]
    assert len(call["output"]) == 5000
    assert len(call["output_summary"]) == 2000


def test_the_transcript_of_an_unknown_scan_is_a_404(client, csrf) -> None:
    response = client.get("/api/v1/scans/does-not-exist/transcript", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 404


def test_the_transcript_needs_a_session(client) -> None:
    response = client.get("/api/v1/scans/whatever/transcript")
    assert response.status_code == 401


# ----------------------------------------------------------------------
# The write that fails
# ----------------------------------------------------------------------
def test_a_failed_tool_call_insert_is_reported(services) -> None:
    class BrokenCollection:
        def insert_one(self, document):
            raise RuntimeError("document too large")

    original = services.db.collection
    services.db.collection = lambda name: (
        BrokenCollection() if name == "platform_tool_calls" else original(name)
    )
    try:
        stored = services.tool_calls.record({"scan_id": "s1", "tool": "http_request"})
    finally:
        services.db.collection = original

    # The failure must be visible, not silent.
    assert stored is False


def test_a_stored_tool_call_is_reported(services) -> None:
    assert services.tool_calls.record({"scan_id": "s1", "tool": "http_request"}) is True


def test_a_tool_call_that_cannot_be_recorded_is_reported_as_an_event(services) -> None:
    from b_hunters.platform.agents.orchestrator import ScanOrchestrator

    scan = services.scans.create(
        {
            "name": "record failed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )

    class BrokenCollection:
        def insert_one(self, document):
            raise RuntimeError("document too large")

    original = services.db.collection
    services.db.collection = lambda name: (
        BrokenCollection() if name == "platform_tool_calls" else original(name)
    )
    try:
        orchestrator = ScanOrchestrator(database=services.db, settings=services.settings)
        orchestrator._audit_tool_call(
            {
                "scan_id": scan.scan_id,
                "task_id": "t1",
                "agent_role": "recon",
                "tool": "http_request",
                "status": "ok",
            }
        )
    finally:
        services.db.collection = original

    events = services.events.list_after(scan.scan_id)
    kinds = [event["kind"] for event in events]
    assert "tool.record_failed" in kinds
    payload = next(event["payload"] for event in events if event["kind"] == "tool.record_failed")
    assert payload["tool"] == "http_request"
