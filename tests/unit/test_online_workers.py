"""A worker that is bound but not running is not online.

Karton only unregisters the bind of a consumer that is *not* persistent.
The workers are persistent, so a worker that stops leaves its bind
behind, and the queue stays bound for good.

Counting those as online is what made a scan wait for tasks that nobody
would take: the router sends a task to every consumer whose filters
match, so a task routed to a stopped worker sits in its queue, the
analysis tree never finishes, and the worker phase runs to its deadline.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.scanners import karton_bridge


class _Queue:
    def __init__(self, identity, consumers):
        self.identity = identity
        self.online_consumers_count = consumers


class _State:
    def __init__(self, queues):
        self.queues = queues


class _Backend:
    """A backend that reports the consumers whose client is named."""

    def __init__(self, consumers):
        self._consumers = consumers

    def get_online_consumers(self):
        return {name: [] for name in self._consumers}


class _Bridge(karton_bridge.KartonWorkerBridge):
    def __init__(self, queues, consumers=()):
        self.producer = type("P", (), {"backend": _Backend(consumers)})()
        self._queue_map = queues

    def _queues(self):  # noqa: D102 - the test double
        return list(self._queue_map.items())


@pytest.fixture
def patched_state(monkeypatch):
    import karton.core.inspect as inspect_module

    def install(queues, consumers=()):
        monkeypatch.setattr(inspect_module, "KartonState", lambda backend: _State(queues))
        return _Bridge(queues, consumers)

    return install


def test_a_worker_with_a_listener_is_online(patched_state):
    bridge = patched_state(
        {"normal:B-Hunters-Katana": _Queue("B-Hunters-Katana", 1)},
        consumers=["B-Hunters-Katana"],
    )

    assert bridge.online_identities() == ["B-Hunters-Katana"]


def test_a_worker_that_is_bound_but_not_listening_is_not_online(patched_state):
    """The bind outlives the worker; the worker does not."""
    bridge = patched_state(
        {"normal:B-Hunters-Gone": _Queue("B-Hunters-Gone", 0)},
    )

    assert bridge.online_identities() == []


def test_the_live_client_names_count(patched_state):
    """A worker whose client is named after it is visible even so."""
    bridge = patched_state(
        {"normal:B-Hunters-Katana": _Queue("B-Hunters-Katana", 0)},
        consumers=["B-Hunters-Katana"],
    )

    assert bridge.online_identities() == ["B-Hunters-Katana"]
