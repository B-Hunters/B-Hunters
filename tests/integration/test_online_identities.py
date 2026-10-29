"""Which workers are online.

The participation table says a worker did not report.  That is only true
if the platform knows the worker was there: a worker that is connected
but consumed no task must not be reported as absent, because the two
are different failures and only one of them is the operator's problem.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.scanners.karton_bridge import identity_from_queue

pytestmark = pytest.mark.integration


def test_a_queue_name_carries_the_worker_identity():
    assert identity_from_queue("normal:B-Hunters-Nuclei") == "B-Hunters-Nuclei"
    assert identity_from_queue("B-Hunters-Katana") == "B-Hunters-Katana"
    assert identity_from_queue("") == ""


class FakeBackend:
    """A backend whose consumers are invisible and whose queues are not."""

    def __init__(self, consumers, queues):
        self._consumers = consumers
        self._queues = queues

    def get_online_consumers(self):
        return self._consumers


class FakeState:
    def __init__(self, backend):
        self.backend = backend

    @property
    def queues(self):
        return {name: [] for name in self.backend._queues}


def _bridge(consumers, queues, monkeypatch):
    from b_hunters.platform.scanners import karton_bridge

    bridge = karton_bridge.KartonWorkerBridge.__new__(karton_bridge.KartonWorkerBridge)
    bridge.producer = type("P", (), {"backend": FakeBackend(consumers, queues)})()

    import karton.core.inspect as inspect_module

    monkeypatch.setattr(inspect_module, "KartonState", FakeState)
    return bridge


def test_a_worker_with_an_unnamed_client_is_still_seen(monkeypatch):
    # The client is called "redis-py" and the identity is unknown, but the
    # worker is bound to a queue that carries its name.
    bridge = _bridge({}, ["normal:B-Hunters-ParamSpider"], monkeypatch)

    assert "B-Hunters-ParamSpider" in bridge.online_identities()


def test_the_client_names_are_seen_too(monkeypatch):
    bridge = _bridge({"B-Hunters-Katana": []}, [], monkeypatch)

    assert "B-Hunters-Katana" in bridge.online_identities()


def test_an_unreachable_backend_reports_nothing(monkeypatch):
    from b_hunters.platform.scanners import karton_bridge

    bridge = karton_bridge.KartonWorkerBridge.__new__(karton_bridge.KartonWorkerBridge)

    class Broken:
        def get_online_consumers(self):
            raise RuntimeError("the backend is down")

    bridge.producer = type("P", (), {"backend": Broken()})()

    assert bridge.online_identities() == []
