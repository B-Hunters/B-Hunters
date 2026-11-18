"""The worker phase does not wait for a scan that will never finish.

The router sends a task to every consumer whose filters match it.  A
worker that has stopped leaves its bind behind, so a task routed to it
sits in a queue for good - and a scan that waits for the whole analysis
tree waits for that task too.

That is how the worker phase spent the whole budget of a scan and left
the agent phase with none.  A scan that was asked to stop waited as well,
for the same reason: nothing was watching.

The wait ends when the remaining tasks are queued to consumers nobody is
listening to, or when the scan is stopped.
"""

from __future__ import annotations

import time

import pytest

from b_hunters.platform.scanners import karton_bridge


class _Task:
    def __init__(self, status, receiver):
        self.status = status
        self.headers = {"receiver": receiver}


class _Analysis:
    def __init__(self, tasks):
        self.tasks = tasks


class _State:
    def __init__(self, analysis):
        self._analysis = analysis

    def get_analysis(self, root_uid):
        return self._analysis


class _Bridge(karton_bridge.KartonWorkerBridge):
    """A bridge whose backend is not needed."""

    def __init__(self, analysis):
        self.producer = type("P", (), {"backend": object()})()
        self._analysis = analysis
        self.poll_seconds = 0.01


def _patch_state(monkeypatch, analysis):
    import karton.core.inspect as inspect_module

    monkeypatch.setattr(inspect_module, "KartonState", lambda backend: _State(analysis))


def test_the_wait_ends_when_every_task_is_finished(monkeypatch):
    from karton.core.task import TaskState

    analysis = _Analysis([_Task(TaskState.FINISHED, "B-Hunters-Katana")])
    _patch_state(monkeypatch, analysis)
    bridge = _Bridge(analysis)

    bridge._await_analysis("root", deadline=time.monotonic() + 5, online={"B-Hunters-Katana"})


def test_the_wait_ends_when_the_remaining_tasks_have_nowhere_to_go(monkeypatch):
    """The task is queued to a worker that is not running."""
    from karton.core.task import TaskState

    analysis = _Analysis([_Task(TaskState.DECLARED, "B-Hunters-gone")])
    _patch_state(monkeypatch, analysis)
    bridge = _Bridge(analysis)

    started = time.monotonic()
    bridge._await_analysis(
        "root",
        deadline=time.monotonic() + 30,
        online={"B-Hunters-Katana"},
    )

    assert time.monotonic() - started < 5, "the wait must not run to its deadline"


def test_the_wait_ends_when_the_scan_is_stopped(monkeypatch):
    from karton.core.task import TaskState

    analysis = _Analysis([_Task(TaskState.DECLARED, "B-Hunters-Katana")])
    _patch_state(monkeypatch, analysis)
    bridge = _Bridge(analysis)

    started = time.monotonic()
    bridge._await_analysis(
        "root",
        deadline=time.monotonic() + 30,
        should_stop=lambda: True,
        online={"B-Hunters-Katana"},
    )

    assert time.monotonic() - started < 5, "a stopped scan does not wait"


def test_the_wait_continues_while_a_running_worker_still_has_a_task(monkeypatch):
    from karton.core.task import TaskState

    analysis = _Analysis([_Task(TaskState.DECLARED, "B-Hunters-Katana")])
    _patch_state(monkeypatch, analysis)
    bridge = _Bridge(analysis)

    started = time.monotonic()
    bridge._await_analysis(
        "root",
        deadline=time.monotonic() + 0.2,
        online={"B-Hunters-Katana"},
    )

    # It waited, and it waited no longer than it was told to.
    assert time.monotonic() - started >= 0.15
    assert time.monotonic() - started < 5
