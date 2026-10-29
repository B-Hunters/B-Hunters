"""The authentication payload a task carries.

A scan can name an identity: the platform puts the identity's cookies
and headers into the payload of the task it publishes, and the worker
adds them to the request its tool makes.  The payload is optional - a
scan without an identity carries none - and it holds secrets, so no
value of it ever reaches a log line or an error message.
"""

from __future__ import annotations

import logging
from typing import Any

from b_hunters.bhunter import BHunters


class _Task:
    """A task that carries nothing but a payload."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload


class _Worker(BHunters):
    """A worker without a configuration file and without a database.

    The base class wants both when it is constructed, and the helper
    needs neither: it only reads the task.
    """

    identity = "B-Hunters-test-worker"

    def __init__(self) -> None:
        pass

    def process(self, task: Any) -> None:
        """The worker does nothing: only the helper is under test."""


def _worker() -> BHunters:
    return _Worker()


def _task(payload: Any) -> _Task:
    return _Task(payload)


def test_an_absent_auth_payload_yields_no_headers() -> None:
    worker = _worker()
    assert worker.auth_headers(_task(payload={})) == {}


def test_the_auth_payload_becomes_headers() -> None:
    worker = _worker()
    headers = worker.auth_headers(
        _task(payload={"auth": {"cookies": {"JSESSIONID": "abc"}, "headers": {"X-Test": "1"}}})
    )
    assert headers["Cookie"] == "JSESSIONID=abc"
    assert headers["X-Test"] == "1"


def test_extra_headers_win() -> None:
    worker = _worker()
    headers = worker.auth_headers(
        _task(payload={"auth": {"headers": {"X-Test": "1"}, "extra": {"X-Test": "2"}}})
    )
    assert headers["X-Test"] == "2"


def test_an_empty_auth_payload_yields_no_headers() -> None:
    worker = _worker()
    assert worker.auth_headers(_task(payload={"auth": {}})) == {}
    assert worker.auth_cookies(_task(payload={"auth": {}})) == {}


def test_several_cookies_become_one_cookie_header() -> None:
    worker = _worker()
    headers = worker.auth_headers(
        _task(payload={"auth": {"cookies": {"JSESSIONID": "abc", "theme": "dark"}}})
    )
    assert headers["Cookie"] == "JSESSIONID=abc; theme=dark"


def test_the_cookies_are_read_on_their_own() -> None:
    worker = _worker()
    task = _task(payload={"auth": {"cookies": {"JSESSIONID": "abc"}, "headers": {"X-Test": "1"}}})
    assert worker.auth_cookies(task) == {"JSESSIONID": "abc"}


def test_the_auth_payload_is_read_on_its_own() -> None:
    worker = _worker()
    auth = {"cookies": {"JSESSIONID": "abc"}, "headers": {"X-Test": "1"}}
    assert worker.auth_payload(_task(payload={"auth": auth})) == auth


def test_a_task_without_a_payload_yields_no_headers() -> None:
    worker = _worker()
    assert worker.auth_headers(_task(payload=None)) == {}
    assert worker.auth_headers(_task(payload="not a mapping")) == {}


def test_the_values_are_not_logged(caplog: Any) -> None:
    caplog.set_level(logging.DEBUG)
    worker = _worker()
    worker.auth_headers(
        _task(
            payload={
                "auth": {
                    "cookies": {"JSESSIONID": "s3cr3t"},
                    "headers": {"X-Test": "s3cr3t"},
                }
            }
        )
    )
    assert "s3cr3t" not in caplog.text
