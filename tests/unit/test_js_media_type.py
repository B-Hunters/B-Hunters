"""The JavaScript media-type check.

A URL is a script when the server says so.  The old check only accepted
``application/javascript``, a type that was never registered and that RFC
9239 obsoleted in favour of ``text/javascript``: every JavaScript URL was
dropped, so no ``js`` task was ever published and the workers that store
their findings by that check stored nothing.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.bhunter import BHunters


class _Response:
    def __init__(self, content_type: str) -> None:
        self.headers = {"Content-Type": content_type}


class _Worker(BHunters):
    """The base class without its Karton and Mongo plumbing."""

    def __init__(self) -> None:  # noqa: D107 - the base class needs no setup
        pass

    def process(self, task: Any) -> None:  # noqa: D102 - abstract method
        raise NotImplementedError


@pytest.mark.parametrize(
    "content_type",
    [
        "application/javascript",
        "text/javascript",
        "text/javascript; charset=utf-8",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
        "TEXT/JAVASCRIPT",
    ],
)
def test_javascript_media_types_are_accepted(monkeypatch: pytest.MonkeyPatch, content_type: str) -> None:
    monkeypatch.setattr(
        "b_hunters.bhunter.requests.get",
        lambda *args, **kwargs: _Response(content_type),
    )
    assert _Worker().checkjs("http://target/app.js") is True


@pytest.mark.parametrize(
    "content_type",
    [
        "text/html; charset=utf-8",
        "application/json",
        "image/png",
        "",
    ],
)
def test_other_media_types_are_rejected(monkeypatch: pytest.MonkeyPatch, content_type: str) -> None:
    monkeypatch.setattr(
        "b_hunters.bhunter.requests.get",
        lambda *args, **kwargs: _Response(content_type),
    )
    assert _Worker().checkjs("http://target/app.js") is False


def test_a_request_that_fails_is_not_a_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*args: Any, **kwargs: Any) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr("b_hunters.bhunter.requests.get", _boom)
    assert _Worker().checkjs("http://target/app.js") is False


def test_a_response_without_a_content_type_is_not_a_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Bare:
        headers: dict[str, str] = {}

    monkeypatch.setattr("b_hunters.bhunter.requests.get", lambda *args, **kwargs: _Bare())
    assert _Worker().checkjs("http://target/app.js") is False
