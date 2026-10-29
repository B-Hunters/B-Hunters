"""The scanner must stay on the target.

A crawler records the third-party links of a page as well.  A scanner
that is handed the raw list probes youtube.com and google.com instead of
the target, and it never finishes.  The base class now keeps only the
links that belong to the target.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.bhunter import BHunters


class _Worker(BHunters):
    """The base class without its Karton and Mongo plumbing."""

    def __init__(self) -> None:  # noqa: D107 - the base class needs no setup
        pass

    def process(self, task: Any) -> None:  # noqa: D102 - abstract method
        raise NotImplementedError


TARGET = "172.25.0.15:5013"


@pytest.mark.parametrize(
    "link",
    [
        "http://172.25.0.15:5013/",
        "http://172.25.0.15:5013/graphql",
        "http://172.25.0.15:5013/static/jquery/jquery.js",
        "https://172.25.0.15:5013/audit",
    ],
)
def test_links_of_the_target_are_kept(link: str) -> None:
    assert _Worker.is_on_target(TARGET, link) is True


@pytest.mark.parametrize(
    "link",
    [
        "https://www.youtube.com/watch?v=ZQL7tL2S0oQ",
        "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application",
        "https://www.google.com/",
        "http://172.25.0.16:5013/graphql",
        "http://172.25.0.15:8080/graphql",
        "",
    ],
)
def test_links_of_other_hosts_are_dropped(link: str) -> None:
    assert _Worker.is_on_target(TARGET, link) is False


def test_a_target_without_a_port_keeps_every_port() -> None:
    # The platform always names a target as host:port.  A target without
    # a port matches every port of that host: the port is then part of
    # what is being scanned, not of what separates it from the target.
    assert _Worker.is_on_target("example.com", "http://example.com/x") is True
    assert _Worker.is_on_target("example.com", "http://example.com:8080/x") is True
    assert _Worker.is_on_target("example.com", "http://other.com:8080/x") is False


def test_checklinksexist_drops_the_third_party_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scanner is handed the target's links only."""
    worker = _Worker()
    checked: dict[str, Any] = {}

    class _Collection:
        def find_one(self, query: dict[str, Any]) -> Any:
            checked["query"] = query
            return {"Scanid": "6adec07b4a8091431faec29d"}

        def update_one(self, *args: Any, **kwargs: Any) -> Any:
            return None

    class _Database:
        def __getitem__(self, name: str) -> Any:
            return _Collection()

    worker.db = _Database()
    monkeypatch.setattr(worker, "waitformongo", lambda: None)
    monkeypatch.setattr(worker, "identity", "B-Hunters-SQLMap")

    links = worker.checklinksexist(
        TARGET,
        [
            "http://172.25.0.15:5013/graphql",
            "https://www.youtube.com/watch?v=1",
            "http://172.25.0.15:5013/audit",
        ],
    )

    assert links == ["http://172.25.0.15:5013/graphql", "http://172.25.0.15:5013/audit"]
