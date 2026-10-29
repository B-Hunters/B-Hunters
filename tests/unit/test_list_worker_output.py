"""The agent can ask what the scanner workers found.

The crawlers find the surface; the scanners test it.  A role that wants
to test what a crawler found asks for it here, instead of reading the
legacy documents.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.platform.tools.builtin.worker_output import list_worker_output
from b_hunters.platform.tools.gateway import ToolContext, ToolError


class _Repository:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items
        self.calls: list[dict[str, Any]] = []

    def list_for_scan(
        self, scan_id: str, *, worker: str = "", kind: str = "", limit: int = 500
    ) -> list[dict[str, Any]]:
        self.calls.append({"scan_id": scan_id, "worker": worker, "kind": kind})
        return [
            item
            for item in self.items
            if item["scan_id"] == scan_id
            and (not worker or item["worker"] == worker)
            and (not kind or item["kind"] == kind)
        ][:limit]


def _context(repository: Any) -> ToolContext:
    context = ToolContext(scan_id="scan-1", task_id="task", role="recon")
    context.metadata["worker_output_repository"] = repository
    return context


def test_the_items_of_the_scan_are_listed() -> None:
    repository = _Repository(
        [
            {
                "scan_id": "scan-1",
                "worker": "B-Hunters-Katana",
                "kind": "url",
                "value": "http://a/x",
            },
            {
                "scan_id": "scan-2",
                "worker": "B-Hunters-Katana",
                "kind": "url",
                "value": "http://b/y",
            },
        ]
    )

    result = list_worker_output(context=_context(repository))

    assert result["count"] == 1
    assert result["items"][0]["value"] == "http://a/x"


def test_the_list_can_be_narrowed() -> None:
    repository = _Repository(
        [
            {"scan_id": "scan-1", "worker": "W", "kind": "url", "value": "http://a/x"},
            {"scan_id": "scan-1", "worker": "W", "kind": "path", "value": "/admin"},
        ]
    )

    result = list_worker_output(kind="path", context=_context(repository))

    assert result["count"] == 1
    assert result["items"][0]["value"] == "/admin"


def test_without_the_repository_the_tool_says_so() -> None:
    context = ToolContext(scan_id="scan-1", task_id="task", role="recon")
    with pytest.raises(ToolError):
        list_worker_output(context=context)
