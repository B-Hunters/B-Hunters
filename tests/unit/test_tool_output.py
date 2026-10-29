"""What a tool call stores.

The stored tool call carries the full output next to the summary: the
transcript shows what the model saw.  The output is bounded at the
limit the gateway already applies, and a cut is never silent.
"""

from __future__ import annotations

import asyncio

from b_hunters.platform.tools.gateway import (
    ToolContext,
    ToolGateway,
    ToolPermissions,
    ToolRegistry,
    bound_output,
)


def _context(max_output_bytes: int = 512 * 1024) -> ToolContext:
    return ToolContext(
        scan_id="s1",
        task_id="t1",
        role="recon",
        permissions=ToolPermissions(max_output_bytes=max_output_bytes),
    )


def _gateway(records: list[dict]) -> ToolGateway:
    registry = ToolRegistry()
    registry.register(
        "echo",
        "return what it is given",
        {"type": "object", "properties": {"text": {"type": "string"}}},
        lambda text, context: text,
    )
    return ToolGateway(registry, audit=records.append)


def test_the_full_output_is_stored_next_to_the_summary() -> None:
    records: list[dict] = []
    gateway = _gateway(records)

    asyncio.run(gateway.execute(tool_name="echo", arguments={"text": "x" * 5000}, context=_context()))

    record = records[0]
    assert record["output"] == "x" * 5000
    assert len(record["output_summary"]) == 2000
    assert record["output_truncated"] is False
    assert record["output_bytes"] == 5000


def test_an_output_that_does_not_fit_is_cut_and_says_so() -> None:
    records: list[dict] = []
    gateway = _gateway(records)
    context = _context(max_output_bytes=100)

    asyncio.run(gateway.execute(tool_name="echo", arguments={"text": "x" * 5000}, context=context))

    record = records[0]
    assert len(record["output"].encode("utf-8")) == 100
    assert record["output_truncated"] is True
    # The size of the output that was cut, not of the text that was kept.
    assert record["output_bytes"] > 100


def test_a_failed_call_stores_no_output() -> None:
    records: list[dict] = []
    gateway = _gateway(records)

    asyncio.run(gateway.execute(tool_name="unknown", arguments={}, context=_context()))

    record = records[0]
    assert record["status"] == "error"
    assert record["output"] == ""
    assert record["output_bytes"] == 0
    assert record["output_truncated"] is False


def test_the_output_is_measured_in_bytes_and_not_in_characters() -> None:
    text = "é" * 100

    stored, truncated, size = bound_output(text, 100)

    assert truncated is True
    assert size == 200
    assert len(stored.encode("utf-8")) == 100


def test_an_output_that_fits_is_kept_whole() -> None:
    stored, truncated, size = bound_output("hello", 100)

    assert stored == "hello"
    assert truncated is False
    assert size == 5


def test_the_stored_output_never_exceeds_the_limit() -> None:
    records: list[dict] = []
    gateway = _gateway(records)
    context = _context(max_output_bytes=64)

    asyncio.run(gateway.execute(tool_name="echo", arguments={"text": "x" * 100000}, context=context))

    assert len(records[0]["output"].encode("utf-8")) <= 64
