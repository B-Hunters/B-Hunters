"""A failure the platform cannot explain is a defect.

The error ledger decides whether a scan was clean: a failure the
platform can name is an expected outcome of probing a target, and a
failure it cannot name means something went wrong that nobody
accounted for.  A tool that raises an exception without a message must
not therefore produce a failure with no explanation.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.errors import ErrorLedger, classify_error
from b_hunters.platform.tools.gateway import ToolGateway, ToolRegistry


class _Registry(ToolRegistry):
    pass


@pytest.mark.asyncio
async def test_an_exception_without_a_message_still_names_its_type():
    from b_hunters.platform.tools.gateway import ToolContext

    registry = _Registry()

    def boom(**kwargs):
        raise ValueError()

    registry.register(
        name="boom",
        description="raises",
        parameters={"type": "object", "properties": {}},
        handler=boom,
    )

    gateway = ToolGateway(registry)
    context = ToolContext(scan_id="s1", task_id="t1", role="recon")

    result = await gateway.execute(tool_name="boom", arguments={}, context=context)

    assert result.ok is False
    assert "ValueError" in (result.error or "")


def test_the_rate_limit_of_a_provider_is_an_explained_failure():
    # The provider says plainly that its plan is exhausted.  That is a
    # condition the platform can name, not a mystery.
    # The provider says plainly that its plan is exhausted.  That is a
    # condition the platform can name, not a mystery.
    classified = classify_error(
        "provider rate limit reached (HTTP 429): rate_limit_error: "
        "Token Plan usage limit reached: Upgrade your Token Plan"
    )
    assert classified != "unexplained"


def test_an_empty_failure_is_still_unexplained():
    ledger = ErrorLedger()
    ledger.add("tool_call", "")
    assert ledger.verdict()["verdict"] == "fail"
