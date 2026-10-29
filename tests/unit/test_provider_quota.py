"""A rate limit and an exhausted plan are different problems.

The provider answers both with HTTP 429.  A rate limit is counted per
minute and a retry helps; an exhausted plan needs credits, and waiting
only wastes the scan's budget.  The message is what tells them apart,
and it has to reach the operator.
"""

from __future__ import annotations

import httpx
import pytest

from b_hunters.platform.agents import provider as provider_module
from b_hunters.platform.agents.provider import ProviderConfig, ProviderError


def _response(status_code: int, payload: dict | None = None, headers: dict | None = None):
    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        json=payload if payload is not None else {},
        request=httpx.Request("POST", "https://provider.invalid/v1/chat/completions"),
    )


@pytest.mark.asyncio
async def test_an_exhausted_plan_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    client = provider_module.Provider(ProviderConfig(base_url="https://provider.invalid/v1", model="m"))
    attempts = {"count": 0}

    async def _post(*args, **kwargs):
        attempts["count"] += 1
        return _response(
            429,
            {
                "type": "error",
                "error": {
                    "type": "rate_limit_error",
                    "message": (
                        "Token Plan usage limit reached: Upgrade your Token Plan or "
                        "purchase Credits for more usage. (2056)"
                    ),
                },
            },
        )

    monkeypatch.setattr(client._get_client(), "post", _post)

    with pytest.raises(ProviderError) as raised:
        await client.complete(model="m", messages=[{"role": "user", "content": "hi"}])

    assert attempts["count"] == 1, "an exhausted plan must not be retried"
    message = raised.value.message
    assert "usage limit reached" in message
    assert "will not help" in message
    assert raised.value.retryable is False


@pytest.mark.asyncio
async def test_a_rate_limit_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    client = provider_module.Provider(ProviderConfig(base_url="https://provider.invalid/v1", model="m"))
    attempts = {"count": 0}

    async def _post(*args, **kwargs):
        attempts["count"] += 1
        return _response(429, {"error": {"message": "too many requests"}})

    monkeypatch.setattr(client._get_client(), "post", _post)

    async def _sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(provider_module, "_sleep", _sleep)

    with pytest.raises(ProviderError) as raised:
        await client.complete(model="m", messages=[{"role": "user", "content": "hi"}])

    assert attempts["count"] > 1, "a rate limit is worth retrying"
    assert raised.value.retryable is True


def test_the_providers_message_is_read() -> None:
    response = _response(
        429, {"error": {"type": "rate_limit_error", "message": "Token Plan usage limit reached"}}
    )
    assert "Token Plan usage limit reached" in provider_module._error_detail(response)


def test_a_response_without_an_error_says_nothing() -> None:
    assert provider_module._error_detail(_response(429, {})) == ""
