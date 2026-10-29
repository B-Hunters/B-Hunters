"""A rate limit is not a hiccup.

The provider counts the requests per minute.  A backoff of a second or
two is rejected again, so a run that is cut short by a rate limit loses
every role it was running.  The retry has to wait as long as the limit
needs, and it has to honour what the provider asked for.
"""

from __future__ import annotations

import httpx
import pytest

from b_hunters.platform.agents import provider as provider_module
from b_hunters.platform.agents.provider import (
    RATE_LIMIT_BACKOFF_SECONDS,
    ProviderConfig,
    ProviderError,
    _retry_after,
)


def _response(status_code: int, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        json={"choices": [{"message": {"content": "hello"}}]},
        request=httpx.Request("POST", "https://provider.invalid/v1/chat/completions"),
    )


def test_retry_after_is_read_in_seconds() -> None:
    response = _response(429, {"Retry-After": "42"})
    assert _retry_after(response) == 42.0


def test_retry_after_is_absent_when_the_provider_says_nothing() -> None:
    assert _retry_after(_response(429)) is None


def test_retry_after_that_is_not_a_number_is_ignored() -> None:
    assert _retry_after(_response(429, {"Retry-After": "soon"})) is None


def test_a_rate_limit_waits_longer_than_the_ordinary_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = provider_module.Provider(ProviderConfig(base_url="https://provider.invalid/v1", model="m"))
    error = ProviderError("provider rate limit reached (HTTP 429)", status_code=429, retryable=True)
    ordinary = client._backoff(ProviderError("boom", status_code=500, retryable=True), 1)
    limited = client._backoff(error, 1)

    assert limited >= RATE_LIMIT_BACKOFF_SECONDS
    assert limited > ordinary


def test_the_providers_own_instruction_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = provider_module.Provider(ProviderConfig(base_url="https://provider.invalid/v1", model="m"))
    error = ProviderError(
        "provider rate limit reached (HTTP 429)",
        status_code=429,
        retryable=True,
        retry_after=90.0,
    )
    assert client._backoff(error, 1) >= 90.0


@pytest.mark.asyncio
async def test_a_rate_limit_is_retried_until_it_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"count": 0}

    async def _request(body: dict[str, object], *, timeout: object = None) -> object:
        calls["count"] += 1
        if calls["count"] < 3:
            raise ProviderError("provider rate limit reached (HTTP 429)", status_code=429, retryable=True)
        return "done"

    client = provider_module.Provider(
        ProviderConfig(base_url="https://provider.invalid/v1", model="m", max_retries=4)
    )
    monkeypatch.setattr(client, "_request", _request)
    slept: list[float] = []

    async def _sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(provider_module, "_sleep", _sleep)

    assert await client._request_with_retry({}, timeout=None) == "done"
    assert calls["count"] == 3
    # The waits grow, and none of them is the sub-second backoff that
    # would be rejected again.
    assert len(slept) == 2
    assert all(delay >= RATE_LIMIT_BACKOFF_SECONDS for delay in slept)
    assert slept[1] > slept[0]
