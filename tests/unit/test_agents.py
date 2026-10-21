"""Unit tests for the agent provider, the compatibility layer and the runtime."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from b_hunters.platform.agents.compat import extract_tool_call, merge_native_and_compat
from b_hunters.platform.agents.provider import (
    ChatMessage,
    Provider,
    ProviderAuthError,
    ProviderConfig,
    ProviderInvalidResponse,
    ProviderTimeout,
    ToolCall,
)
from b_hunters.platform.agents.roles import builtin_roles, role_prompt
from b_hunters.platform.agents.schemas import (
    AgentMessage,
    Budget,
    CandidateFinding,
    Confidence,
    Disposition,
    MessageKind,
)
from b_hunters.platform.tools.gateway import (
    CAPABILITY_NETWORK,
    CAPABILITY_SHELL,
    CAPABILITY_WRITE,
    ToolContext,
    ToolGateway,
    ToolPermissions,
    ToolRegistry,
)


# ----------------------------------------------------------------------
# Provider configuration
# ----------------------------------------------------------------------
def test_chat_url_is_built_from_the_base_url() -> None:
    config = ProviderConfig(base_url="https://api.example.com/v1")
    assert config.chat_url() == "https://api.example.com/v1/chat/completions"
    assert config.models_url() == "https://api.example.com/v1/models"


def test_chat_url_does_not_double_up() -> None:
    config = ProviderConfig(base_url="https://api.example.com/v1/chat/completions")
    assert config.chat_url() == "https://api.example.com/v1/chat/completions"


def test_role_model_override_is_used() -> None:
    config = ProviderConfig(model="default-model", role_models={"verifier": "strong-model"})
    assert config.model_for_role("verifier") == "strong-model"
    assert config.model_for_role("recon") == "default-model"


def test_no_provider_hardcodes_a_vendor() -> None:
    """The provider layer must not assume a particular vendor."""
    source = __import__("b_hunters.platform.agents.provider", fromlist=["x"]).__file__
    text = open(source, encoding="utf-8").read()
    for forbidden in ["api.openai.com", "api.anthropic.com", "gpt-4", "claude-3"]:
        assert forbidden not in text, f"{forbidden} must not be hard-coded"


# ----------------------------------------------------------------------
# Provider responses
# ----------------------------------------------------------------------
def _response(payload: dict[str, Any], status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code=status_code, json=payload)


async def _provider(handler, **kwargs) -> Provider:
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    config = ProviderConfig(base_url="https://api.test/v1", model="test-model", api_key="secret", **kwargs)
    return Provider(config, client=client)


@pytest.mark.asyncio
async def test_successful_completion_is_parsed() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return _response(
            {
                "model": "test-model",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "hello"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
        )

    provider = await _provider(handler)
    completion = await provider.complete([{"role": "user", "content": "hi"}])
    assert completion.message.content == "hello"
    assert completion.total_tokens == 15
    assert completion.finish_reason == "stop"


@pytest.mark.asyncio
async def test_native_tool_calls_are_parsed() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return _response(
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "http_request",
                                        "arguments": '{"url": "https://x.test/"}',
                                    },
                                }
                            ],
                        }
                    }
                ]
            }
        )

    provider = await _provider(handler)
    completion = await provider.complete([{"role": "user", "content": "go"}])
    assert len(completion.message.tool_calls) == 1
    call = completion.message.tool_calls[0]
    assert call.name == "http_request"
    assert call.arguments == {"url": "https://x.test/"}
    assert call.origin == "native"


@pytest.mark.asyncio
async def test_authentication_failure_is_reported_clearly() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return _response({"error": "bad key"}, status_code=401)

    provider = await _provider(handler)
    with pytest.raises(ProviderAuthError):
        await provider.complete([{"role": "user", "content": "hi"}])


@pytest.mark.asyncio
async def test_server_error_is_retried() -> None:
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return _response({"error": "boom"}, status_code=503)
        return _response({"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    provider = await _provider(handler, max_retries=3, retry_backoff_seconds=0.01)
    completion = await provider.complete([{"role": "user", "content": "hi"}])
    assert completion.message.content == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_malformed_response_raises() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return _response({"choices": []})

    provider = await _provider(handler)
    with pytest.raises(ProviderInvalidResponse):
        await provider.complete([{"role": "user", "content": "hi"}])


@pytest.mark.asyncio
async def test_timeout_is_reported_as_retryable() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    provider = await _provider(handler, max_retries=0)
    with pytest.raises(ProviderTimeout):
        await provider.complete([{"role": "user", "content": "hi"}])


@pytest.mark.asyncio
async def test_authorization_header_is_sent_but_never_logged() -> None:
    seen: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization", "")
        return _response({"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    provider = await _provider(handler)
    await provider.complete([{"role": "user", "content": "hi"}])
    assert seen["auth"] == "Bearer secret"
    status = provider.status()
    assert "secret" not in json.dumps(status)


@pytest.mark.asyncio
async def test_native_tool_support_is_probed_and_cached() -> None:
    bodies: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        if "tools" in body:
            return _response(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "c1",
                                        "type": "function",
                                        "function": {"name": "probe", "arguments": "{}"},
                                    }
                                ],
                            }
                        }
                    ]
                }
            )
        return _response({"data": [{"id": "test-model"}]})

    provider = await _provider(handler)
    assert await provider.supports_native_tools() is True
    assert await provider.supports_native_tools() is True
    assert len(bodies) == 1  # the probe result is cached, not repeated


# ----------------------------------------------------------------------
# Compatibility layer
# ----------------------------------------------------------------------
def test_compat_extracts_a_plain_json_tool_call() -> None:
    call = extract_tool_call('{"tool": "http_request", "arguments": {"url": "https://x.test/"}}')
    assert call is not None
    assert call.name == "http_request"
    assert call.arguments == {"url": "https://x.test/"}
    assert call.origin == "compat"


def test_compat_extracts_a_fenced_tool_call() -> None:
    call = extract_tool_call('Sure, here it is:\n```json\n{"tool": "list_findings", "arguments": {}}\n```\n')
    assert call is not None
    assert call.name == "list_findings"


def test_compat_extracts_json_embedded_in_prose() -> None:
    call = extract_tool_call(
        'I will call the tool now: {"tool": "analyze_javascript", "arguments": {"source": "x"}} done'
    )
    assert call is not None
    assert call.name == "analyze_javascript"


def test_compat_ignores_prose_without_a_tool_call() -> None:
    assert extract_tool_call("I could not find anything interesting.") is None
    assert extract_tool_call("") is None


def test_compat_rejects_a_malformed_tool_call() -> None:
    assert extract_tool_call('{"tool": "x", "arguments": {invalid json}}') is None


def test_native_calls_are_preserved_by_merge() -> None:
    message = ChatMessage(role="assistant", content="ignored")
    message.tool_calls = [ToolCall(id="1", name="native_tool", arguments={})]
    merged = merge_native_and_compat(message)
    assert merged.tool_calls[0].name == "native_tool"
    assert merged.tool_calls[0].origin == "native"


def test_compat_path_produces_a_tool_call() -> None:
    message = ChatMessage(role="assistant", content='{"tool": "list_findings", "arguments": {}}')
    merged = merge_native_and_compat(message)
    assert len(merged.tool_calls) == 1
    assert merged.tool_calls[0].origin == "compat"
    assert merged.content == ""


# ----------------------------------------------------------------------
# Roles
# ----------------------------------------------------------------------
def test_every_role_has_a_prompt_and_permissions() -> None:
    roles = builtin_roles()
    assert len(roles) >= 10
    for role_id, role in roles.items():
        assert role.system_prompt.strip(), role_id
        assert role.objective.strip(), role_id
        assert role.output_schema, role_id
        assert role.budget, role_id


def test_every_role_prompt_includes_the_operating_policy() -> None:
    for role in builtin_roles().values():
        prompt = role_prompt(role)
        assert "authorised" in prompt
        assert "never" in prompt.lower()


def test_verifier_has_a_distinct_output_schema() -> None:
    verifier = builtin_roles()["verifier"]
    assert "verdict" in verifier.output_schema["properties"]
    assert verifier.output_schema["properties"]["verdict"]["enum"] == [
        "confirmed",
        "likely",
        "unverified",
        "inconclusive",
        "rejected",
    ]


def test_shell_capable_roles_are_not_the_default_ones() -> None:
    roles = builtin_roles()
    assert CAPABILITY_SHELL not in roles["recon"].permissions.capabilities
    assert CAPABILITY_SHELL in roles["source_analysis"].permissions.capabilities


# ----------------------------------------------------------------------
# Tool gateway
# ----------------------------------------------------------------------
def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        "read_thing",
        "Read a thing.",
        {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        lambda path, context=None: {"path": path},
        capabilities={},
    )
    registry.register(
        "write_thing",
        "Write a thing.",
        {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        lambda path, context=None: {"path": path},
        capabilities={CAPABILITY_WRITE},
    )
    registry.register(
        "shell_thing",
        "Run a shell command.",
        {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
        lambda cmd, context=None: {"cmd": cmd},
        capabilities={CAPABILITY_SHELL},
    )
    registry.register(
        "network_thing",
        "Make a request.",
        {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        lambda url, context=None: {"url": url},
        capabilities={CAPABILITY_NETWORK},
    )
    return registry


def _context(**kwargs) -> ToolContext:
    defaults = {
        "scan_id": "s1",
        "task_id": "t1",
        "role": "recon",
        "permissions": ToolPermissions(capabilities={}),
    }
    defaults.update(kwargs)
    return ToolContext(**defaults)


@pytest.mark.asyncio
async def test_tool_call_without_the_required_capability_is_denied() -> None:
    gateway = ToolGateway(_registry())
    result = await gateway.execute(tool_name="write_thing", arguments={"path": "a"}, context=_context())
    assert result.ok is False
    assert "write_files" in result.error


@pytest.mark.asyncio
async def test_tool_call_with_the_capability_succeeds() -> None:
    gateway = ToolGateway(_registry())
    context = _context(permissions=ToolPermissions(capabilities={CAPABILITY_WRITE}))
    result = await gateway.execute(
        tool_name="write_thing",
        arguments={"path": "a"},
        context=_context(permissions=ToolPermissions(capabilities={CAPABILITY_WRITE})),
    )
    assert result.ok is True
    # Structured output is rendered as JSON text for the model.
    assert json.loads(str(result.output)) == {"path": "a"}
    assert context.role == "recon"


@pytest.mark.asyncio
async def test_invalid_arguments_are_rejected() -> None:
    gateway = ToolGateway(_registry())
    result = await gateway.execute(tool_name="read_thing", arguments={"wrong": "x"}, context=_context())
    assert result.ok is False
    assert "invalid arguments" in result.error


@pytest.mark.asyncio
async def test_unknown_tool_is_rejected() -> None:
    gateway = ToolGateway(_registry())
    result = await gateway.execute(tool_name="nope", arguments={}, context=_context())
    assert result.ok is False
    assert "unknown tool" in result.error


@pytest.mark.asyncio
async def test_tool_not_offered_to_the_role_is_denied() -> None:
    gateway = ToolGateway(_registry())
    result = await gateway.execute(
        tool_name="read_thing",
        arguments={"path": "a"},
        context=_context(allowed_tools={"something_else"}),
    )
    assert result.ok is False
    assert "not offered" in result.error


@pytest.mark.asyncio
async def test_denied_tool_takes_priority() -> None:
    gateway = ToolGateway(_registry())
    result = await gateway.execute(
        tool_name="read_thing",
        arguments={"path": "a"},
        context=_context(permissions=ToolPermissions(capabilities=set(), denied_tools={"read_thing"})),
    )
    assert result.ok is False
    assert "denied" in result.error


@pytest.mark.asyncio
async def test_tool_timeout_is_enforced() -> None:
    import asyncio

    registry = ToolRegistry()
    registry.register(
        "slow",
        "Sleeps.",
        {"type": "object", "properties": {}},
        lambda context=None: asyncio.sleep(5),
        timeout=0.2,
    )
    gateway = ToolGateway(registry)
    result = await gateway.execute(tool_name="slow", arguments={}, context=_context())
    assert result.ok is False
    assert "timeout" in result.error.lower()


@pytest.mark.asyncio
async def test_tool_output_is_truncated() -> None:
    registry = ToolRegistry()
    registry.register(
        "big",
        "Returns a lot.",
        {"type": "object", "properties": {}},
        lambda context=None: "x" * 100000,
    )
    gateway = ToolGateway(registry)
    context = _context(permissions=ToolPermissions(capabilities=set(), max_output_bytes=1000))
    result = await gateway.execute(tool_name="big", arguments={}, context=context)
    assert result.ok is True
    assert len(str(result.output)) < 2000
    assert "truncated" in str(result.output)


@pytest.mark.asyncio
async def test_tool_calls_are_audited() -> None:
    records: list[dict[str, Any]] = []
    gateway = ToolGateway(_registry(), audit=records.append)
    await gateway.execute(tool_name="read_thing", arguments={"path": "a"}, context=_context())
    await gateway.execute(tool_name="nope", arguments={}, context=_context())
    assert len(records) == 2
    assert records[0]["status"] == "ok"
    assert records[1]["status"] == "error"


# ----------------------------------------------------------------------
# Budget
# ----------------------------------------------------------------------
def test_budget_reports_each_exhausted_dimension() -> None:
    budget = Budget(max_tokens=100, max_tool_calls=2, max_rounds=3, max_wall_clock_seconds=50)
    assert budget.exhausted(tokens_used=101, tool_calls=0, rounds=0, elapsed=0) == "token budget exhausted"
    assert budget.exhausted(tokens_used=0, tool_calls=3, rounds=0, elapsed=0) == "tool call budget exhausted"
    assert budget.exhausted(tokens_used=0, tool_calls=0, rounds=4, elapsed=0) == "round budget exhausted"
    assert (
        budget.exhausted(tokens_used=0, tool_calls=0, rounds=0, elapsed=60) == "wall clock budget exhausted"
    )
    assert budget.exhausted(tokens_used=0, tool_calls=0, rounds=0, elapsed=0) is None


def test_message_serialisation_round_trips() -> None:
    message = AgentMessage(
        scan_id="s",
        task_id="t",
        sender_role="recon",
        kind=MessageKind.CHALLENGE,
        target="https://x.test/",
        hypothesis="maybe vulnerable",
        confidence=Confidence.MEDIUM,
        disposition=Disposition.ESCALATE,
    )
    data = message.to_dict()
    restored = AgentMessage.from_dict(data)
    assert restored.kind == MessageKind.CHALLENGE
    assert restored.confidence == Confidence.MEDIUM
    assert restored.disposition == Disposition.ESCALATE


def test_candidate_finding_ignores_unknown_keys() -> None:
    finding = CandidateFinding.from_dict({"title": "t", "vuln_class": "xss", "summary": "s", "unexpected": 1})
    assert finding.title == "t"
    assert finding.vuln_class == "xss"
