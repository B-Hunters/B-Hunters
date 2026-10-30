"""The agent loop, on a framework.

The platform keeps its own orchestrator, its tool gateway and its scope
enforcer; what this module adds is a loop that handles the parts every
tool-calling agent has to get right: the request/response cycle, the tool
calls, the usage accounting, the retries on a rate limit and the
structured output.

The gateway's tools are bridged into framework tools.  The bridge keeps
the schema of every tool - the model sees the same fields and the same
descriptions - and the tool is still called through the gateway, so the
capability check, the scope check and the audit stay where they are.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Annotated, Any, Optional, cast

from pydantic import BaseModel, Field, ValidationError
from pydantic_ai import RunContext
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    RequestUsage,
    SystemPromptPart,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.tools import Tool

from ..tools.gateway import ToolContext, ToolDefinition
from .provider import ToolSpec


class Conclusion(BaseModel):
    """What an agent concluded.

    The conclusion is a model, not a blob of text: a malformed answer is
    a validation error the framework can retry, rather than an empty
    conclusion that reaches the console.
    """

    conclusion: str = Field(default="", description="What the agent found, in prose.")
    # A model writes what it writes: the confidence may come as a level or
    # as a number, the observations as one string or as a list, and the
    # findings as objects or as text.  The model is normalised rather
    # than rejected, because a rejected conclusion is a lost finding.
    confidence: str | float = Field(
        default="none",
        description="How sure the agent is: none, low, medium, high or confirmed.",
    )
    observations: list[str] | str = Field(default_factory=list)
    uncertainty: str = Field(default="", description="What the agent could not settle.")
    next_step: str = Field(default="", description="What the agent would do next.")
    findings: list[dict[str, Any] | str] = Field(default_factory=list)
    delegate: Optional[dict[str, Any]] = Field(default=None)


def _python_type(schema: dict[str, Any]) -> Any:
    """The Python type of a JSON schema property."""
    kind = schema.get("type")
    if kind == "integer":
        return int
    if kind == "number":
        return float
    if kind == "boolean":
        return bool
    if kind == "array":
        return list
    if kind == "object":
        return dict
    return str


def _accepts_null(schema: dict[str, Any]) -> bool:
    """Does the schema accept a null for this property?"""
    kind = schema.get("type")
    if isinstance(kind, list):
        return "null" in kind
    return kind == "null"


def _annotation(schema: dict[str, Any], *, optional: bool = False) -> Any:
    """The annotation of a property, with the description it carries."""
    description = str(schema.get("description", "")).strip()
    kind = Optional[_python_type(schema)] if optional else _python_type(schema)
    if not description:
        return kind
    return Annotated[kind, Field(description=description)]


#: The levels a confidence may be given in.
CONFIDENCE_LEVELS = ("none", "low", "medium", "high", "confirmed")


def normalise_conclusion(conclusion: Conclusion) -> dict[str, Any]:
    """The conclusion in the shape the platform stores.

    The model is free to write the confidence as a number, the
    observations as one string and the findings as text.  The platform
    stores a level, a list and objects, so that is what it gets.
    """
    confidence = conclusion.confidence
    if isinstance(confidence, (int, float)):
        number = float(confidence)
        if number >= 0.9:
            confidence = "confirmed"
        elif number >= 0.7:
            confidence = "high"
        elif number >= 0.4:
            confidence = "medium"
        elif number > 0:
            confidence = "low"
        else:
            confidence = "none"
    else:
        confidence = str(confidence).strip().lower()
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "none"

    observations = conclusion.observations
    if isinstance(observations, str):
        observations = [observations] if observations.strip() else []

    findings: list[dict[str, Any]] = []
    for finding in conclusion.findings:
        if isinstance(finding, dict):
            findings.append(finding)
        elif str(finding).strip():
            findings.append({"title": str(finding).strip()})

    return {
        "conclusion": conclusion.conclusion,
        "confidence": confidence,
        "observations": list(observations),
        "uncertainty": conclusion.uncertainty,
        "next_step": conclusion.next_step,
        "findings": findings,
        "delegate": conclusion.delegate,
    }


def conclusion_from_text(text: str) -> Conclusion:
    """The conclusion a model wrote as prose.

    A model that answers with text instead of filling in the answer tool
    still knows what it found.  Its prose is read as the conclusion
    rather than the run ending with nothing: the role did the work, and
    throwing the answer away because it came in the wrong shape loses it.
    """
    text = (text or "").strip()
    if not text:
        return Conclusion()
    payload = _json_object_in(text)
    if isinstance(payload, dict):
        try:
            return Conclusion.model_validate(payload)
        except ValidationError:
            pass
    return Conclusion(
        conclusion=text[:4000],
        observations=[text[:1000]],
    )


def _json_object_in(text: str) -> Any:
    """The JSON object in a piece of text, if there is one."""
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except (TypeError, ValueError):
        return None


def build_tools(
    definitions: list[ToolDefinition],
    context: ToolContext,
    gateway: Any = None,
    *,
    records: Optional[list[dict[str, Any]]] = None,
    max_identical_calls: int = 3,
) -> list[Tool[Any]]:
    """The gateway's tools as framework tools.

    Each tool becomes a function whose signature is generated from the
    tool's JSON schema, so the framework derives the schema the gateway
    already published.  The tool is executed through the gateway, so a
    tool the role may not use is refused there, and the refusal is
    recorded.

    The tool is executed through the gateway, so the capability check, the
    scope check, the audit trail and the per-call timeout are the ones
    the platform already has.
    """
    tools: list[Tool[Any]] = []
    for definition in definitions:
        # Only the tools the role may use are bridged.  A model that is
        # offered a tool it may not use does not learn from the refusal:
        # it keeps reaching for it, and the rounds it spends on the
        # refusals are the rounds it needed for its own work.
        tools.append(_as_tool(definition, gateway, records, max_identical_calls))
    return tools


def _as_tool(
    definition: ToolDefinition,
    gateway: Any = None,
    records: Optional[list[dict[str, Any]]] = None,
    max_identical_calls: int = 3,
) -> Tool[Any]:
    """One gateway tool as a framework tool."""
    properties = (definition.parameters or {}).get("properties", {}) or {}
    required = set((definition.parameters or {}).get("required", []) or [])

    seen: dict[str, int] = {}

    async def call(ctx: RunContext[Any], **kwargs: Any) -> Any:
        # An optional argument the model did not supply is not passed at
        # all: the tool's schema does not accept a null where it expects a
        # value, and the gateway would refuse the call.
        supplied = {
            name: value
            for name, value in kwargs.items()
            if value is not None or _accepts_null(properties.get(name, {}))
        }
        kwargs = supplied
        tool_context: ToolContext = cast(ToolContext, getattr(ctx, "deps", ctx))
        call_id = str(getattr(ctx, "tool_call_id", "") or "")
        signature = f"{definition.name}:{json.dumps(kwargs, sort_keys=True, default=str)}"
        seen[signature] = seen.get(signature, 0) + 1
        if seen[signature] > max_identical_calls:
            # The same call with the same arguments again: the agent is
            # going in circles.  Say so, and let it change its approach.
            return json.dumps(
                {
                    "error": (
                        f"tool '{definition.name}' was already called with these exact "
                        "arguments. Change your approach."
                    )
                }
            )
        if gateway is not None:
            result = await gateway.execute(
                tool_name=definition.name,
                arguments=kwargs,
                context=tool_context,
                call_id=call_id,
            )
            # The model is told which tool produced the result: the
            # answer of one tool is read next to the answers of the
            # others.
            if result.ok:
                body = str(result.output)
                if len(body) > 12000:
                    body = body[:12000] + "\n... [truncated]"
                payload = f"Tool '{definition.name}' succeeded:\n{body}"
            else:
                payload = f"Tool '{definition.name}' failed: {result.error}"
            if records is not None:
                records.append(
                    {
                        "tool": definition.name,
                        "arguments": kwargs,
                        "ok": result.ok,
                        "error": result.error,
                        "duration_ms": result.duration_ms,
                        "output": str(result.output)[:4000],
                        "call_id": call_id,
                    }
                )
            return json.dumps(payload, default=str)
        return json.dumps(await definition.handler(**kwargs, context=tool_context), default=str)

    parameters = [inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=RunContext[Any])]
    for name, schema in properties.items():
        if name in required:
            parameters.append(
                inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, annotation=_annotation(schema))
            )
        else:
            parameters.append(
                inspect.Parameter(
                    name,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=_annotation(schema, optional=True),
                )
            )
    call.__signature__ = inspect.Signature(parameters)  # type: ignore[attr-defined]
    # The framework resolves the annotations of the function, not only the
    # signature, so both carry the schema of the tool.
    call.__annotations__ = {  # type: ignore[attr-defined]
        parameter.name: parameter.annotation for parameter in parameters
    }
    call.__name__ = definition.name
    call.__doc__ = definition.description

    return Tool(
        call,
        takes_ctx=True,
        name=definition.name,
        description=definition.description,
    )


class ProviderModel(Model):
    """The platform's provider, as a framework model.

    The provider stays the transport: it knows the quirks of the endpoint
    - the tool-call format of MiniMax, the compatibility mode for a
    provider without native tools - and it backs off when the provider
    rate limits a request.  The framework drives the loop around it.
    """

    def __init__(
        self,
        provider: Any,
        *,
        role: str = "",
        temperature: float = 0.2,
        max_output_tokens: int = 4096,
        native_tools: bool = True,
        nudge: Optional[Callable[[int], Optional[str]]] = None,
        function_tools_until: int = 0,
    ) -> None:
        super().__init__()
        # Not ``_provider``: the framework's model base reads that name
        # for its own provider, and it would call the framework's methods
        # on the platform's provider.
        self._transport = provider
        self._role = role
        self._temperature = temperature
        self._max_output_tokens = max_output_tokens
        self._native_tools = native_tools
        self._nudge = nudge
        #: From this request on, the tools are withheld.  The budget ends
        #: with a request that the role may still make, and on that one
        #: it is offered nothing but the answer it has to give: a role
        #: that is told to conclude and then calls a tool again must not
        #: lose everything it found.
        self._function_tools_until = function_tools_until
        #: The usage of the last request, so the platform can watch the
        #: token budget while the framework drives the loop.
        self.last_usage_total_tokens = 0
        #: The tokens of every request of this run.
        self.total_tokens = 0
        #: How many requests the endpoint was asked for.  The budget
        #: limits the requests, so the nudge that asks the role to
        #: conclude is counted in the same currency.
        self.request_count = 0

    @property
    def model_name(self) -> str:
        return str(getattr(self._transport.config, "model", "") or "model")

    @property
    def system(self) -> str:
        return "b-hunters"

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: Any = None,
        model_request_parameters: ModelRequestParameters = None,  # type: ignore[assignment]
    ) -> ModelResponse:
        """One request to the provider."""
        self.request_count += 1

        payload: list[dict[str, Any]] = []
        for message in messages:
            payload.extend(_to_openai_messages(message))
        if not self._native_tools:
            # An endpoint without native tools never saw a tool call, so
            # it must not be answered with a tool message: the result
            # goes back as a plain message.
            payload = [
                {"role": "user", "content": item["content"]} if item.get("role") == "tool" else item
                for item in payload
            ]
        if self._nudge is not None:
            text = self._nudge(self.request_count)
            if text:
                payload.append({"role": "user", "content": text})
        tools: list[ToolSpec] = []
        withhold_tools = bool(self._function_tools_until and self.request_count > self._function_tools_until)
        if self._native_tools and model_request_parameters is not None:
            # The provider takes its own tool description, so the tools
            # are handed over in the shape it expects.
            if not withhold_tools:
                tools = [
                    ToolSpec(
                        name=definition.name,
                        description=definition.description or "",
                        parameters=definition.parameters_json_schema,
                    )
                    for definition in model_request_parameters.function_tools
                ]
            # The structured output is asked for as a tool as well: the
            # model fills it in, and the framework reads the answer from
            # the call.  A provider that answers with prose is a provider
            # that answers with prose - the framework checks the answer
            # against the schema and retries when it does not fit.
            #
            # The answer tool is offered even when the other tools are
            # withheld: withholding it as well left the role with no way
            # to deliver its conclusion at all, and it ran out of
            # rounds with everything it had found still in its head.
            for definition in model_request_parameters.output_tools:
                tools.append(
                    ToolSpec(
                        name=definition.name,
                        description=definition.description or "",
                        parameters=definition.parameters_json_schema,
                    )
                )
        completion = await self._transport.complete(
            payload,
            tools=tools if self._native_tools else (),
            role=self._role,
            temperature=self._temperature,
            max_tokens=self._max_output_tokens,
        )
        if not self._native_tools:
            # The model wrote the tool call as text; read it back.
            from .compat import merge_native_and_compat

            completion.message = merge_native_and_compat(completion.message)

        parts: list[Any] = []
        message = completion.message
        if message.content:
            parts.append(TextPart(content=message.content))
        for call in message.tool_calls:
            parts.append(
                ToolCallPart(
                    tool_name=call.name,
                    args=call.arguments,
                    tool_call_id=call.id,
                )
            )
        if not parts:
            parts.append(TextPart(content=""))

        usage = RequestUsage(
            input_tokens=completion.prompt_tokens,
            output_tokens=completion.completion_tokens,
        )
        self.last_usage_total_tokens = int(completion.total_tokens or 0)
        self.total_tokens += self.last_usage_total_tokens
        return ModelResponse(
            parts=parts,
            model_name=completion.model or self.model_name,
            usage=usage,
            provider_name="b-hunters",
        )


def _to_openai_messages(message: ModelMessage) -> list[dict[str, Any]]:
    """A framework message in the shape the provider expects.

    A request may carry three things: the instructions of the agent (the
    role's prompt), the prompt itself and the results of the tools. They
    are three separate messages, in that order.
    """
    if isinstance(message, ModelResponse):
        text = "\n".join(part.content for part in message.parts if isinstance(part, TextPart))
        payload: dict[str, Any] = {"role": "assistant", "content": text}
        calls = [part for part in message.parts if isinstance(part, ToolCallPart)]
        if calls:
            payload["tool_calls"] = [
                {
                    "id": call.tool_call_id or "",
                    "type": "function",
                    "function": {
                        "name": call.tool_name,
                        "arguments": json.dumps(call.args_as_dict(), default=str),
                    },
                }
                for call in calls
            ]
        return [payload]

    instructions = str(getattr(message, "instructions", "") or "")
    texts: list[str] = []
    results: list[dict[str, Any]] = []
    for part in message.parts:
        if isinstance(part, SystemPromptPart):
            instructions = f"{instructions}\n\n{part.content}" if instructions else part.content
        elif isinstance(part, UserPromptPart):
            content = part.content
            texts.append(content if isinstance(content, str) else str(content))
        elif isinstance(part, ToolReturnPart):
            results.append(
                {
                    "role": "tool",
                    "tool_call_id": part.tool_call_id or "",
                    "content": str(part.content),
                }
            )

    messages: list[dict[str, Any]] = []
    if instructions:
        messages.append({"role": "system", "content": instructions})
    if texts:
        messages.append({"role": "user", "content": "\n".join(texts)})
    messages.extend(results)
    return messages


class NudgeModel(OpenAIChatModel):
    """The model, with the platform's nudges.

    The platform asks a role to record what it found a few rounds before
    its budget runs out: a model gets one answer per round, so a role that
    only says "I will record it" in its last round records nothing.  The
    nudge is a message added to the request, which is where the platform's
    own loop used to put it.
    """

    def __init__(
        self, *args: Any, nudge: Optional[Callable[[], Optional[str]]] = None, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self._nudge = nudge

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: Any = None,
        model_request_parameters: ModelRequestParameters = None,  # type: ignore[assignment]
    ) -> Any:
        if self._nudge is not None:
            text = self._nudge()
            if text:
                messages = list(messages) + [ModelRequest(parts=[UserPromptPart(text)])]
        return await super().request(messages, model_settings, model_request_parameters)
