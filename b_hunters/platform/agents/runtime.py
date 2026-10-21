"""The agent runtime.

A single agent run is a bounded loop:

    model call -> tool calls -> tool results -> model call -> ... -> conclusion

The loop is bounded by four independent limits - rounds, tool calls, tokens
and wall-clock - so a confused or looping agent cannot consume the scan
budget indefinitely.  Every tool call goes through the gateway, every
message is persisted, and every conclusion is emitted as a structured
:class:`~b_hunters.platform.agents.schemas.AgentRun`.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Optional

from ..tools.gateway import ToolContext, ToolGateway, ToolResult
from .compat import build_compat_instruction, merge_native_and_compat
from .provider import ChatMessage, Completion, Provider, ProviderError, ToolCall
from .roles import AgentRole, role_prompt
from .schemas import (
    AgentMessage,
    AgentRun,
    Budget,
    CandidateFinding,
    Confidence,
    Disposition,
    EvidenceRef,
    MessageKind,
)

log = logging.getLogger(__name__)

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.S)


@dataclass
class AgentRuntimeConfig:
    """Tunables for the agent loop."""

    max_rounds: int = 8
    max_tool_calls: int = 40
    max_tokens: int = 200000
    max_wall_clock_seconds: int = 900
    #: Seconds to wait for a tool call before giving up on that round.
    tool_timeout: float = 90.0
    #: Repeat the same tool call with identical arguments at most this often.
    max_identical_calls: int = 2
    #: Temperature used for agent reasoning.
    temperature: float = 0.0
    #: Whether the model is asked to return structured JSON.
    structured_output: bool = True


@dataclass
class AgentRuntime:
    """Executes a single agent task."""

    provider: Provider
    gateway: ToolGateway
    role: AgentRole
    config: AgentRuntimeConfig = field(default_factory=AgentRuntimeConfig)
    #: Called with every structured message the agent produces.
    on_message: Optional[Callable[[AgentMessage], None]] = None
    #: Called with every tool call record.
    on_tool_call: Optional[Callable[[dict[str, Any]], None]] = None
    #: Called after each round with a status snapshot.
    on_progress: Optional[Callable[[dict[str, Any]], None]] = None

    # ------------------------------------------------------------------
    async def run(
        self,
        *,
        scan_id: str,
        task_id: str,
        objective: str,
        target: str = "",
        context: Optional[ToolContext] = None,
        input_payload: Optional[dict[str, Any]] = None,
        prior_messages: Sequence[AgentMessage] = (),
    ) -> AgentRun:
        """Run the agent until it concludes or a budget is exhausted."""
        started = time.monotonic()
        budget = Budget(
            max_tokens=self.config.max_tokens,
            max_tool_calls=self.config.max_tool_calls,
            max_rounds=self.config.max_rounds,
            max_wall_clock_seconds=self.config.max_wall_clock_seconds,
        )
        ctx = context or ToolContext(scan_id=scan_id, task_id=task_id, role=self.role.role)
        ctx.budget = budget

        definitions = self.gateway.registry.for_role(self.role.role, ctx.allowed_tools)
        tools = [d.to_openai() for d in definitions]

        messages: list[dict[str, Any]] = [{"role": "system", "content": role_prompt(self.role)}]
        if definitions and not (await self._native_tools_enabled()):
            messages[0]["content"] += "\n\n" + build_compat_instruction(definitions)
        if input_payload:
            messages.append(
                {
                    "role": "user",
                    "content": "Task context:\n" + json.dumps(input_payload, indent=2, default=str)[:20000],
                }
            )
        prompt_parts = [f"Objective: {objective}"]
        if target:
            prompt_parts.append(f"Target asset: {target}")
        prompt_parts.append(
            "Work step by step using the tools you need, then produce your final answer "
            "as a JSON object with the keys: conclusion, confidence, observations, "
            "uncertainty, next_step, findings (and optionally delegate)."
        )
        messages.append({"role": "user", "content": "\n".join(prompt_parts)})

        for prior in prior_messages[-6:]:
            messages.append(
                {
                    "role": "user",
                    "content": f"[{prior.sender_role}] {prior.kind.value}: {prior.hypothesis}",
                }
            )

        run = AgentRun(task_id=task_id, role=self.role.role)
        tokens_used = 0
        tool_calls_used = 0
        rounds = 0
        seen_calls: dict[str, int] = {}
        transcript: list[ChatMessage] = []

        while True:
            elapsed = time.monotonic() - started
            exhausted = budget.exhausted(
                tokens_used=tokens_used,
                tool_calls=tool_calls_used,
                rounds=rounds,
                elapsed=elapsed,
            )
            if exhausted:
                run.status = "budget_exhausted"
                run.error = exhausted
                self._emit(
                    AgentMessage(
                        scan_id=scan_id,
                        task_id=task_id,
                        sender_role=self.role.role,
                        kind=MessageKind.BUDGET_EXHAUSTED,
                        hypothesis=exhausted,
                        disposition=Disposition.BLOCKED,
                        rationale=f"run stopped: {exhausted}",
                    )
                )
                break

            rounds += 1
            try:
                completion = await self._complete(messages, tools, definitions)
            except ProviderError as exc:
                run.status = "failed"
                run.error = exc.message
                self._emit(
                    AgentMessage(
                        scan_id=scan_id,
                        task_id=task_id,
                        sender_role=self.role.role,
                        kind=MessageKind.ERROR,
                        hypothesis=exc.message,
                        disposition=Disposition.BLOCKED,
                        rationale="the model provider returned an error",
                    )
                )
                break

            tokens_used += completion.total_tokens
            transcript.append(completion.message)

            if self.on_progress:
                self.on_progress(
                    {
                        "role": self.role.role,
                        "round": rounds,
                        "tokens_used": tokens_used,
                        "tool_calls_used": tool_calls_used,
                        "latency_ms": completion.latency_ms,
                    }
                )

            if not completion.message.tool_calls:
                conclusion = self._parse_conclusion(completion.message.content)
                run.conclusion = conclusion.get("conclusion", completion.message.content.strip()[:4000])
                run.confidence = _confidence(conclusion.get("confidence"))
                run.observations = list(conclusion.get("observations") or [])
                run.next_step = str(conclusion.get("next_step") or "")
                run.uncertainty = str(conclusion.get("uncertainty") or "")
                run.findings = list(conclusion.get("findings") or [])
                run.status = "succeeded"
                run.disposition = Disposition.DELEGATE if conclusion.get("delegate") else Disposition.COMPLETE
                if conclusion.get("delegate"):
                    run.next_step = json.dumps(conclusion["delegate"])
                break

            # --- execute the requested tools ----------------------------
            assistant_payload = completion.message.to_openai()
            messages.append(assistant_payload)

            for call in completion.message.tool_calls:
                if tool_calls_used >= budget.max_tool_calls:
                    messages.append(
                        {
                            "role": "user",
                            "content": "Tool call budget exhausted. Produce your final JSON answer now.",
                        }
                    )
                    break

                signature = f"{call.name}:{json.dumps(call.arguments, sort_keys=True, default=str)}"
                seen_calls[signature] = seen_calls.get(signature, 0) + 1
                if seen_calls[signature] > self.config.max_identical_calls:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                f"Tool '{call.name}' was already called with these exact arguments. "
                                "Change your approach or produce your final JSON answer."
                            ),
                        }
                    )
                    continue

                tool_calls_used += 1
                result = await self.gateway.execute(
                    tool_name=call.name,
                    arguments=call.arguments,
                    context=ctx,
                    call_id=call.id,
                )
                run.tool_calls.append(
                    {
                        "tool": call.name,
                        "arguments": call.arguments,
                        "ok": result.ok,
                        "error": result.error,
                        "duration_ms": result.duration_ms,
                        "output": str(result.output)[:4000],
                    }
                )
                if self.on_tool_call:
                    self.on_tool_call(
                        {
                            "scan_id": scan_id,
                            "task_id": task_id,
                            "agent_role": self.role.role,
                            "tool": call.name,
                            "call_id": call.id,
                            "status": "ok" if result.ok else "error",
                            "arguments": call.arguments,
                            "output": str(result.output)[:2000],
                            "error": result.error,
                            "duration_ms": result.duration_ms,
                            "at": time.time(),
                        }
                    )

                messages.append(
                    {
                        "role": "user",
                        "content": _format_tool_result(call, result),
                    }
                )

                self._emit(
                    AgentMessage(
                        scan_id=scan_id,
                        task_id=task_id,
                        sender_role=self.role.role,
                        kind=MessageKind.OBSERVATION,
                        target=call.name,
                        hypothesis=_summarise_tool_result(result),
                        observations=[f"{call.name} -> {'ok' if result.ok else 'error'}"],
                        confidence=Confidence.LOW,
                        evidence=[
                            EvidenceRef(
                                kind="tool_output",
                                reference=f"tool:{call.name}",
                                excerpt=str(result.output)[:1500],
                            )
                        ],
                        proposed_next_step="continue investigation",
                        rationale=f"called tool '{call.name}'",
                    )
                )

            if tool_calls_used >= budget.max_tool_calls:
                messages.append(
                    {
                        "role": "user",
                        "content": "Tool call budget exhausted. Produce your final JSON answer now.",
                    }
                )

        run.tokens_used = tokens_used
        run.tool_calls_used = tool_calls_used
        run.rounds = rounds
        run.duration_seconds = round(time.monotonic() - started, 3)
        if run.status == "succeeded" and not run.conclusion:
            run.status = "failed"
            run.error = run.error or "the agent produced no conclusion"
        return run

    # ------------------------------------------------------------------
    async def _complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        definitions: list[Any],
    ) -> Completion:
        native = await self._native_tools_enabled()
        completion = await self.provider.complete(
            messages,
            tools=definitions if native else (),
            role=self.role.role,
            temperature=self.config.temperature,
            max_tokens=self.provider.config.max_output_tokens,
            response_format="json_object" if self.config.structured_output and not tools else None,
        )
        if not native:
            completion.message = merge_native_and_compat(completion.message)
        return completion

    async def _native_tools_enabled(self) -> bool:
        cached = getattr(self.provider, "_native_tools", None)
        if cached is None:
            try:
                return await self.provider.supports_native_tools()
            except ProviderError:
                return False
        return bool(cached)

    def _parse_conclusion(self, content: str) -> dict[str, Any]:
        parsed = _parse_json_object(content)
        if not isinstance(parsed, dict):
            return {"conclusion": (content or "").strip()[:4000]}
        return parsed

    def _emit(self, message: AgentMessage) -> None:
        if self.on_message is None:
            return
        try:
            self.on_message(message)
        except Exception:  # pragma: no cover - persistence must not break the run
            log.exception("failed to persist an agent message")


def _format_tool_result(call: ToolCall, result: ToolResult) -> str:
    if result.ok:
        body = str(result.output)
        if len(body) > 12000:
            body = body[:12000] + "\n... [truncated]"
        return f"Tool '{call.name}' succeeded:\n{body}"
    return f"Tool '{call.name}' failed: {result.error}"


def _summarise_tool_result(result: ToolResult) -> str:
    if not result.ok:
        return f"{result.tool} failed: {result.error}"
    body = str(result.output)
    return f"{result.tool} returned {len(body)} bytes"


def _confidence(value: Any) -> Confidence:
    try:
        return Confidence(str(value).strip().lower())
    except (ValueError, AttributeError):
        return Confidence.LOW


def _parse_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    stripped = text.strip()
    candidates = [stripped]
    match = _JSON_BLOCK_RE.search(stripped)
    if match:
        candidates.append(match.group(0))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def parse_findings(payload: Any, *, role: str, task_id: str) -> list[CandidateFinding]:
    """Normalise the ``findings`` array of an agent conclusion."""
    if not isinstance(payload, list):
        return []
    findings: list[CandidateFinding] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            finding = CandidateFinding.from_dict(item)
        except TypeError:
            continue
        finding.proposed_by = role
        finding.task_id = task_id
        findings.append(finding)
    return findings
