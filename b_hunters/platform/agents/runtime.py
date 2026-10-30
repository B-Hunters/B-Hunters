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
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic_ai import Agent
from pydantic_ai.exceptions import RunCancelled, RunTimedOut, UsageLimitExceeded
from pydantic_ai.messages import TextPart
from pydantic_ai.usage import UsageLimits

from ..tools.gateway import ToolContext, ToolGateway, ToolResult
from .compat import build_compat_instruction, merge_native_and_compat
from .framework import (
    Conclusion,
    ProviderModel,
    build_tools,
    conclusion_from_text,
    normalise_conclusion,
)
from .provider import Completion, Provider, ProviderError, ToolCall
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
    #: How many rounds in a row may produce nothing new before the task
    #: ends.  Zero means the runtime never stops a role for that reason.
    max_empty_rounds: int = 3
    #: Temperature used for agent reasoning.
    temperature: float = 0.0
    #: Whether the model is asked to return structured JSON.
    structured_output: bool = True


def _wrap_up_message(*, rounds: int, tool_calls: int, tokens: int, budget: Budget) -> str | None:
    """What to tell the role before its budget runs out.

    A model gets one answer per round.  A role that is asked to record
    what it found and to conclude in the same round records it and ends
    the round without a conclusion - so the recording is asked for a few
    rounds before the end, and the conclusion in the last one.
    """
    if tool_calls >= budget.max_tool_calls:
        return "Tool call budget exhausted. Produce your final JSON answer now."
    if rounds >= budget.max_rounds - 1:
        return (
            "This is your last round. Do not call any tool. Summarise what you "
            "found and produce your final JSON answer now."
        )
    if rounds >= max(1, budget.max_rounds - 3):
        return (
            "You have few rounds left. If your role has a tool for recording what you found, record it now."
        )
    if tool_calls >= budget.max_tool_calls * 0.8:
        return (
            "You are close to your tool call budget. If your role has a tool "
            "for recording what you found, record it now."
        )
    if tokens >= budget.max_tokens * 0.8:
        # The tokens are what a reasoning model spends, so a role that is
        # cut off here loses everything it found.  It is told to stop
        # working and to answer.
        return (
            "You are close to your token budget. Do not call any tool any more. "
            "Summarise what you have found and produce your final JSON answer now."
        )
    return None


def _evidence_seen(tool_records: Sequence[dict[str, Any]], said: Collection[str] = ()) -> tuple[Any, ...]:
    """What the role has produced so far.

    The fingerprint is the number of distinct outputs, the number of URLs
    that appeared in them and the number of distinct things the role
    said.  A round that does not change it produced nothing the role did
    not already know: the *number* of calls is not part of it, because
    making the same call again is not learning anything, and neither is
    saying the same thing again.

    What the role *says* counts: a role that reports in prose without
    calling a tool has still produced something, and a round in which it
    said something new is not an empty round.
    """
    outputs = {str(record.get("output", "")) for record in tool_records}
    urls: set[str] = set()
    for record in tool_records:
        for match in re.finditer(r"https?://[^\s\"'<>]+", str(record.get("output", ""))):
            urls.add(match.group(0))
    return (len(outputs), len(urls), len(set(said)))


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
        if not ctx.permissions.capabilities and not ctx.permissions.tools:
            # A context that carries no permissions of its own takes the
            # role's: the role knows what it may do.
            ctx.permissions = self.role.permissions
        if not ctx.allowed_tools and self.role.tools:
            # The same for the tools: the role's own list is what the
            # role may use.
            ctx.allowed_tools = set(self.role.tools)
        ctx.budget = budget

        # The role is offered the tools it may use, and only those.  It
        # was offered every tool of the registry, so the gateway refused
        # the ones it may not have - and a model does not learn from a
        # refusal: it kept reaching for `record_verdict` and for the
        # network tools, spending the rounds it needed for its own work
        # on calls that could never succeed.
        definitions = self.gateway.registry.for_role(self.role.role, ctx.allowed_tools)
        tool_records: list[dict[str, Any]] = []
        tools = build_tools(
            definitions,
            ctx,
            self.gateway,
            records=tool_records,
            max_identical_calls=self.config.max_identical_calls,
        )

        system_prompt = role_prompt(self.role)
        if definitions and not (await self._native_tools_enabled()):
            system_prompt += "\n\n" + build_compat_instruction(definitions)

        prompt_parts = [f"Objective: {objective}"]
        if target:
            prompt_parts.append(f"Target asset: {target}")
        prompt_parts.append(
            "Work step by step using the tools you need, then give your final answer by "
            "calling the `final_result` tool with these keys: conclusion, confidence, "
            "observations, uncertainty, next_step, findings (and optionally delegate). "
            "Do not write the answer as text: the tool call is what carries it."
        )
        if "record_verdict" not in self.role.tools:
            # The model keeps reaching for `record_verdict` - it is the
            # obvious name for "say what you think of this finding" - and
            # every attempt is refused, because only the adjudicator (and
            # the optional verifier) may judge a finding.  Saying so
            # saves the rounds it spends on the refusals.
            prompt_parts.append(
                "You do not judge findings and you do not record verdicts: the "
                "adjudicator does that after you are done. Do not call "
                "`record_verdict`. Put everything you concluded into the "
                "`final_result` tool, in the `findings` list."
            )
        prompt = "\n".join(prompt_parts)
        if input_payload:
            prompt = (
                "Task context:\n" + json.dumps(input_payload, indent=2, default=str)[:20000] + "\n\n" + prompt
            )
        for prior in prior_messages[-6:]:
            prompt += f"\n\n[{prior.sender_role}] {prior.kind.value}: {prior.hypothesis}"

        run = AgentRun(task_id=task_id, role=self.role.role)
        tokens_used = 0
        tool_calls_used = 0
        rounds = 0
        empty_rounds = 0
        evidence_seen: Optional[tuple[Any, ...]] = None
        said_so_far: set[str] = set()
        texts_said: list[str] = []
        last_text = ""
        state = {"requests": 0, "rounds": 0, "tool_calls": 0, "tokens": 0}

        def _nudge(request_number: int) -> str | None:
            # The nudge counts the requests, not the rounds that were
            # finished: the budget limits the requests, so the "this is
            # your last round, conclude now" has to arrive with the last
            # request that is still allowed.  The number is the one the
            # adapter counts, so the two cannot drift apart.
            return _wrap_up_message(
                rounds=request_number,
                tool_calls=state["tool_calls"],
                tokens=state["tokens"],
                budget=budget,
            )

        model = ProviderModel(
            self.provider,
            role=self.role.role,
            temperature=self.config.temperature,
            max_output_tokens=self.provider.config.max_output_tokens,
            native_tools=await self._native_tools_enabled(),
            nudge=_nudge,
            # From the request that carries the "this is your last
            # round" instruction onwards, the role is offered no tools:
            # it has to answer there, and it cannot spend another round
            # and lose everything it found.
            function_tools_until=max(1, budget.max_rounds - 2),
        )
        limits = UsageLimits(
            # One request beyond the budget: the last one carries the
            # instruction to conclude, and a conclusion is a request too.
            request_limit=budget.max_rounds + 1,
            tool_calls_limit=budget.max_tool_calls,
            total_tokens_limit=budget.max_tokens,
        )

        agent = Agent(
            model,
            tools=tools,
            output_type=Conclusion,
            # A conclusion that does not fit the schema is worth a few
            # more attempts: it is the difference between a role that
            # reports and a role that is cut off.
            retries=3,
            system_prompt=system_prompt,
        )

        try:
            async with agent.iter(
                prompt,
                deps=ctx,
                usage_limits=limits,
                timeout=budget.max_wall_clock_seconds,
            ) as iteration:
                async for node in iteration:
                    # The last thing the model said in prose.  A model
                    # that answers with text instead of filling in the
                    # answer tool still knows what it found, and that
                    # text is read as its conclusion below.  The response
                    # is attached to the node that follows the request,
                    # so every node is looked at.
                    said = _node_text(node)
                    if said:
                        last_text = said
                        said_so_far.add(said)
                        texts_said.append(said)
                    if Agent.is_model_request_node(node):
                        rounds += 1
                        # The framework counts the requests itself, and
                        # its count is the one the budget limits.  Asking
                        # it keeps the nudge and the limit in step: the
                        # "this is your last round, conclude now" has to
                        # arrive with the last request that is still
                        # allowed.
                        state["requests"] = model.request_count + 1
                        state["tool_calls"] = len(tool_records)
                        state["tokens"] = model.total_tokens
                        if self.on_progress:
                            self.on_progress(
                                {
                                    "role": self.role.role,
                                    "round": rounds,
                                    "tokens_used": tokens_used,
                                    "tool_calls_used": tool_calls_used,
                                    "latency_ms": 0,
                                }
                            )
                    elif Agent.is_call_tools_node(node):
                        # The round is finished: the tools ran and the
                        # answers are in.  The nudge counts the rounds
                        # that are done, not the ones that are prepared.
                        state["rounds"] = rounds
                        # A round that found nothing new is a round the
                        # model spent without learning anything.  Three
                        # of them in a row mean the role has nothing
                        # left to look at, and the task ends with what
                        # it has rather than spending the rest of its
                        # budget asking the same question again.
                        seen = _evidence_seen(tool_records, said_so_far)
                        if evidence_seen is not None and seen == evidence_seen:
                            empty_rounds += 1
                        else:
                            empty_rounds = 0
                            evidence_seen = seen
                        if empty_rounds >= self.config.max_empty_rounds:
                            run.status = "no_new_evidence"
                            run.error = f"the role found nothing new in {empty_rounds} round(s) and stopped"
                            log.info(
                                "the role %s found nothing new in %s round(s)",
                                self.role.role,
                                empty_rounds,
                            )
                            # The role stopped for want of something to
                            # look at, not because it found nothing: what
                            # it worked out is kept.  A role that already
                            # concluded - in prose, because the model did
                            # not use the answer tool - has done its
                            # work, and the stop does not undo it.
                            if not run.conclusion:
                                for text in reversed(texts_said):
                                    parsed = _structured_conclusion(text)
                                    if not parsed:
                                        continue
                                    run.conclusion = parsed["conclusion"]
                                    run.confidence = _confidence(parsed["confidence"])
                                    run.observations = list(parsed["observations"])
                                    run.next_step = str(parsed["next_step"] or "")
                                    run.uncertainty = str(parsed["uncertainty"] or "")
                                    run.findings = list(parsed["findings"])
                                    run.status = "succeeded"
                                    run.error = ""
                                    break
                                if run.status != "succeeded" and last_text:
                                    run.conclusion = last_text
                            break
                    elif Agent.is_end_node(node):
                        conclusion = normalise_conclusion(node.data.output)
                        run.conclusion = conclusion["conclusion"]
                        run.confidence = _confidence(conclusion["confidence"])
                        run.observations = list(conclusion["observations"])
                        run.next_step = str(conclusion["next_step"] or "")
                        run.uncertainty = str(conclusion["uncertainty"] or "")
                        run.findings = list(conclusion["findings"])
                        run.status = "succeeded"
                        run.disposition = (
                            Disposition.DELEGATE if conclusion["delegate"] else Disposition.COMPLETE
                        )
                        if conclusion["delegate"]:
                            run.next_step = json.dumps(conclusion["delegate"])
                        self._emit(
                            AgentMessage(
                                scan_id=scan_id,
                                task_id=task_id,
                                sender_role=self.role.role,
                                kind=MessageKind.TASK_RESULT,
                                target=target,
                                hypothesis=run.conclusion,
                                observations=run.observations,
                                evidence=_evidence_refs(run.findings),
                                proposed_next_step=run.next_step,
                                uncertainty=run.uncertainty,
                                confidence=run.confidence,
                                disposition=run.disposition,
                                rationale=(
                                    f"the role finished after {rounds} round(s) and "
                                    f"{len(tool_records)} tool call(s), with "
                                    f"{len(run.findings)} proposed finding(s)"
                                ),
                            )
                        )
        except UsageLimitExceeded as exc:
            run.status = "budget_exhausted"
            run.error = (
                "the role ran out of rounds before it concluded: "
                f"{budget.max_rounds} round(s) were not enough"
            )
            log.info("the budget of %s ran out: %s", self.role.role, exc)
            self._emit(
                AgentMessage(
                    scan_id=scan_id,
                    task_id=task_id,
                    sender_role=self.role.role,
                    kind=MessageKind.BUDGET_EXHAUSTED,
                    hypothesis=str(exc),
                    disposition=Disposition.BLOCKED,
                    rationale=f"run stopped: {exc}",
                )
            )
        except RunTimedOut as exc:
            # The wall clock of the task ran out.  It is a stop reason of
            # its own: a role that was cut off is not a role that failed
            # and certainly not one that succeeded.
            run.status = "wall_clock"
            run.error = "the task ran out of its wall clock"
            log.info("the wall clock of %s ran out: %s", self.role.role, exc)
            self._emit(
                AgentMessage(
                    scan_id=scan_id,
                    task_id=task_id,
                    sender_role=self.role.role,
                    kind=MessageKind.BUDGET_EXHAUSTED,
                    hypothesis=str(exc),
                    disposition=Disposition.BLOCKED,
                    rationale="run stopped: the wall clock of the task ran out",
                )
            )
        except RunCancelled as exc:
            run.status = "cancelled"
            run.error = "the task was cancelled"
            log.info("the run of %s was cancelled: %s", self.role.role, exc)
            self._emit(
                AgentMessage(
                    scan_id=scan_id,
                    task_id=task_id,
                    sender_role=self.role.role,
                    kind=MessageKind.ERROR,
                    hypothesis=str(exc),
                    disposition=Disposition.BLOCKED,
                    rationale="run stopped: the run was cancelled",
                )
            )
        except Exception as exc:
            run.status = "failed"
            run.error = str(exc)
            self._emit(
                AgentMessage(
                    scan_id=scan_id,
                    task_id=task_id,
                    sender_role=self.role.role,
                    kind=MessageKind.ERROR,
                    hypothesis=str(exc),
                    disposition=Disposition.BLOCKED,
                    rationale="the run ended with an error",
                )
            )

        # The tool calls the run made, with what each of them returned.
        for record in tool_records:
            tool_calls_used += 1
            run.tool_calls.append(record)
            if self.on_tool_call:
                self.on_tool_call(
                    {
                        "scan_id": scan_id,
                        "task_id": task_id,
                        "agent_role": self.role.role,
                        "tool": record.get("tool", ""),
                        "call_id": record.get("call_id", ""),
                        "status": "ok" if record.get("ok") else "error",
                        "arguments": record.get("arguments", {}),
                        "output": str(record.get("output", ""))[:2000],
                        "error": record.get("error", ""),
                        "duration_ms": record.get("duration_ms", 0),
                        "at": time.time(),
                    }
                )
            self._emit(
                AgentMessage(
                    scan_id=scan_id,
                    task_id=task_id,
                    sender_role=self.role.role,
                    kind=MessageKind.OBSERVATION,
                    target=str(record.get("tool", "")),
                    hypothesis=str(record.get("output", ""))[:1500],
                    observations=[f"{record.get('tool', '')} -> {'ok' if record.get('ok') else 'error'}"],
                    confidence=Confidence.LOW,
                    evidence=[
                        EvidenceRef(
                            kind="tool_output",
                            reference=f"tool:{record.get('tool', '')}",
                            excerpt=str(record.get("output", ""))[:1500],
                        )
                    ],
                    proposed_next_step="continue investigation",
                    rationale=f"called tool '{record.get('tool', '')}'",
                )
            )

        run.tokens_used = model.total_tokens
        run.tool_calls_used = tool_calls_used
        run.rounds = rounds
        run.duration_seconds = round(time.monotonic() - started, 3)
        if not run.conclusion and last_text.strip() and _answer_shaped_failure(run):
            # The role answered with prose instead of filling in the
            # answer tool.  Its answer is read as its conclusion: the
            # work it did is not thrown away because the answer came in
            # the wrong shape.  A run that failed for another reason -
            # a provider that is down, a tool that hung - keeps its
            # failure: the prose before it is not the role's conclusion.
            conclusion = normalise_conclusion(conclusion_from_text(last_text))
            if conclusion["conclusion"]:
                run.conclusion = conclusion["conclusion"]
                run.confidence = _confidence(conclusion["confidence"])
                run.observations = list(conclusion["observations"])
                run.next_step = str(conclusion["next_step"] or "")
                run.uncertainty = str(conclusion["uncertainty"] or "")
                run.findings = list(conclusion["findings"])
                run.status = "succeeded"
                run.error = ""
                self._emit(
                    AgentMessage(
                        scan_id=scan_id,
                        task_id=task_id,
                        sender_role=self.role.role,
                        kind=MessageKind.TASK_RESULT,
                        target=target,
                        hypothesis=run.conclusion,
                        observations=run.observations,
                        evidence=_evidence_refs(run.findings),
                        proposed_next_step=run.next_step,
                        uncertainty=run.uncertainty,
                        confidence=run.confidence,
                        disposition=Disposition.COMPLETE,
                        rationale=(
                            "the role answered in prose; the answer was read "
                            f"as its conclusion after {rounds} round(s)"
                        ),
                    )
                )
        if run.status == "succeeded" and not run.conclusion:
            run.status = "failed"
            run.error = run.error or "the agent produced no conclusion"
        if run.status != "succeeded" and not run.findings:
            # A role that was cut off keeps what it worked out.  The
            # findings of a role live in its final answer, so a role
            # that ran out of time would lose everything it had found.
            # What it last said is read as its answer: the findings it
            # names are kept, and they are judged like any other.
            _salvage(run, last_text)
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


#: The failures that mean "the role did not deliver its answer", as
#: opposed to "the run broke".  Only the first kind may be answered with
#: the prose the model wrote.
ANSWER_SHAPED_FAILURES = (
    "no conclusion",
    "output retries",
    "ran out of rounds",
)


def _answer_shaped_failure(run: Any) -> bool:
    """Did the run fail because the answer never arrived?

    A provider that is down, a tool that hung and a refusal are
    failures of the run, not of the answer: the prose the model wrote
    before them is not its conclusion.
    """
    if run.status == "succeeded":
        return True
    error = str(run.error or "")
    return any(marker in error for marker in ANSWER_SHAPED_FAILURES)


def _structured_conclusion(text: str) -> dict[str, Any] | None:
    """The conclusion a model wrote as a structured answer.

    The prose fallback reads any sentence as a conclusion, which is the
    right thing when a role answers once and finishes.  It is the wrong
    thing when a role keeps saying the same sentence: then the sentence
    is not an answer, it is a repetition.  Only an answer that carries
    the fields of a conclusion counts.
    """
    body = (text or "").strip()
    start = body.find("{")
    end = body.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        payload = json.loads(body[start : end + 1])
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or "conclusion" not in payload:
        return None
    parsed = normalise_conclusion(conclusion_from_text(body))
    return parsed if parsed["conclusion"] else None


def _node_text(node: Any) -> str:
    """The prose a model wrote in one request.

    The framework keeps the answer of a request in the node; the text
    parts of it are what the model said in words.
    """
    response = getattr(node, "model_response", None)
    if response is None:
        return ""
    parts = getattr(response, "parts", None) or ()
    texts = [part.content for part in parts if isinstance(part, TextPart)]
    return "\n".join(text for text in texts if text).strip()


def _evidence_refs(findings: Sequence[Any]) -> list[EvidenceRef]:
    """The evidence a role attached to the findings it proposed.

    The model writes the evidence in whatever shape it likes, so every
    entry is read defensively: a finding that names a source, a snippet
    of what it saw and where it saw it.
    """
    refs: list[EvidenceRef] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or "")
        for item in finding.get("evidence") or []:
            if isinstance(item, dict):
                refs.append(
                    EvidenceRef(
                        kind=str(item.get("kind") or "note"),
                        reference=str(item.get("reference") or title),
                        excerpt=str(item.get("excerpt") or ""),
                    )
                )
            elif isinstance(item, str):
                refs.append(EvidenceRef(kind="note", reference=title, excerpt=item))
    return refs


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


def _salvage(run: Any, last_text: str) -> None:
    """Keep what a role that was cut off had worked out.

    The findings of a role travel in its final answer, and a role that
    ran out of time never gives one.  The last thing it said is read
    as its answer, so that the findings it names are kept and judged
    like any other.  The run keeps its status: it was cut off, and it
    says so.
    """
    text = (last_text or "").strip()
    if not text:
        return
    if run.findings:
        # The role recorded something already; that is what it found.
        return
    conclusion = normalise_conclusion(conclusion_from_text(text))
    if not conclusion["findings"]:
        return
    run.findings = list(conclusion["findings"])
    if not run.conclusion:
        run.conclusion = conclusion["conclusion"] or text[:4000]
    if not run.observations:
        run.observations = list(conclusion["observations"])
    if not run.uncertainty:
        run.uncertainty = str(conclusion["uncertainty"] or "")


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
