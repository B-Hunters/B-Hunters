"""Structured contracts for the agent collaboration protocol.

Agents never exchange free-form chat.  They exchange
:class:`AgentMessage` records with a fixed shape so that the orchestrator
can reason about dependencies, budget consumption and disagreement, and so
that the audit trail stays reviewable.

What is stored is *conclusions, evidence, tool invocations and rationale* -
never hidden model chain-of-thought.  The ``rationale`` field is a short
justification the agent deliberately produced as part of its output schema.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class MessageKind(str, Enum):
    """The kind of collaboration event."""

    TASK_ASSIGNMENT = "task_assignment"
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    EVIDENCE_REQUEST = "evidence_request"
    CHALLENGE = "challenge"
    REBUTTAL = "rebuttal"
    VERIFICATION = "verification"
    FINDING_PROPOSAL = "finding_proposal"
    FINDING_REJECTION = "finding_rejection"
    TASK_RESULT = "task_result"
    DELEGATION = "delegation"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ERROR = "error"
    NOTE = "note"


class Disposition(str, Enum):
    """What the sender concludes from a message."""

    CONTINUE = "continue"
    ESCALATE = "escalate"
    DELEGATE = "delegate"
    COMPLETE = "complete"
    REJECT = "reject"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    BLOCKED = "blocked"


class Confidence(str, Enum):
    """Coarse confidence band attached to a conclusion."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


@dataclass
class Budget:
    """Resource budget for a task or agent run."""

    max_tokens: int = 100000
    max_tool_calls: int = 40
    max_rounds: int = 8
    max_wall_clock_seconds: int = 600
    max_tasks: int = 10

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Budget:
        data = data or {}
        return cls(
            max_tokens=int(data.get("max_tokens", 100000)),
            max_tool_calls=int(data.get("max_tool_calls", 40)),
            max_rounds=int(data.get("max_rounds", 8)),
            max_wall_clock_seconds=int(data.get("max_wall_clock_seconds", 600)),
            max_tasks=int(data.get("max_tasks", 10)),
        )

    def exhausted(self, *, tokens_used: int, tool_calls: int, rounds: int, elapsed: float) -> Optional[str]:
        if tokens_used >= self.max_tokens:
            return "token budget exhausted"
        if tool_calls >= self.max_tool_calls:
            return "tool call budget exhausted"
        if rounds >= self.max_rounds:
            return "round budget exhausted"
        if elapsed >= self.max_wall_clock_seconds:
            return "wall clock budget exhausted"
        return None


@dataclass
class EvidenceRef:
    """A pointer to a piece of evidence backing a claim."""

    kind: str
    reference: str
    excerpt: str = ""
    asset: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentMessage:
    """A structured message exchanged between agents."""

    scan_id: str
    task_id: str
    sender_role: str
    sender_instance: str = ""
    kind: MessageKind = MessageKind.OBSERVATION
    #: The asset the message concerns (URL, host, file).
    target: str = ""
    #: The question or claim.
    hypothesis: str = ""
    observations: list[str] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    uncertainty: str = ""
    proposed_next_step: str = ""
    rationale: str = ""
    budget: Budget = field(default_factory=Budget)
    disposition: Disposition = Disposition.CONTINUE
    recipients: list[str] = field(default_factory=list)
    finding_id: str = ""
    severity: str = ""
    vuln_class: str = ""
    created_at: float = field(default_factory=time.time)
    message_id: str = ""
    seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["confidence"] = self.confidence.value
        data["disposition"] = self.disposition.value
        data["budget"] = self.budget.to_dict()
        data["evidence"] = [e.to_dict() for e in self.evidence]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentMessage:
        evidence = [EvidenceRef(**e) for e in data.get("evidence", []) if isinstance(e, dict)]
        return cls(
            scan_id=data.get("scan_id", ""),
            task_id=data.get("task_id", ""),
            sender_role=data.get("sender_role", ""),
            sender_instance=data.get("sender_instance", ""),
            kind=MessageKind(data.get("kind", MessageKind.OBSERVATION.value)),
            target=data.get("target", ""),
            hypothesis=data.get("hypothesis", ""),
            observations=list(data.get("observations", [])),
            evidence=evidence,
            confidence=Confidence(data.get("confidence", Confidence.LOW.value)),
            uncertainty=data.get("uncertainty", ""),
            proposed_next_step=data.get("proposed_next_step", ""),
            rationale=data.get("rationale", ""),
            budget=Budget.from_dict(data.get("budget")),
            disposition=Disposition(data.get("disposition", Disposition.CONTINUE.value)),
            recipients=list(data.get("recipients", [])),
            finding_id=data.get("finding_id", ""),
            severity=data.get("severity", ""),
            vuln_class=data.get("vuln_class", ""),
            created_at=data.get("created_at", time.time()),
            message_id=data.get("message_id", ""),
            seq=data.get("seq", 0),
        )

    def summary(self) -> str:
        """One-line human readable rendering used by the dashboard."""
        head = f"[{self.sender_role}] {self.kind.value}"
        if self.target:
            head += f" {self.target}"
        if self.hypothesis:
            head += f": {self.hypothesis[:160]}"
        return head


@dataclass
class AgentTask:
    """A unit of work handed to an agent."""

    task_id: str
    scan_id: str
    role: str
    title: str
    objective: str = ""
    target: str = ""
    depends_on: list[str] = field(default_factory=list)
    budget: Budget = field(default_factory=Budget)
    input: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    priority: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["budget"] = self.budget.to_dict()
        return data


#: Why a run stopped, and the status each reason comes from.  The
#: reasons are the ones the report uses: a run that finished, a run
#: that ran out of its budget, a run that ran out of its wall clock, a
#: run that was cancelled and a run that failed.
STOP_REASONS = {
    "succeeded": "completed",
    "budget_exhausted": "budget_exhausted",
    "wall_clock": "wall_clock",
    "cancelled": "cancelled",
    "failed": "failed",
}


def stop_reason_for(status: str) -> str:
    """Why a run with this status stopped.

    The status decides the reason and nothing else does: an empty
    error string says nothing, and a run without a reason is a failure.
    """
    return STOP_REASONS.get(str(status or ""), "failed")


@dataclass
class AgentRun:
    """The result of running one agent task."""

    task_id: str
    role: str
    status: str = "succeeded"
    conclusion: str = ""
    confidence: Confidence = Confidence.LOW
    findings: list[dict[str, Any]] = field(default_factory=list)
    messages: list[AgentMessage] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tokens_used: int = 0
    tool_calls_used: int = 0
    rounds: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    next_step: str = ""
    disposition: Disposition = Disposition.COMPLETE

    @property
    def stop_reason(self) -> str:
        """Why the run stopped.

        The reason comes from the status of the run and from nothing
        else: an empty error string is not a reason, and a run that
        stopped without one is never reported as completed.
        """
        return stop_reason_for(self.status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "role": self.role,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "conclusion": self.conclusion,
            "confidence": self.confidence.value,
            "findings": self.findings,
            "messages": [m.to_dict() for m in self.messages],
            "tool_calls": self.tool_calls,
            "tokens_used": self.tokens_used,
            "tool_calls_used": self.tool_calls_used,
            "rounds": self.rounds,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "next_step": self.next_step,
            "disposition": self.disposition.value,
        }


@dataclass
class CandidateFinding:
    """A finding proposed by an agent, before verification."""

    title: str
    vuln_class: str
    severity: str = "info"
    host: str = ""
    path: str = ""
    parameter: str = ""
    cwe: str = ""
    affected_url: str = ""
    summary: str = ""
    confidence: float = 0.5
    remediation: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    extra_key: str = ""
    proposed_by: str = ""
    task_id: str = ""
    verification_status: str = "unverified"
    verification_notes: str = ""
    false_positive_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CandidateFinding:
        allowed = set(cls.__dataclass_fields__)
        fields = {k: v for k, v in data.items() if k in allowed}
        # The model writes the confidence as a word often enough - "high",
        # "medium" - and the platform keeps a number.  A word means the
        # model was unsure of the scale, not that the finding is worth
        # more than the scale allows.
        raw = fields.get("confidence", 0.5)
        try:
            fields["confidence"] = float(raw)
        except (TypeError, ValueError):
            fields["confidence"] = {
                "critical": 1.0,
                "high": 0.9,
                "medium": 0.6,
                "low": 0.3,
                "info": 0.1,
            }.get(str(raw).strip().lower(), 0.5)
        return cls(**fields)


def summarise_messages(messages: Sequence[AgentMessage], limit: int = 20) -> list[dict[str, Any]]:
    """Render messages for the dashboard."""
    return [
        {
            "message_id": m.message_id,
            "seq": m.seq,
            "at": m.created_at,
            "kind": m.kind.value,
            "sender_role": m.sender_role,
            "target": m.target,
            "hypothesis": m.hypothesis,
            "confidence": m.confidence.value,
            "disposition": m.disposition.value,
            "summary": m.summary(),
            "evidence_count": len(m.evidence),
            "observations": m.observations[:5],
            "uncertainty": m.uncertainty,
            "proposed_next_step": m.proposed_next_step,
            "rationale": m.rationale,
        }
        for m in list(messages)[-limit:]
    ]
