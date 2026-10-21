"""The agent collaboration protocol.

Collaboration is structured, not conversational.  Agents publish
:class:`~b_hunters.platform.agents.schemas.AgentMessage` records; the
orchestrator reads them to decide whether more investigation is
justified.

Three properties matter:

* **Bounded rounds** - a disagreement is escalated at most
  ``max_challenge_rounds`` times before it is settled as inconclusive.
* **No circular delegation** - delegation is only permitted to a role that
  is not already in the current delegation chain, and a task that has
  already been asked the same question is not re-created.
* **Evidence over votes** - a challenge is answered with evidence, and the
  orchestrator never treats agreement between agents as proof.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .schemas import AgentMessage, Confidence, Disposition, EvidenceRef, MessageKind

log = logging.getLogger(__name__)

#: Message kinds that constitute a challenge in the disagreement workflow.
CHALLENGE_KINDS = frozenset({MessageKind.CHALLENGE, MessageKind.EVIDENCE_REQUEST})
#: Message kinds that answer a challenge.
ANSWER_KINDS = frozenset(
    {MessageKind.REBUTTAL, MessageKind.OBSERVATION, MessageKind.VERIFICATION, MessageKind.FINDING_PROPOSAL}
)


def question_key(target: str, hypothesis: str) -> str:
    """Stable identity for the question a message asks.

    Two messages asking the same question about the same target share a key,
    which is what lets the orchestrator detect repeated arguments.
    """
    material = f"{(target or '').strip().lower()}|{(hypothesis or '').strip().lower()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


@dataclass
class Disagreement:
    """An open disagreement between agents."""

    key: str
    target: str
    hypothesis: str
    opened_by: str
    opened_at: float = field(default_factory=time.time)
    rounds: int = 0
    challengers: list[str] = field(default_factory=list)
    responders: list[str] = field(default_factory=list)
    resolved: bool = False
    resolution: str = ""
    resolution_status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "target": self.target,
            "hypothesis": self.hypothesis,
            "opened_by": self.opened_by,
            "opened_at": self.opened_at,
            "rounds": self.rounds,
            "challengers": list(self.challengers),
            "responders": list(self.responders),
            "resolved": self.resolved,
            "resolution": self.resolution,
            "resolution_status": self.resolution_status,
        }


@dataclass
class CollaborationState:
    """Tracks open questions, disagreements and the delegation graph."""

    max_challenge_rounds: int = 2
    open_disagreements: dict[str, Disagreement] = field(default_factory=dict)
    asked_questions: dict[str, int] = field(default_factory=dict)
    delegation_edges: list[tuple[str, str]] = field(default_factory=list)
    delegation_depth: int = 0
    rounds_used: int = 0
    max_rounds: int = 6
    #: A repeated question beyond this count is treated as a loop.
    max_repeats: int = 2

    # ------------------------------------------------------------------
    def note_message(self, message: AgentMessage) -> None:
        """Update the state from a newly published message."""
        self.rounds_used += 1
        if message.kind in (MessageKind.HYPOTHESIS, MessageKind.CHALLENGE, MessageKind.EVIDENCE_REQUEST):
            key = question_key(message.target, message.hypothesis)
            self.asked_questions[key] = self.asked_questions.get(key, 0) + 1

        if message.kind in CHALLENGE_KINDS:
            key = question_key(message.target, message.hypothesis)
            disagreement = self.open_disagreements.get(key)
            if disagreement is None:
                disagreement = Disagreement(
                    key=key,
                    target=message.target,
                    hypothesis=message.hypothesis,
                    opened_by=message.sender_role,
                )
                self.open_disagreements[key] = disagreement
            disagreement.rounds += 1
            if message.sender_role not in disagreement.challengers:
                disagreement.challengers.append(message.sender_role)
        elif message.kind in ANSWER_KINDS:
            key = question_key(message.target, message.hypothesis)
            disagreement = self.open_disagreements.get(key)
            if disagreement is not None and message.sender_role not in disagreement.responders:
                disagreement.responders.append(message.sender_role)

    # ------------------------------------------------------------------
    def is_repeated(self, target: str, hypothesis: str) -> bool:
        """Has this exact question already been asked too often?"""
        key = question_key(target, hypothesis)
        return self.asked_questions.get(key, 0) >= self.max_repeats

    def can_delegate(self, from_role: str, to_role: str, chain: Sequence[str]) -> bool:
        """Prevent circular delegation."""
        if to_role == from_role:
            return False
        if to_role in chain:
            return False
        if self.delegation_depth >= 2:
            return False
        return True

    def record_delegation(self, from_role: str, to_role: str) -> None:
        self.delegation_edges.append((from_role, to_role))
        self.delegation_depth += 1

    def reset_delegation_depth(self) -> None:
        self.delegation_depth = 0

    # ------------------------------------------------------------------
    def settle(self, key: str, *, resolution: str, status: str) -> None:
        disagreement = self.open_disagreements.get(key)
        if disagreement is None:
            return
        disagreement.resolved = True
        disagreement.resolution = resolution
        disagreement.resolution_status = status

    def settle_stale(self) -> list[Disagreement]:
        """Close disagreements that exceeded their challenge budget."""
        settled = []
        for disagreement in list(self.open_disagreements.values()):
            if disagreement.resolved:
                continue
            if disagreement.rounds > self.max_challenge_rounds:
                disagreement.resolved = True
                disagreement.resolution_status = "inconclusive"
                disagreement.resolution = (
                    "the disagreement was not settled within the challenge budget; "
                    "the finding stays unverified"
                )
                settled.append(disagreement)
        return settled

    def budget_exhausted(self) -> bool:
        return self.rounds_used >= self.max_rounds

    def summary(self) -> dict[str, Any]:
        return {
            "rounds_used": self.rounds_used,
            "max_rounds": self.max_rounds,
            "asked_questions": len(self.asked_questions),
            "open_disagreements": [d.to_dict() for d in self.open_disagreements.values() if not d.resolved],
            "resolved_disagreements": [d.to_dict() for d in self.open_disagreements.values() if d.resolved],
            "delegation_edges": [list(edge) for edge in self.delegation_edges],
            "delegation_depth": self.delegation_depth,
        }


def build_evidence_request(
    *,
    scan_id: str,
    task_id: str,
    sender_role: str,
    recipient_role: str,
    target: str,
    question: str,
    context: str = "",
) -> AgentMessage:
    """Build a structured request for more evidence."""
    return AgentMessage(
        scan_id=scan_id,
        task_id=task_id,
        sender_role=sender_role,
        kind=MessageKind.EVIDENCE_REQUEST,
        target=target,
        hypothesis=question,
        observations=[context] if context else [],
        proposed_next_step=f"{recipient_role} should gather evidence for: {question}",
        disposition=Disposition.NEEDS_MORE_EVIDENCE,
        recipients=[recipient_role],
        confidence=Confidence.LOW,
    )


def build_challenge(
    *,
    scan_id: str,
    task_id: str,
    sender_role: str,
    recipient_role: str,
    target: str,
    claim: str,
    reason: str,
    evidence: Iterable[Any] = (),
) -> AgentMessage:
    """Build a structured challenge to a peer's claim."""
    refs = []
    for item in evidence:
        if isinstance(item, EvidenceRef):
            refs.append(item)
        elif isinstance(item, dict):
            refs.append(
                EvidenceRef(
                    kind=item.get("kind", "note"),
                    reference=item.get("reference", ""),
                    excerpt=item.get("excerpt", ""),
                )
            )
    return AgentMessage(
        scan_id=scan_id,
        task_id=task_id,
        sender_role=sender_role,
        kind=MessageKind.CHALLENGE,
        target=target,
        hypothesis=claim,
        observations=[reason] if reason else [],
        evidence=refs,
        proposed_next_step=f"{recipient_role} should confirm or refute: {claim}",
        disposition=Disposition.ESCALATE,
        recipients=[recipient_role],
        confidence=Confidence.MEDIUM,
    )


def build_rebuttal(
    *,
    scan_id: str,
    task_id: str,
    sender_role: str,
    recipient_role: str,
    target: str,
    claim: str,
    explanation: str,
    evidence: Iterable[Any] = (),
    confidence: Confidence = Confidence.MEDIUM,
) -> AgentMessage:
    """Build a structured rebuttal with its supporting evidence."""
    refs = []
    for item in evidence:
        if isinstance(item, EvidenceRef):
            refs.append(item)
        elif isinstance(item, dict):
            refs.append(
                EvidenceRef(
                    kind=item.get("kind", "note"),
                    reference=item.get("reference", ""),
                    excerpt=item.get("excerpt", ""),
                )
            )
    return AgentMessage(
        scan_id=scan_id,
        task_id=task_id,
        sender_role=sender_role,
        kind=MessageKind.REBUTTAL,
        target=target,
        hypothesis=claim,
        observations=[explanation] if explanation else [],
        evidence=refs,
        proposed_next_step="review the evidence and settle the disagreement",
        disposition=Disposition.CONTINUE,
        recipients=[recipient_role],
        confidence=confidence,
    )
