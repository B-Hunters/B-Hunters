"""Benchmark execution and scoring.

The runner drives the benchmark laboratory, executes each test case against
the running application, and compares what the platform reported against
what the manifest expected.

The outcome vocabulary is deliberately explicit:

``true_positive``
    The vulnerability was expected and the platform reported it.
``false_positive``
    The vulnerability was not expected (a hygiene case) and the platform
    reported it anyway.
``false_negative``
    The vulnerability was expected and the platform did not report it.
``not_applicable``
    The application does not contain this vulnerability class, so it is not
    counted against the platform.
``inconclusive``
    The probe could not be executed, so no conclusion can be drawn.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

OUTCOME_TRUE_POSITIVE = "true_positive"
OUTCOME_FALSE_POSITIVE = "false_positive"
OUTCOME_FALSE_NEGATIVE = "false_negative"
OUTCOME_NOT_APPLICABLE = "not_applicable"
OUTCOME_INCONCLUSIVE = "inconclusive"

#: Outcomes that count towards precision/recall.
COUNTED_OUTCOMES = (OUTCOME_TRUE_POSITIVE, OUTCOME_FALSE_POSITIVE, OUTCOME_FALSE_NEGATIVE)


def stable_vulnerability_id(application: str, vuln_class: str, location: str) -> str:
    """A stable identity for a vulnerability, used to deduplicate findings."""
    material = f"{application}|{vuln_class}|{location}".lower()
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


@dataclass
class TestResult:
    """The outcome of one test case."""

    test_id: str
    application: str
    vuln_class: str
    outcome: str
    expected: bool = False
    detected: bool = False
    severity: str = ""
    expected_severity: str = ""
    finding_ids: list[str] = field(default_factory=list)
    matched_finding_id: str = ""
    evidence: list[str] = field(default_factory=list)
    notes: str = ""
    duration_ms: int = 0
    detection_source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "application": self.application,
            "vuln_class": self.vuln_class,
            "outcome": self.outcome,
            "expected": self.expected,
            "detected": self.detected,
            "severity": self.severity,
            "expected_severity": self.expected_severity,
            "finding_ids": list(self.finding_ids),
            "matched_finding_id": self.matched_finding_id,
            "evidence": list(self.evidence),
            "notes": self.notes,
            "duration_ms": self.duration_ms,
            "detection_source": self.detection_source,
        }


@dataclass
class BenchmarkScore:
    """The aggregate score of one benchmark run."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    not_applicable: int = 0
    inconclusive: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return round(self.true_positives / denominator, 4) if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return round(self.true_positives / denominator, 4) if denominator else 0.0

    @property
    def f1(self) -> float:
        precision, recall = self.precision, self.recall
        return round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "not_applicable": self.not_applicable,
            "inconclusive": self.inconclusive,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "total": self.true_positives
            + self.false_positives
            + self.false_negatives
            + self.not_applicable
            + self.inconclusive,
        }


def score_results(results: Sequence[TestResult]) -> BenchmarkScore:
    """Aggregate the per-test outcomes into a score."""
    score = BenchmarkScore()
    for result in results:
        if result.outcome == OUTCOME_TRUE_POSITIVE:
            score.true_positives += 1
        elif result.outcome == OUTCOME_FALSE_POSITIVE:
            score.false_positives += 1
        elif result.outcome == OUTCOME_FALSE_NEGATIVE:
            score.false_negatives += 1
        elif result.outcome == OUTCOME_NOT_APPLICABLE:
            score.not_applicable += 1
        elif result.outcome == OUTCOME_INCONCLUSIVE:
            score.inconclusive += 1
    return score


def detection_rate_by_class(results: Sequence[TestResult]) -> dict[str, dict[str, Any]]:
    """Detection rate per vulnerability class."""
    buckets: dict[str, list[TestResult]] = {}
    for result in results:
        buckets.setdefault(result.vuln_class, []).append(result)
    output: dict[str, dict[str, Any]] = {}
    for vuln_class, items in sorted(buckets.items()):
        expected = [item for item in items if item.outcome in COUNTED_OUTCOMES]
        true_positives = sum(1 for item in items if item.outcome == OUTCOME_TRUE_POSITIVE)
        detected = sum(1 for item in items if item.detected)
        output[vuln_class] = {
            "total": len(items),
            "expected": len(expected),
            "detected": detected,
            "true_positives": true_positives,
            "false_positives": sum(1 for item in items if item.outcome == OUTCOME_FALSE_POSITIVE),
            "false_negatives": sum(1 for item in items if item.outcome == OUTCOME_FALSE_NEGATIVE),
            "not_applicable": sum(1 for item in items if item.outcome == OUTCOME_NOT_APPLICABLE),
            "detection_rate": round(detected / len(expected), 4) if expected else None,
        }
    return output


def detection_rate_by_application(results: Sequence[TestResult]) -> dict[str, dict[str, Any]]:
    """Detection rate per application."""
    buckets: dict[str, list[TestResult]] = {}
    for result in results:
        buckets.setdefault(result.application, []).append(result)
    output: dict[str, dict[str, Any]] = {}
    for application, items in sorted(buckets.items()):
        expected = [item for item in items if item.outcome in COUNTED_OUTCOMES]
        detected = sum(1 for item in items if item.detected)
        output[application] = {
            "total": len(items),
            "expected": len(expected),
            "detected": detected,
            "true_positives": sum(1 for item in items if item.outcome == OUTCOME_TRUE_POSITIVE),
            "false_positives": sum(1 for item in items if item.outcome == OUTCOME_FALSE_POSITIVE),
            "false_negatives": sum(1 for item in items if item.outcome == OUTCOME_FALSE_NEGATIVE),
            "not_applicable": sum(1 for item in items if item.outcome == OUTCOME_NOT_APPLICABLE),
            "detection_rate": round(detected / len(expected), 4) if expected else None,
        }
    return output


def duplicate_rate(results: Sequence[TestResult]) -> float:
    """The share of matched findings that more than one detector reported.

    A finding that two tools reported independently is a duplicate
    detection.  Counting the *extra* findings that satisfied a test case
    would instead penalise a single strong finding that happens to cover
    more than one expectation, which is not what "duplicate" means.
    """
    total = 0
    duplicates = 0
    for result in results:
        for _finding_id in result.finding_ids:
            total += 1
            if result.detection_source and "," in result.detection_source:
                duplicates += 1
    if total == 0:
        return 0.0
    return round(duplicates / total, 4)


def median_time_to_first_valid_finding(results: Sequence[TestResult]) -> float | None:
    """Median time to the first confirmed finding, in seconds."""
    times = sorted(
        result.duration_ms / 1000.0 for result in results if result.detected and result.duration_ms
    )
    if not times:
        return None
    middle = len(times) // 2
    if len(times) % 2:
        return round(times[middle], 3)
    return round((times[middle - 1] + times[middle]) / 2, 3)


def match_finding(
    finding: dict[str, Any],
    *,
    vuln_class: str,
    expected_evidence: Sequence[str],
    location_hint: str = "",
) -> bool:
    """Decide whether *finding* satisfies a test case.

    The match is evidence based: the vulnerability class must match and at
    least one of the expected evidence markers must be present, unless the
    case did not declare any markers (in which case the class alone is
    enough).
    """
    actual_class = str(finding.get("vuln_class", "")).strip().lower()
    if vuln_class and actual_class != vuln_class.strip().lower():
        return False

    if not expected_evidence:
        return True

    haystack = " ".join(
        str(finding.get(key, "")) for key in ("title", "summary", "affected_url", "path", "host", "evidence")
    ).lower()
    for marker in expected_evidence:
        if str(marker).lower() in haystack:
            return True

    if location_hint and location_hint.lower() in haystack:
        return True
    return False


def build_summary(
    results: Sequence[TestResult],
    *,
    duration_seconds: float = 0.0,
    model_usage: dict[str, Any] | None = None,
    tool_failure_rate: float = 0.0,
    agent_failure_rate: float = 0.0,
    endpoint_coverage: float | None = None,
    auth_completion_rate: float | None = None,
) -> dict[str, Any]:
    """Build the full benchmark summary."""
    score = score_results(results)
    return {
        "score": score.to_dict(),
        "by_vuln_class": detection_rate_by_class(results),
        "by_application": detection_rate_by_application(results),
        "duplicate_finding_rate": duplicate_rate(results),
        "median_time_to_first_valid_finding_seconds": median_time_to_first_valid_finding(results),
        "total_duration_seconds": round(duration_seconds, 3),
        "model_usage": model_usage or {},
        "tool_failure_rate": tool_failure_rate,
        "agent_failure_rate": agent_failure_rate,
        "endpoint_route_discovery_coverage": endpoint_coverage,
        "authentication_workflow_completion_rate": auth_completion_rate,
        "results": [result.to_dict() for result in results],
    }


def summarise_for_humans(summary: dict[str, Any]) -> str:
    """Render a benchmark summary as a short text block."""
    score = summary.get("score", {})
    lines = [
        f"True positives:      {score.get('true_positives', 0)}",
        f"False positives:     {score.get('false_positives', 0)}",
        f"False negatives:     {score.get('false_negatives', 0)}",
        f"Not applicable:      {score.get('not_applicable', 0)}",
        f"Inconclusive:        {score.get('inconclusive', 0)}",
        f"Precision:           {score.get('precision', 0.0)}",
        f"Recall:              {score.get('recall', 0.0)}",
        f"F1:                  {score.get('f1', 0.0)}",
        f"Duplicate rate:      {summary.get('duplicate_finding_rate', 0.0)}",
        f"Median first find:   {summary.get('median_time_to_first_valid_finding_seconds')}s",
        f"Total duration:      {summary.get('total_duration_seconds')}s",
    ]
    return "\n".join(lines)
