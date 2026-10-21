"""Benchmark harness tests.

These verify the scoring arithmetic, the manifest contract and the
runner's matching logic.  They deliberately do not need a running
laboratory: the manifests and the scoring are pure functions.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.bench.manifest import VULN_CLASSES, default_manifests
from b_hunters.platform.bench.runner import BenchmarkRunConfig
from b_hunters.platform.bench.scoring import (
    OUTCOME_FALSE_NEGATIVE,
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_NOT_APPLICABLE,
    OUTCOME_TRUE_POSITIVE,
    TestResult,
    build_summary,
    detection_rate_by_application,
    detection_rate_by_class,
    duplicate_rate,
    match_finding,
    median_time_to_first_valid_finding,
    score_results,
    stable_vulnerability_id,
)

pytestmark = pytest.mark.benchmark


def _result(**kwargs) -> TestResult:
    defaults = {
        "test_id": "t",
        "application": "app",
        "vuln_class": "xss",
        "outcome": OUTCOME_TRUE_POSITIVE,
    }
    defaults.update(kwargs)
    return TestResult(**defaults)


# ----------------------------------------------------------------------
# Manifests
# ----------------------------------------------------------------------
def test_the_default_manifests_are_well_formed() -> None:
    manifests = default_manifests()
    assert len(manifests) >= 5
    slugs = [manifest.slug for manifest in manifests]
    assert len(slugs) == len(set(slugs)), "the slugs must be unique"
    for manifest in manifests:
        assert manifest.name
        assert manifest.version
        assert manifest.image
        assert manifest.port > 0
        assert manifest.license
        assert manifest.upstream
        assert manifest.test_cases, manifest.slug
        for case in manifest.test_cases:
            assert case.test_id
            assert case.vuln_class in VULN_CLASSES, f"{manifest.slug}: {case.vuln_class}"
            assert case.expectation in {"expected", "not_applicable", "hygiene"}
            assert case.expected_evidence, f"{manifest.slug}/{case.test_id}"
            assert case.expected_severity in {
                "critical",
                "high",
                "medium",
                "low",
                "info",
            }


def test_test_ids_are_unique_within_a_manifest() -> None:
    for manifest in default_manifests():
        ids = [case.test_id for case in manifest.test_cases]
        assert len(ids) == len(set(ids)), manifest.slug


def test_manifest_test_ids_are_globally_unique() -> None:
    ids = [case.test_id for manifest in default_manifests() for case in manifest.test_cases]
    assert len(ids) == len(set(ids))


def test_the_manifests_cover_the_required_categories() -> None:
    classes = {case.vuln_class for manifest in default_manifests() for case in manifest.test_cases}
    for required in [
        "route_discovery",
        "javascript_analysis",
        "api_discovery",
        "authentication",
        "access_control",
        "sql_injection",
        "xss",
        "ssti",
        "security_misconfiguration",
        "graphql",
    ]:
        assert required in classes, f"the benchmark must cover {required}"


def test_the_lab_generates_a_compose_file_bound_to_loopback() -> None:
    from b_hunters.platform.bench.lab import LabManager

    manager = LabManager()
    compose = manager.compose_file(["dvga"])
    assert "127.0.0.1:" in compose, "the lab must publish on loopback only"
    assert "bhunters-bench-net" in compose
    assert "dolevf/dvga:2.2.0" in compose
    # Only the selected application may be started.
    assert "juice-shop" not in compose


def test_the_lab_manifest_covers_every_application() -> None:
    from b_hunters.platform.bench.lab import LabManager

    manager = LabManager()
    compose = manager.compose_file()
    for manifest in default_manifests():
        assert manifest.image in compose


# ----------------------------------------------------------------------
# Scoring arithmetic
# ----------------------------------------------------------------------
def test_perfect_scores_are_one() -> None:
    results = [
        _result(outcome=OUTCOME_TRUE_POSITIVE),
        _result(outcome=OUTCOME_TRUE_POSITIVE),
    ]
    score = score_results(results)
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.f1 == 1.0


def test_false_positives_reduce_precision() -> None:
    results = [
        _result(outcome=OUTCOME_TRUE_POSITIVE),
        _result(outcome=OUTCOME_TRUE_POSITIVE),
        _result(outcome=OUTCOME_FALSE_POSITIVE),
    ]
    score = score_results(results)
    assert score.precision == pytest.approx(2 / 3, rel=1e-3)
    assert score.recall == 1.0


def test_false_negatives_reduce_recall() -> None:
    results = [
        _result(outcome=OUTCOME_TRUE_POSITIVE),
        _result(outcome=OUTCOME_FALSE_NEGATIVE),
    ]
    score = score_results(results)
    assert score.precision == 1.0
    assert score.recall == 0.5
    assert score.f1 == pytest.approx(2 / 3, rel=1e-3)


def test_not_applicable_cases_do_not_affect_the_score() -> None:
    results = [
        _result(outcome=OUTCOME_TRUE_POSITIVE),
        _result(outcome=OUTCOME_NOT_APPLICABLE),
        _result(outcome=OUTCOME_NOT_APPLICABLE),
    ]
    score = score_results(results)
    assert score.not_applicable == 2
    assert score.precision == 1.0
    assert score.recall == 1.0


def test_inconclusive_cases_do_not_affect_the_score() -> None:
    results = [
        _result(outcome=OUTCOME_TRUE_POSITIVE),
        _result(outcome=OUTCOME_INCONCLUSIVE),
    ]
    score = score_results(results)
    assert score.inconclusive == 1
    assert score.precision == 1.0
    assert score.recall == 1.0


def test_an_empty_run_scores_zero_without_dividing_by_zero() -> None:
    score = score_results([])
    assert score.precision == 0.0
    assert score.recall == 0.0
    assert score.f1 == 0.0


def test_detection_rate_per_class() -> None:
    results = [
        _result(vuln_class="xss", outcome=OUTCOME_TRUE_POSITIVE, detected=True),
        _result(vuln_class="xss", outcome=OUTCOME_FALSE_NEGATIVE, detected=False),
        _result(vuln_class="sqli", outcome=OUTCOME_TRUE_POSITIVE, detected=True),
    ]
    rates = detection_rate_by_class(results)
    assert rates["xss"]["expected"] == 2
    assert rates["xss"]["detection_rate"] == 0.5
    assert rates["sqli"]["detection_rate"] == 1.0


def test_detection_rate_per_application() -> None:
    results = [
        _result(application="dvga", outcome=OUTCOME_TRUE_POSITIVE, detected=True),
        _result(application="juice", outcome=OUTCOME_FALSE_NEGATIVE, detected=False),
    ]
    rates = detection_rate_by_application(results)
    assert rates["dvga"]["detection_rate"] == 1.0
    assert rates["juice"]["detection_rate"] == 0.0


def test_duplicate_rate_counts_findings_reported_by_several_detectors() -> None:
    """A finding that two tools reported is a duplicate detection."""
    results = [
        _result(finding_ids=["a"], detected=True, detection_source="nuclei, dalfox"),
        _result(finding_ids=["b"], detected=True, detection_source="nuclei"),
    ]
    assert duplicate_rate(results) == pytest.approx(0.5, rel=1e-3)


def test_duplicate_rate_is_zero_without_findings() -> None:
    assert duplicate_rate([]) == 0.0
    assert duplicate_rate([_result(finding_ids=[], detected=False)]) == 0.0


def test_median_time_to_first_valid_finding() -> None:
    results = [
        _result(duration_ms=1000, detected=True),
        _result(duration_ms=3000, detected=True),
        _result(duration_ms=2000, detected=True),
    ]
    assert median_time_to_first_valid_finding(results) == 2.0


def test_median_time_is_none_without_detections() -> None:
    assert median_time_to_first_valid_finding([_result(detected=False)]) is None


def test_the_summary_contains_every_required_metric() -> None:
    summary = build_summary(
        [
            _result(outcome=OUTCOME_TRUE_POSITIVE, detected=True, duration_ms=1500),
            _result(outcome=OUTCOME_FALSE_NEGATIVE, detected=False),
        ],
        duration_seconds=42.0,
        model_usage={"total_tokens": 1000},
        tool_failure_rate=0.1,
        agent_failure_rate=0.0,
        endpoint_coverage=0.8,
        auth_completion_rate=0.5,
    )
    for key in [
        "score",
        "by_vuln_class",
        "by_application",
        "duplicate_finding_rate",
        "median_time_to_first_valid_finding_seconds",
        "total_duration_seconds",
        "model_usage",
        "tool_failure_rate",
        "agent_failure_rate",
        "endpoint_route_discovery_coverage",
        "authentication_workflow_completion_rate",
    ]:
        assert key in summary, key


# ----------------------------------------------------------------------
# Matching
# ----------------------------------------------------------------------
def test_a_finding_matches_on_the_class_and_the_evidence() -> None:
    finding = {
        "vuln_class": "xss",
        "title": "Reflected XSS in search",
        "summary": "the parameter is echoed into the HTML",
        "affected_url": "https://x.test/search",
    }
    assert match_finding(finding, vuln_class="xss", expected_evidence=["<b>"]) is False
    assert match_finding(finding, vuln_class="xss", expected_evidence=["xss"]) is True
    assert match_finding(finding, vuln_class="sqli", expected_evidence=["xss"]) is False


def test_a_case_without_evidence_matches_on_the_class_alone() -> None:
    finding = {"vuln_class": "xss", "title": "t", "summary": "s"}
    assert match_finding(finding, vuln_class="xss", expected_evidence=[]) is True
    assert match_finding(finding, vuln_class="sqli", expected_evidence=[]) is False


def test_the_vulnerability_id_is_stable() -> None:
    first = stable_vulnerability_id("dvga", "xss", "/v1/notes")
    second = stable_vulnerability_id("DVGA", "XSS", "/v1/notes")
    assert first == second
    assert stable_vulnerability_id("dvga", "sqli", "/v1/notes") != first


# ----------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------
def test_the_runner_config_defaults_are_safe() -> None:
    config = BenchmarkRunConfig()
    assert config.applications == []
    assert config.profile == "standard"


@pytest.mark.asyncio
async def test_an_unreachable_application_yields_inconclusive_results(services) -> None:
    """A laboratory that is not running must not produce fake scores."""
    from b_hunters.platform.bench.lab import LabManager
    from b_hunters.platform.bench.runner import BenchmarkRunner

    class DeadLab(LabManager):
        def wait_healthy(self, manifest, *, timeout=None):
            return False, "the container did not start"

    runner = BenchmarkRunner(database=services.db, lab=DeadLab())
    outcome = await runner.run(BenchmarkRunConfig(applications=["dvga"]))

    results = outcome["results"]
    assert results
    assert all(item["outcome"] == OUTCOME_INCONCLUSIVE for item in results)
    assert outcome["summary"]["score"]["true_positives"] == 0
    assert outcome["summary"]["score"]["inconclusive"] == len(results)


@pytest.mark.asyncio
async def test_the_runner_scores_reported_findings(services) -> None:
    from b_hunters.platform.bench.lab import LabManager
    from b_hunters.platform.bench.runner import BenchmarkRunner

    class ReadyLab(LabManager):
        def wait_healthy(self, manifest, *, timeout=None):
            return True, ""

    scan_id = "benchmark-scan"

    async def scan_creator(**kwargs):
        return {"scan_id": scan_id}

    runner = BenchmarkRunner(database=services.db, lab=ReadyLab(), scan_creator=scan_creator)
    # Seed the findings the runner will compare against.
    from b_hunters.platform.db.repositories import FindingRepository

    findings = FindingRepository(services.db)
    findings.upsert(
        scan_id=scan_id,
        title="GraphQL introspection is enabled",
        summary="__schema types users",
        vuln_class="graphql",
        severity="low",
        host="127.0.0.1",
        path="/graphql",
        detected_by=["scanner"],
    )

    outcome = await runner.run(BenchmarkRunConfig(applications=["dvga"]))
    results = {item["test_id"]: item for item in outcome["results"]}
    assert results["dvga-introspection"]["outcome"] == OUTCOME_TRUE_POSITIVE
    assert results["dvga-introspection"]["detected"] is True
    # A class the finding does not cover is a false negative.
    assert results["dvga-graphql-sqli"]["outcome"] == OUTCOME_FALSE_NEGATIVE
