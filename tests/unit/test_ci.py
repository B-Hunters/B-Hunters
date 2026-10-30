"""The CI entry point.

The exit code is the point of the command: a pipeline needs to fail when
the scan found something bad, and it needs to fail in a way it can act
on.
"""

from __future__ import annotations

from b_hunters.platform.ci import at_least, ci_scan, severity_rank


class _Fake:
    """A platform that answers with what the test tells it to."""

    def __init__(self, findings=None, status="completed"):
        self.findings = findings or []
        self.status = status
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path))
        if method == "POST" and path == "/scans":
            return 201, {"scan_id": "s1"}
        if method == "POST" and path.endswith("/start"):
            return 202, {"status": "running"}
        if method == "GET" and path.startswith("/scans/"):
            return 200, {"status": self.status, "scan_id": "s1"}
        if method == "GET" and path.startswith("/findings"):
            return 200, {"findings": self.findings}
        return 404, {"detail": "not found"}


def _finding(severity: str) -> dict:
    return {
        "title": f"a {severity} finding",
        "severity": severity,
        "vuln_class": "xss",
    }


def test_the_severities_are_ordered_worst_first():
    assert severity_rank("critical") < severity_rank("high")
    assert severity_rank("high") < severity_rank("medium")
    assert severity_rank("info") < severity_rank("unknown")


def test_a_severity_is_compared_with_the_threshold():
    assert at_least("critical", "high") is True
    assert at_least("high", "high") is True
    assert at_least("medium", "high") is False


def test_the_command_fails_on_a_high_finding():
    platform = _Fake(findings=[_finding("medium"), _finding("high")])
    lines: list[str] = []

    code = ci_scan(
        target="https://demo.test/",
        token="t",
        request=platform,
        fail_on="high",
        log=lines.append,
    )

    assert code == 1
    assert any("high" in line for line in lines)


def test_the_command_succeeds_when_nothing_is_that_bad():
    platform = _Fake(findings=[_finding("low"), _finding("info")])

    code = ci_scan(
        target="https://demo.test/",
        token="t",
        request=platform,
        fail_on="high",
        log=lambda line: None,
    )

    assert code == 0


def test_the_command_fails_on_a_critical_finding_even_when_the_threshold_is_high():
    platform = _Fake(findings=[_finding("critical")])

    code = ci_scan(
        target="https://demo.test/",
        token="t",
        request=platform,
        fail_on="high",
        log=lambda line: None,
    )

    assert code == 1


def test_the_command_reports_a_scan_that_could_not_be_created():
    def broken(method, path, body=None):
        return 500, {"detail": "no"}

    code = ci_scan(
        target="https://demo.test/",
        token="t",
        request=broken,
        log=lambda line: None,
    )

    assert code == 2


def test_the_command_reports_a_scan_that_failed():
    platform = _Fake(status="failed")

    code = ci_scan(
        target="https://demo.test/",
        token="t",
        request=platform,
        log=lambda line: None,
    )

    assert code == 2


def test_the_command_creates_and_starts_the_scan():
    platform = _Fake()

    ci_scan(
        target="https://demo.test/",
        token="t",
        request=platform,
        log=lambda line: None,
    )

    assert ("POST", "/scans") in platform.calls
    assert ("POST", "/scans/s1/start") in platform.calls


def test_the_command_does_not_wait_when_it_is_told_not_to():
    platform = _Fake()

    ci_scan(
        target="https://demo.test/",
        token="t",
        wait=False,
        request=platform,
        log=lambda line: None,
    )

    assert not any(path.startswith("/scans/s1") and method == "GET" for method, path in platform.calls)


def test_the_findings_are_printed():
    platform = _Fake(findings=[_finding("high")])
    lines: list[str] = []

    ci_scan(
        target="https://demo.test/",
        token="t",
        request=platform,
        log=lines.append,
    )

    assert any("a high finding" in line for line in lines)
