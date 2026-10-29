"""A structured finding a worker wrote is read as a finding.

Xray writes an object - the plugin that found the issue, the target and
the detail - and 117 of those objects were one finding each.  Read as a
string, such an object says nothing but the name of the field it came
from, so the finding needs its title, its location and its evidence read
out of it.
"""

from __future__ import annotations

from b_hunters.platform.bench.workers import findings_from_report

_XRAY = {
    "detail": {
        "addr": "http://t:8080/DownloadServlet?FileName=..\\..\\login.jsp",
        "payload": "",
        "extra": {"param": {}},
    },
    "plugin": "baseline/sensitive/server-error",
    "target": {"url": "http://t:8080/DownloadServlet"},
}


def test_a_structured_finding_gets_a_title() -> None:
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY]}})
    assert len(findings) == 1
    title = findings[0]["title"]
    assert "baseline/sensitive/server-error" in title
    assert "DownloadServlet" in title
    assert title != "Xray"


def test_a_structured_finding_gets_its_location() -> None:
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY]}})
    assert "DownloadServlet" in findings[0]["location"]


def test_a_structured_finding_gets_its_evidence() -> None:
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY]}})
    summary = findings[0]["summary"]
    assert "issue: baseline/sensitive/server-error" in summary
    assert "address: http://t:8080/DownloadServlet" in summary
    assert findings[0]["evidence"][0]["excerpt"]


def test_the_class_comes_from_the_plugin() -> None:
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY]}})
    assert findings[0]["vuln_class"] == "information_disclosure"


def test_the_detector_is_the_worker_that_wrote_it() -> None:
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY]}})
    assert findings[0]["detector"] == "Xray"


def test_the_instances_of_one_issue_are_one_finding() -> None:
    """A server that leaks a stack trace on 117 URLs is one finding."""
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY, _XRAY]}})
    assert len(findings) == 1
    assert "2 URL(s)" in findings[0]["title"]


def test_the_urls_of_one_issue_are_kept_together() -> None:
    second = {
        "detail": {"addr": "http://t:8080/other", "payload": "", "extra": {}},
        "plugin": "baseline/sensitive/server-error",
        "target": {"url": "http://t:8080/other"},
    }
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY, second]}})
    excerpt = findings[0]["evidence"][0]["excerpt"]
    assert "http://t:8080/DownloadServlet" in excerpt
    assert "http://t:8080/other" in excerpt


def test_different_issues_stay_apart() -> None:
    other = {
        "detail": {"addr": "http://t:8080/x", "payload": "", "extra": {}},
        "plugin": "dirscan/sourcemap/default",
        "target": {"url": "http://t:8080/x"},
    }
    findings = findings_from_report({"Vulns": {"Xray": [_XRAY, other]}})
    assert len(findings) == 2


def test_a_plain_text_finding_is_never_merged() -> None:
    findings = findings_from_report(
        {
            "Vulns": {
                "Nuclei": [
                    "[springboot-env] [http] [low] http://t/actuator/env",
                    "[tomcat-stacktraces] [http] [low] http://t/",
                ]
            }
        }
    )
    assert len(findings) == 2


def test_a_plain_text_finding_is_unchanged() -> None:
    findings = findings_from_report(
        {"Vulns": {"Nuclei": ["[springboot-env] [http] [low] http://t/actuator/env"]}}
    )
    assert findings[0]["title"].startswith("[springboot-env]")
    assert findings[0]["detector"] == "Nuclei"
