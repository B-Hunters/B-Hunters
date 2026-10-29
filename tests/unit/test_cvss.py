"""The CVSS 3.1 calculator and the OWASP mapping."""

from __future__ import annotations

import pytest

from b_hunters.platform.cvss import (
    base_score,
    owasp_category,
    parse_vector,
    roundup,
    score_for,
    severity_from_score,
)


def test_a_vector_is_parsed_into_its_metrics():
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert metrics["AV"] == "N"
    assert metrics["AC"] == "L"
    assert metrics["S"] == "U"
    assert metrics["C"] == "H"


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N",
        "CVSS:3.1/AV:NAC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_a_malformed_vector_is_refused(vector):
    with pytest.raises(ValueError):
        parse_vector(vector)


def test_the_published_vectors_score_what_they_should():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 8.8
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N") == 4.3
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert base_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == 0.0


def test_the_score_never_leaves_the_scale():
    for vector in (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
    ):
        score = base_score(vector)
        assert 0.0 <= score <= 10.0


def test_the_roundup_matches_the_definition():
    assert roundup(4.02) == 4.1
    assert roundup(4.00) == 4.0
    assert roundup(4.0) == 4.0
    assert roundup(0.1) == 0.1
    assert roundup(9.7601608) == 9.8
    assert roundup(8.7083727) == 8.8


def test_the_severity_bands():
    assert severity_from_score(0) == "none"
    assert severity_from_score(3.9) == "low"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(6.9) == "medium"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(8.9) == "high"
    assert severity_from_score(9.0) == "critical"
    assert severity_from_score(10.0) == "critical"


def test_the_vulnerability_classes_map_onto_the_owasp_categories():
    assert owasp_category("sql_injection").startswith("A03")
    assert owasp_category("xss").startswith("A03")
    assert owasp_category("access_control").startswith("A01")
    assert owasp_category("tls_configuration").startswith("A02")
    assert owasp_category("security_misconfiguration").startswith("A05")
    assert owasp_category("ssrf").startswith("A03")
    assert owasp_category("graphql").startswith("A03")
    assert owasp_category("ssti").startswith("A03")
    assert owasp_category("path_traversal").startswith("A01")
    assert owasp_category("something_unknown") == ""


def test_a_finding_without_a_vector_has_no_score():
    result = score_for("xss", "")
    assert result["score"] == 0.0
    assert result["severity"] == ""
    assert result["owasp_category"].startswith("A03")


def test_a_finding_with_a_vector_is_scored():
    result = score_for("sql_injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result["score"] == 9.8
    assert result["severity"] == "critical"
    assert result["owasp_category"].startswith("A03")
