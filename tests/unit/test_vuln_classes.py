"""One name for each kind of vulnerability.

The classes in this file are the ones the platform has actually
produced — seventy-eight spellings of about twenty kinds of
vulnerability, taken from the scans that have run.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.vuln_classes import (
    CANONICAL_CLASSES,
    class_aliases,
    normalise_vuln_class,
    primary_class,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("sql_injection", "sql_injection"),
        ("SQL Injection", "sql_injection"),
        ("NoSQL Injection", "sql_injection"),
        ("CWE-943 (NoSQL Injection) - no reachable sink", "sql_injection"),
        ("CWE-89 (SQL Injection) - tested, not reproduced", "sql_injection"),
        ("CWE-1021 (Clickjacking)", "security_misconfiguration"),
        (
            "CWE-1021 / CWE-693 (Improper Restriction of Rendered UI Layers or Frameworks)",
            "security_misconfiguration",
        ),
        ("CWE-693 (Improper Restriction of Rendered UI Layers or Frameworks)", "security_misconfiguration"),
        (
            "CWE-306 Missing Authentication for Critical Function / CWE-200 Exposure of Sensitive Information",
            "access_control",
        ),
        ("CWE-209", "information_disclosure"),
        ("CWE-598 Use of Request Parameters in Sensitive Query Strings / CWE-200", "information_disclosure"),
        ("CWE-319 (Cleartext Transmission of Sensitive Information)", "cleartext_transmission"),
        ("CWE-352", "csrf"),
        ("security_misconfiguration / csrf_protection_disabled", "security_misconfiguration"),
        ("information_disclosure / verbose_error", "information_disclosure"),
        ("information_disclosure / session_management", "information_disclosure"),
        ("ssrf / path_traversal (unverified - no evidence of exploitability obtained)", "ssrf"),
        ("server_side_request_forgery / path_traversal", "ssrf"),
        ("Server-Side Template Injection (SSTI)", "ssti"),
        ("OS Command Injection", "command_injection"),
        ("broken_object_level_authorization", "access_control"),
        ("broken_object_level_authorization / privilege_escalation", "access_control"),
        ("missing_authorization / exposed_management_endpoint", "access_control"),
        ("exposure-of-sensitive-information / unauthenticated management endpoint", "information_disclosure"),
        (
            "security_misconfiguration / unauthenticated_management_endpoint_exposure",
            "security_misconfiguration",
        ),
        ("Security Misconfiguration / Information Disclosure", "security_misconfiguration"),
        ("Information Exposure (CWE-200)", "information_disclosure"),
        (
            "Information Exposure Through an Error Message / Sensitive Information Exposure (CWE-200)",
            "information_disclosure",
        ),
        (
            "Use of Undocumented/Exposed Administrative API; potential Missing Authorization / BOLA (CWE-306, CWE-862, CWE-639)",
            "access_control",
        ),
        ("Session management observation (CWE-1004)", "session_management"),
        ("Session management weakness", "session_management"),
        ("assessment_coverage_limitation / CWE-89, CWE-943, CWE-78 untested", "coverage_gap"),
        ("Coverage Gap", "coverage_gap"),
        ("Coverage limitation", "coverage_gap"),
        ("noise triage", "note"),
        ("triage_note", "note"),
        ("attack_surface_discovery / missing service in inventory", "attack_surface"),
        ("service_inventory", "technology"),
        ("technology_identification", "technology"),
        ("potential_path_traversal", "path_traversal"),
        ("path_traversal (tested - filtered)", "path_traversal"),
        ("cleartext_transmission / missing_tls", "cleartext_transmission"),
        ("active_vulnerability", "active_vulnerability"),
        ("", "unknown"),
    ],
)
def test_a_class_is_normalised(raw, expected):
    assert normalise_vuln_class(raw) == expected


def test_every_canonical_class_is_reachable():
    # A class the platform uses must survive the normalisation: the
    # scanner adapters emit them and they must not be rewritten.
    for canonical in CANONICAL_CLASSES:
        assert normalise_vuln_class(canonical) == canonical


def test_a_class_that_names_two_things_leads_with_the_first():
    assert primary_class("security_misconfiguration / information_disclosure") == "security_misconfiguration"
    assert "information_disclosure" in class_aliases("security_misconfiguration / information_disclosure")


def test_the_aliases_of_a_class_are_the_canonical_ones():
    aliases = class_aliases("CWE-306 Missing Authentication / CWE-200 Information Exposure")
    assert "access_control" in aliases
    assert "information_disclosure" in aliases


def test_a_candidate_is_a_note_and_not_a_finding():
    """The agent roles report what they suspect as well as what they proved."""
    assert normalise_vuln_class("client_side_injection_candidate") == "note"
    assert normalise_vuln_class("candidate_access_control_target") == "note"
    assert normalise_vuln_class("injection_candidate") == "note"


def test_an_assessment_that_was_blocked_is_a_coverage_gap():
    assert normalise_vuln_class("access_control_assessment_inconclusive") == "coverage_gap"
    assert normalise_vuln_class("Assessment blocked: the host refused the request") == "coverage_gap"


def test_a_note_about_the_target_is_a_note():
    assert normalise_vuln_class("context") == "note"


def test_an_unknown_class_keeps_its_text():
    assert normalise_vuln_class("Something Nobody Classified") == "something_nobody_classified"
