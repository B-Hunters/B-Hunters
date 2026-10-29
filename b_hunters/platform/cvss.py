"""CVSS 3.1 scoring and the OWASP Top 10 mapping.

The platform records a severity for every finding, and the severity is
what an operator reads first and what a report is sorted by.  The
severity that arrives with a finding is the one the tool that found it
claimed; this module turns a vector into the score that CVSS 3.1
defines, so that two findings of the same kind are comparable.

The calculator is implemented here rather than pulled in as a
dependency: the base score is a few lines of arithmetic, and a scanner
platform that cannot be installed offline is a scanner platform that
cannot be audited.
"""

from __future__ import annotations

import math
from typing import Any

#: The metric abbreviations and the values each accepts.
METRIC_VALUES: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}

#: The weight of the attack vector.
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}

#: The weight of the attack complexity.
AC_WEIGHTS = {"L": 0.77, "H": 0.44}

#: The weight of the privileges required, which depends on the scope.
PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

#: The weight of the user interaction.
UI_WEIGHTS = {"N": 0.85, "R": 0.62}

#: The weight of a confidentiality, integrity or availability impact.
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

#: The OWASP Top 10 (2021) categories the platform maps onto.
OWASP_CATEGORIES: dict[str, str] = {
    # A01 Broken Access Control
    "access_control": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "auth_bypass": "A01:2021 - Broken Access Control",
    "csrf": "A01:2021 - Broken Access Control",
    # A02 Cryptographic Failures
    "weak_crypto": "A02:2021 - Cryptographic Failures",
    "tls_configuration": "A02:2021 - Cryptographic Failures",
    "cleartext_transmission": "A02:2021 - Cryptographic Failures",
    # A03 Injection
    "sql_injection": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "ssrf": "A03:2021 - Injection",
    "ssti": "A03:2021 - Injection",
    "xxe": "A03:2021 - Injection",
    "command_injection": "A03:2021 - Injection",
    "ldap_injection": "A03:2021 - Injection",
    "graphql": "A03:2021 - Injection",
    # A04 Insecure Design
    "insecure_deserialization": "A04:2021 - Insecure Design",
    "business_logic": "A04:2021 - Insecure Design",
    # A05 Security Misconfiguration
    "security_misconfiguration": "A05:2021 - Security Misconfiguration",
    "cors": "A05:2021 - Security Misconfiguration",
    "open_redirect": "A05:2021 - Security Misconfiguration",
    "host_header_injection": "A05:2021 - Security Misconfiguration",
    "directory_listing": "A05:2021 - Security Misconfiguration",
    "default_credentials": "A05:2021 - Security Misconfiguration",
    # A06 Vulnerable and Outdated Components
    "outdated_component": "A06:2021 - Vulnerable and Outdated Components",
    # A07 Identification and Authentication Failures
    "session_management": "A07:2021 - Identification and Authentication Failures",
    "weak_password": "A07:2021 - Identification and Authentication Failures",
    # A08 Software and Data Integrity Failures
    "integrity_failure": "A08:2021 - Software and Data Integrity Failures",
    # A09 Security Logging and Monitoring Failures
    "logging_failure": "A09:2021 - Security Logging and Monitoring Failures",
    # A10 SSRF
    "server_side_request_forgery": "A10:2021 - Server-Side Request Forgery",
    # A07 (the older, widely used name of the SSRF category)
    "path_traversal": "A01:2021 - Broken Access Control",
    # A05 information exposure
    "info_disclosure": "A05:2021 - Security Misconfiguration",
}


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS 3.1 vector into its metrics.

    Raises ``ValueError`` for a malformed vector, an unknown metric, an
    unknown value, a missing metric, or a version other than 3.1.  The
    base metrics are all required: a vector that leaves one out cannot
    be scored, and guessing one would produce a score that looks
    authoritative and is not.
    """
    text = (vector or "").strip()
    if not text:
        raise ValueError("the vector is empty")
    parts = text.split("/")
    head = parts[0]
    if not head.startswith("CVSS:3.1"):
        raise ValueError(f"unsupported vector version '{head}'")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"malformed vector component '{part}'")
        name, _, value = part.partition(":")
        name = name.strip().upper()
        value = value.strip().upper()
        if name not in METRIC_VALUES:
            raise ValueError(f"unknown metric '{name}'")
        if value not in METRIC_VALUES[name]:
            raise ValueError(f"unknown value '{value}' for the metric '{name}'")
        if name in metrics:
            raise ValueError(f"the metric '{name}' appears twice")
        metrics[name] = value

    missing = sorted(set(METRIC_VALUES) - set(metrics))
    if missing:
        raise ValueError(f"the vector is missing the metric(s): {', '.join(missing)}")
    return metrics


def roundup(value: float) -> float:
    """Round a score up to one decimal, the way CVSS 3.1 defines it.

    The definition rounds to six decimal places first, and then adds the
    smallest number that makes the result a multiple of 0.1 — so 4.02
    becomes 4.1 and 4.00 stays 4.0.
    """
    scaled = round(float(value) * 100000)
    if scaled % 10000 == 0:
        return round(scaled / 100000.0, 1)
    # The multiplication by 0.1 is not exact in binary floating point:
    # 41 * 0.1 is 4.1000000000000005.  The score is rounded to one
    # decimal so that it reads as a score and compares as one.
    return round((math.floor(scaled / 10000) + 1) * 0.1, 1)


def base_score(vector: str) -> float:
    """The CVSS 3.1 base score of a vector."""
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"

    isc_base = 1 - (
        (1 - CIA_WEIGHTS[metrics["C"]]) * (1 - CIA_WEIGHTS[metrics["I"]]) * (1 - CIA_WEIGHTS[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        impact = 6.42 * isc_base

    privileges = PR_WEIGHTS_CHANGED if scope_changed else PR_WEIGHTS_UNCHANGED
    exploitability = (
        8.22
        * AV_WEIGHTS[metrics["AV"]]
        * AC_WEIGHTS[metrics["AC"]]
        * privileges[metrics["PR"]]
        * UI_WEIGHTS[metrics["UI"]]
    )

    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity_from_score(score: float) -> str:
    """The severity band a score belongs to."""
    value = float(score)
    if value <= 0:
        return "none"
    if value < 4.0:
        return "low"
    if value < 7.0:
        return "medium"
    if value < 9.0:
        return "high"
    return "critical"


def owasp_category(vuln_class: str) -> str:
    """The OWASP Top 10 (2021) category a vulnerability class belongs to.

    An unknown class maps to nothing rather than to a guess.
    """
    return OWASP_CATEGORIES.get((vuln_class or "").strip().lower(), "")


def score_for(vuln_class: str, vector: str = "") -> dict[str, Any]:
    """The score of a finding: the vector, the score and the band.

    A finding without a vector has no score; the severity it carries is
    the tool's own opinion and is returned unchanged.
    """
    if not vector:
        return {"vector": "", "score": 0.0, "severity": "", "owasp_category": owasp_category(vuln_class)}
    score = base_score(vector)
    return {
        "vector": vector,
        "score": score,
        "severity": severity_from_score(score),
        "owasp_category": owasp_category(vuln_class),
    }
