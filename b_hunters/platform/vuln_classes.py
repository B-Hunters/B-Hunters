"""One name for each kind of vulnerability.

The platform's findings come from three kinds of source: the scanner
adapters, which name a class in the platform's own vocabulary, and the
agent roles, which name it in their own words — ``"CWE-1021
(Clickjacking)"``, ``"security_misconfiguration / csrf_protection_disabled"``,
``"SQL Injection"``.  Across the scans that is more than seventy
spellings of about twenty kinds of vulnerability.

That is not cosmetic.  The fingerprint of a finding is its class, so two
reports of the same issue in two spellings are two findings; the triage
view groups by class, so the same issue lands in two groups; and the
benchmark compares the class exactly, so a finding the platform
reported is scored as missed.

The class is therefore normalised on the way in: the canonical name is
stored, and the original text is kept beside it, because the original
carries the detail — which header, which parameter, which endpoint.
"""

from __future__ import annotations

import re

#: The classes the platform uses.
CANONICAL_CLASSES = (
    "access_control",
    "active_vulnerability",
    "api_discovery",
    "attack_surface",
    "cleartext_transmission",
    "command_injection",
    "coverage_gap",
    "csrf",
    "dos",
    "graphql",
    "idempotency",
    "information_disclosure",
    "informational",
    "insecure_deserialization",
    "javascript_analysis",
    "note",
    "open_redirect",
    "path_traversal",
    "route_discovery",
    "security_misconfiguration",
    "session_management",
    "sql_injection",
    "ssrf",
    "ssti",
    "technology",
    "untrusted_content",
    "weak_crypto",
    "weak_crypto_oracle",
    "xss",
    "xxe",
)

#: The classes of things that are not vulnerabilities, and what they are.
_NOTE_CLASSES = {
    "coverage gap": "coverage_gap",
    "coverage_limitation": "coverage_gap",
    "coverage limitation": "coverage_gap",
    "assessment_limitation": "coverage_gap",
    "assessment limitation": "coverage_gap",
    "noise triage": "note",
    "triage_note": "note",
    "false_positive": "note",
    "attack_surface_discovery": "attack_surface",
    "attack_surface_mapping": "attack_surface",
    "attack surface discovery": "attack_surface",
    "service_inventory": "technology",
    "technology_identification": "technology",
    "configuration_intelligence": "technology",
    "untrusted_content": "untrusted_content",
    "informational": "informational",
    # What the target is, rather than what is wrong with it.
    "context": "note",
}

#: Words that name a class of their own, even though they are not
#: classes of the platform's vocabulary.
_SYNONYMS = {
    "misconfiguration": "security_misconfiguration",
    "server_side_request_forgery": "ssrf",
    "path_traversal": "path_traversal",
    "cross_site_scripting": "xss",
    "cross_site_request_forgery": "csrf",
    "sql_injection": "sql_injection",
    "command_injection": "command_injection",
    "template_injection": "ssti",
    "broken_access_control": "access_control",
    "broken_object_level_authorization": "access_control",
    "missing_authorization": "access_control",
    "missing_authentication": "access_control",
    "unauthenticated_management_endpoint": "access_control",
    "information_disclosure": "information_disclosure",
    "session_management": "session_management",
    "cleartext_transmission": "cleartext_transmission",
    "active_vulnerability": "active_vulnerability",
    "potential_path_traversal": "path_traversal",
}

#: The canonical class of a CWE.
CWE_CLASSES = {
    "16": "security_misconfiguration",
    "22": "path_traversal",
    "73": "path_traversal",
    "78": "command_injection",
    "77": "command_injection",
    "79": "xss",
    "89": "sql_injection",
    "94": "xxe",
    "113": "xxe",
    "20": "information_disclosure",
    "125": "information_disclosure",
    "190": "information_disclosure",
    "200": "information_disclosure",
    "266": "information_disclosure",
    "284": "access_control",
    "285": "access_control",
    "306": "access_control",
    "521": "security_misconfiguration",
    "1236": "security_misconfiguration",
    "1321": "security_misconfiguration",
    "209": "information_disclosure",
    "215": "information_disclosure",
    "311": "security_misconfiguration",
    "319": "cleartext_transmission",
    "326": "weak_crypto",
    "327": "weak_crypto",
    "352": "csrf",
    "400": "dos",
    "434": "command_injection",
    "502": "insecure_deserialization",
    "522": "information_disclosure",
    "532": "information_disclosure",
    "538": "information_disclosure",
    "598": "information_disclosure",
    "601": "open_redirect",
    "611": "xxe",
    "614": "security_misconfiguration",
    "639": "access_control",
    "693": "security_misconfiguration",
    "732": "access_control",
    "798": "weak_crypto",
    "862": "access_control",
    "863": "access_control",
    "917": "ssti",
    "918": "ssrf",
    "943": "sql_injection",
    "1004": "session_management",
    "1021": "security_misconfiguration",
    "1275": "security_misconfiguration",
    "1322": "security_misconfiguration",
    "1336": "ssti",
}

#: The phrases that name a class when there is no CWE in the text.
_KEYWORDS = (
    ("sql injection", "sql_injection"),
    ("nosql injection", "sql_injection"),
    ("sqli", "sql_injection"),
    ("cross site scripting", "xss"),
    ("cross-site scripting", "xss"),
    ("xss", "xss"),
    ("server side request forgery", "ssrf"),
    ("server-side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("cross site request forgery", "csrf"),
    ("cross-site request forgery", "csrf"),
    ("csrf", "csrf"),
    ("idor", "access_control"),
    ("bola", "access_control"),
    ("broken object level authorization", "access_control"),
    ("broken access control", "access_control"),
    ("missing authorization", "access_control"),
    ("missing authentication", "access_control"),
    ("unauthenticated management endpoint", "access_control"),
    ("command injection", "command_injection"),
    ("os command injection", "command_injection"),
    ("template injection", "ssti"),
    ("server side template injection", "ssti"),
    ("ssti", "ssti"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("information disclosure", "information_disclosure"),
    ("sensitive information", "information_disclosure"),
    ("information exposure", "information_disclosure"),
    ("verbose error", "information_disclosure"),
    ("credential exposure", "information_disclosure"),
    ("session management", "session_management"),
    ("cleartext", "cleartext_transmission"),
    ("missing security header", "security_misconfiguration"),
    ("security misconfiguration", "security_misconfiguration"),
    ("misconfiguration", "security_misconfiguration"),
    ("csrf protection", "security_misconfiguration"),
    ("javascript", "javascript_analysis"),
    ("graphql", "graphql"),
    ("insecure deserialization", "insecure_deserialization"),
    ("xxe", "xxe"),
    ("weak crypto", "weak_crypto"),
    ("open redirect", "open_redirect"),
)

#: The words that mean the class names a hypothesis.
_CANDIDATE_MARKERS = (
    "candidate",
    "suspected",
    "possible",
    "potential_",
    "injection_candidate",
    "access_control_candidate",
)

#: The words that mean the assessment itself was blocked.
_BLOCKED_MARKERS = (
    "inconclusive",
    "assessment blocked",
    "assessment could not",
    "could not be assessed",
    "was blocked",
)

_CWE = re.compile(r"cwe[-_ ]?(\d{1,4})", re.IGNORECASE)
_TOKEN = re.compile(r"[a-z0-9_]+")


def _spaced(text: str) -> str:
    """The text with its separators as spaces.

    A class is written every way — ``"security_misconfiguration"``,
    ``"security-misconfiguration"`` and ``"Security Misconfiguration"``
    are the same class — and the phrases that name a class have to be
    found in any of them.
    """
    return text.replace("_", " ").replace("-", " ")


def normalise_vuln_class(raw: str) -> str:
    """The canonical class of a finding.

    The order matters: an exact name wins, then a name that appears in
    the text, then a CWE, then a keyword.  The text is searched in the
    order it is written, so a class that names two things leads with the
    first — ``"ssrf / path_traversal"`` is an SSRF.
    """
    text = (raw or "").strip()
    if not text:
        return "unknown"

    lowered = text.lower()

    # 1. The class is already one of ours.
    if lowered in CANONICAL_CLASSES:
        return lowered

    # 2. A class of the platform's own appears in the text, or a word
    # that names one.
    for match in _TOKEN.finditer(lowered):
        token = match.group(0)
        if token in CANONICAL_CLASSES:
            return token
        if token in _SYNONYMS:
            return _SYNONYMS[token]

    # 3. Something the platform notes rather than a vulnerability.  It
    # comes before the CWE because a class that says "untested" is
    # about the assessment, not about the weakness it names.
    for phrase, canonical in _NOTE_CLASSES.items():
        if phrase in lowered:
            return canonical

    # 3a. A class that names a candidate is a hypothesis, not a
    # finding.  The agent roles report what they suspect as well as
    # what they proved, and the two must not land in the same group.
    for marker in _CANDIDATE_MARKERS:
        if marker in lowered:
            return "note"

    # 3b. An assessment that could not be carried out is a gap in the
    # coverage, not a vulnerability.
    for marker in _BLOCKED_MARKERS:
        if marker in lowered:
            return "coverage_gap"

    # 4. A CWE in the text.  It comes before the phrases: a class that
    # names a CWE is that weakness, whatever it goes on to mention.
    for cwe in _CWE.findall(lowered):
        if cwe in CWE_CLASSES:
            return CWE_CLASSES[cwe]

    # 5. A phrase that names a class.  The first one the text names
    # wins: "exposure of sensitive information" is an information
    # disclosure even when the text goes on to mention an endpoint.
    best: tuple[int, str] | None = None
    spaced = _spaced(lowered)
    for phrase, canonical in _KEYWORDS:
        position = spaced.find(phrase)
        if position < 0:
            continue
        if best is None or position < best[0]:
            best = (position, canonical)
    if best is not None:
        # A phrase that the text names before its first CWE is the
        # class the text leads with; a CWE before it wins.
        first_cwe = _CWE.search(lowered)
        if first_cwe is not None and first_cwe.start() < best[0]:
            for cwe in _CWE.findall(lowered):
                if cwe in CWE_CLASSES:
                    return CWE_CLASSES[cwe]
        return best[1]

    # 6. Nothing matched: the text becomes the class, cleaned.
    return "_".join(_TOKEN.findall(lowered)).strip("_") or "unknown"


def class_aliases(raw: str) -> tuple[str, ...]:
    """The canonical classes a free-text class names.

    A class that names two things — ``"security_misconfiguration /
    information_disclosure"`` — names both.  The first is the primary
    one; the others are the aliases, and they let a query for either
    find the finding.
    """
    text = (raw or "").strip().lower()
    if not text:
        return ()
    if text in CANONICAL_CLASSES:
        return (text,)
    found: list[str] = []
    for cwe in _CWE.findall(text):
        canonical = CWE_CLASSES.get(cwe)
        if canonical and canonical not in found:
            found.append(canonical)
    for match in _TOKEN.finditer(text):
        token = match.group(0)
        canonical = token if token in CANONICAL_CLASSES else _SYNONYMS.get(token, "")
        if canonical and canonical not in found:
            found.append(canonical)
    for phrase, canonical in _KEYWORDS:
        if phrase in _spaced(text) and canonical not in found:
            found.append(canonical)
    return tuple(found)


def primary_class(raw: str) -> str:
    """The class of a finding, and the aliases it also names."""
    aliases = class_aliases(raw)
    if aliases:
        return aliases[0]
    return normalise_vuln_class(raw)
