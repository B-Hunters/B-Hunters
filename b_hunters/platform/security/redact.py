"""Secret redaction helpers.

Every string that leaves the process (logs, API responses, reports, agent
transcripts) passes through :func:`redact` so that credentials discovered
during a scan are not echoed back verbatim.

The redaction is intentionally conservative: it errs towards hiding rather
than towards showing, because a false positive here costs a reviewer a
little time while a false negative leaks a live credential.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[REDACTED]"

#: Header names whose values are always replaced.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-access-token",
        "x-session-token",
        "x-amz-security-token",
        "api-key",
        "apikey",
        "authentication",
        "x-forwarded-authorization",
        "x-bearer-token",
    }
)

#: JSON/INI style keys whose values are always replaced.
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|auth|otp|session[_-]?id|cookie|"
    r"client[_-]?secret|refresh[_-]?token|bearer)\b"
)

#: Inline credential shapes in free text.
_INLINE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Bearer / Basic / custom scheme headers
    re.compile(r"(?i)\b(bearer|basic|digest|token)\s+([A-Za-z0-9._\-+/=]{8,})"),
    # AWS style keys
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(aws_secret_access_key|aws_access_key_id)\s*[:=]\s*\S+"),
    # GitHub / Slack / Stripe / Google style tokens
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}\b"),
    # Private key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # key=value / "key": "value" style pairs with sensitive keys
    re.compile(
        r"(?i)([\"']?(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)[\"']?"
        r"\s*[:=]\s*)"
        r"([\"']?)([^\s\"',;}]{4,})(\2)"
    ),
    # JWT
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)

#: The inline rules applied by :func:`redact_text`, as
#: ``(pattern, replacement)`` pairs.  Keeping the replacement next to its
#: pattern avoids the index arithmetic that previously let a pattern be
#: applied with the wrong replacement.
_INLINE_RULES: tuple[tuple[re.Pattern[str], Any], ...] = (
    # Authorization schemes: keep the scheme, drop the credential.
    (_INLINE_PATTERNS[0], lambda m: f"{m.group(1)} {REDACTED}"),
    # AWS access key id and secret.
    (_INLINE_PATTERNS[1], REDACTED),
    (_INLINE_PATTERNS[2], lambda m: f"{m.group(1)}={REDACTED}"),
    # GitHub, Slack, Stripe, Google and Yahoo tokens.
    (_INLINE_PATTERNS[3], REDACTED),
    (_INLINE_PATTERNS[4], REDACTED),
    (_INLINE_PATTERNS[5], REDACTED),
    (_INLINE_PATTERNS[6], REDACTED),
    (_INLINE_PATTERNS[7], REDACTED),
    # Private key blocks.
    (_INLINE_PATTERNS[8], REDACTED),
    # key=value pairs with a sensitive key: keep the key, drop the value.
    (
        _INLINE_PATTERNS[9],
        lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(4)}",
    ),
    # JSON web tokens.
    (_INLINE_PATTERNS[10], REDACTED),
)

#: Query-string parameters whose values are always replaced.
SENSITIVE_QUERY_PARAMS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "session",
        "sessionid",
        "sid",
        "key",
        "signature",
        "sig",
    }
)


def redact_text(value: str) -> str:
    """Redact credential-looking substrings inside free text."""
    if not value:
        return value
    out = value
    for pattern, replacement in _INLINE_RULES:
        out = pattern.sub(replacement, out)
    return out


def redact_headers(headers: Mapping[str, Any] | Iterable[tuple[str, Any]]) -> dict[str, str]:
    """Return a copy of *headers* with sensitive values replaced."""
    items = headers.items() if isinstance(headers, Mapping) else headers
    result: dict[str, str] = {}
    for name, value in items:
        if str(name).lower() in SENSITIVE_HEADERS:
            result[str(name)] = REDACTED
        else:
            result[str(name)] = redact_text(str(value))
    return result


def redact_mapping(data: Any, _depth: int = 0) -> Any:
    """Recursively redact sensitive keys in dicts/lists."""
    if _depth > 12:
        return data
    if isinstance(data, Mapping):
        out: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(key, str) and SENSITIVE_KEY_PATTERN.search(key):
                out[key] = REDACTED
            else:
                out[key] = redact_mapping(value, _depth + 1)
        return out
    if isinstance(data, (list, tuple)):
        return [redact_mapping(item, _depth + 1) for item in data]
    if isinstance(data, str):
        return redact_text(data)
    return data


def redact_url(url: str) -> str:
    """Redact sensitive query parameters in a URL while keeping it usable."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_text(url)
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    cleaned = [(k, REDACTED if k.lower() in SENSITIVE_QUERY_PARAMS else redact_text(v)) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(cleaned), parts.fragment))


def redact_body(body: str | bytes | None, content_type: str = "") -> str:
    """Redact a request/response body, JSON aware when possible."""
    if body is None:
        return ""
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    if "json" in (content_type or "").lower():
        import json

        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return redact_text(text)
        return json.dumps(redact_mapping(parsed), indent=2, default=str)
    return redact_text(text)
