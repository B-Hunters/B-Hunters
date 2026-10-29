"""Normalisation and classification of the URLs a scan discovers.

Every URL that enters the asset inventory passes through
:func:`normalise_url`, so that the same resource is one row however it
was discovered, and through :func:`classify`, so that the inventory can
be grouped by what the URL serves.

The rules live here rather than in the adapters that find the URLs, so
that the crawler, the worker output and the merge step all classify a
URL the same way.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .security.scope import ScopePolicy

#: The kinds of asset the inventory knows.
ASSET_KINDS: tuple[str, ...] = ("page", "js", "image", "css", "api", "other")

#: The value that replaces a credential.
REDACTED = "[REDACTED]"

#: Query parameters whose value is a credential and must never be stored.
CREDENTIAL_PARAM_RE = re.compile(
    r"(?i)(token|key|secret|password|passwd|pwd|auth|session|signature|sig|access_token|api_key)"
)

#: The port each scheme implies, and therefore does not need to be written.
DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

#: What a response content type says the asset is.
CONTENT_TYPE_KINDS: dict[str, str] = {
    "text/html": "page",
    "application/javascript": "js",
    "text/javascript": "js",
    "application/x-javascript": "js",
    "text/css": "css",
    "application/json": "api",
    "application/xml": "api",
    "text/xml": "api",
}

#: What a file extension says the asset is.
EXTENSION_KINDS: dict[str, str] = {
    "js": "js",
    "mjs": "js",
    "css": "css",
    "png": "image",
    "jpg": "image",
    "jpeg": "image",
    "gif": "image",
    "svg": "image",
    "webp": "image",
    "ico": "image",
    "bmp": "image",
    "json": "api",
    "xml": "api",
    "html": "page",
    "htm": "page",
}


def normalise_url(url: str) -> str:
    """Return the canonical form of *url*.

    The scheme and the host are lower-cased, the default port of the
    scheme is dropped, the path is normalised, the fragment is dropped
    and the query is sorted with its credential-shaped values redacted.

    The userinfo is dropped: it can carry a password, and a credential
    must never reach the inventory.
    """
    text = (url or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return text

    scheme = (parts.scheme or "").lower()
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        # A malformed host or port: keep the URL as it was given.
        return text

    return urlunsplit(
        (
            scheme,
            _netloc(host, port, scheme),
            _normalise_path(parts.path),
            _sorted_query(parts.query),
            "",
        )
    )


def redact_query(query: str) -> str:
    """Replace the value of every credential-shaped parameter.

    The name of the parameter is kept, so that the URL still says which
    parameter carried the credential, but the value never reaches the
    inventory.
    """
    if not query:
        return ""
    return urlencode(
        [
            (name, REDACTED if CREDENTIAL_PARAM_RE.search(name) else value)
            for name, value in parse_qsl(query, keep_blank_values=True)
        ],
        safe="[]",
    )


def classify(*, content_type: str = "", url: str = "", path: str = "") -> str:
    """Return what the asset at *url* is.

    The content type of the response wins, because it is what the
    server actually serves.  A URL that was never fetched is classified
    by its extension, and a URL with neither is classified by its path.
    """
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if media:
        if media.startswith("image/"):
            return "image"
        return CONTENT_TYPE_KINDS.get(media, "other")

    kind = EXTENSION_KINDS.get(extension_of(url))
    if kind:
        return kind

    target = (path or _path_of(url)).lower()
    if "/api/" in target or "/graphql" in target:
        return "api"
    return "other"


def extension_of(url: str) -> str:
    """Return the lower-cased file extension of *url*, without the dot."""
    segment = _path_of(url).rsplit("/", 1)[-1]
    if "." not in segment:
        return ""
    candidate = segment.rsplit(".", 1)[-1].lower()
    if not 1 <= len(candidate) <= 10:
        return ""
    if not candidate.isalnum():
        return ""
    return candidate


def is_external(url: str, authorized_hosts: Sequence[str]) -> bool:
    """Return ``True`` when the host of *url* is not covered by the scope.

    The host is matched with the platform's own rule
    (:meth:`ScopePolicy.matches_host`), so a ``*.example.com`` wildcard
    and the denied-host list behave here exactly as they behave when a
    request is made.
    """
    try:
        host = urlsplit(url or "").hostname or ""
    except ValueError:
        host = ""
    policy = ScopePolicy(authorized_hosts=tuple(str(host) for host in authorized_hosts))
    return not policy.matches_host(host)


def _netloc(host: str, port: int | None, scheme: str) -> str:
    """Rebuild the network location of a URL from its parts."""
    if not host:
        return ""
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"
    return netloc


def _normalise_path(path: str) -> str:
    """Return the path of a URL without its empty and dot segments."""
    if not path:
        return "/"
    if not path.startswith("/"):
        path = f"/{path}"
    trailing = path.endswith("/")
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    normalised = "/" + "/".join(segments)
    if trailing and not normalised.endswith("/"):
        normalised = f"{normalised}/"
    return normalised


def _sorted_query(query: str) -> str:
    """Return the query with its parameters sorted and its credentials redacted."""
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    pairs.sort(key=lambda pair: pair[0])
    return urlencode(
        [(name, REDACTED if CREDENTIAL_PARAM_RE.search(name) else value) for name, value in pairs],
        safe="[]",
    )


def _path_of(url: str) -> str:
    """Return the path of *url*, which may be a URL or a bare path."""
    try:
        return urlsplit(url or "").path
    except ValueError:
        return ""
