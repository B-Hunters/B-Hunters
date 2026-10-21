"""Content parsing tools: JavaScript, HTML, JSON, XML, OpenAPI and GraphQL.

The JavaScript analyser is a static, dependency-free analyser.  It extracts
the artefacts an API-focused agent needs - routes, HTTP methods, parameter
names, GraphQL operations, source map references and authentication
related logic - and separates *public configuration* from *credentials*.

Content fetched from a target is untrusted input.  Nothing in this module
executes the analysed content, and any instruction-like text found inside it
is treated as data, never as a command.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...security.redact import redact_text
from ..gateway import ToolContext, ToolError

# ----------------------------------------------------------------------
# JavaScript
# ----------------------------------------------------------------------
_STRING_RE = re.compile(r"""(?P<q>['"`])(?P<body>(?:\\.|(?!(?P=q))[^\\])*)(?P=q)""", re.S)
_JS_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)

_ABSOLUTE_PATH_RE = re.compile(
    r"""['"`](/(?:api|v\d|rest|rpc|graphql|gql|auth|oauth|admin|internal|user|account|search|upload|download)[A-Za-z0-9_\-./{}:$]*)['"`]""",
    re.I,
)
_ANY_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./{}:$]{2,120})['"`]""")
_FULL_URL_RE = re.compile(r"""['"`](https?://[A-Za-z0-9._\-]+(?::\d+)?/[A-Za-z0-9_\-./{}:$?=&%]*)['"`]""")

_METHOD_RE = re.compile(
    r"""\b(?:fetch|axios|ajax|request|http|client)\s*(?:\.\s*)?(?:\(\s*[^)]*?\)\s*,\s*)?[\{\(]?\s*['"]?(get|post|put|patch|delete|head|options)['"]?""",
    re.I,
)
_AXIOS_METHOD_RE = re.compile(r"""\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\b""", re.I)
_FETCH_METHOD_RE = re.compile(
    r"""fetch\s*\(\s*[^,)]{1,200}?,\s*\{[^}]{0,400}?method\s*:\s*['"]([A-Za-z]+)['"]""",
    re.I | re.S,
)
_PARAM_KEY_RE = re.compile(
    r"""\b(?:params|query|data|body|form|searchParams)\b\s*[:=]\s*\{([^}]{1,600})\}""",
    re.I | re.S,
)
_QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{0,40})=")
_URL_TEMPLATE_RE = re.compile(r"""\$\{[^}]{1,80}\}""")
_GRAPHQL_RE = re.compile(r"""(?:gql|graphql)\s*`([^`]{1,8000})`""", re.I | re.S)
_GRAPHQL_OP_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?", re.I)
_SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s'"]+)""")
_AUTH_TOKENS = (
    "authorization",
    "bearer",
    "jwt",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "x-auth-token",
    "session",
    "csrf",
    "xsrf",
    "login",
    "logout",
    "signup",
    "signin",
    "oauth",
    "client_secret",
    "private_key",
)
_STORAGE_RE = re.compile(
    r"""(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*['"]([A-Za-z0-9_\-]{2,64})['"]""",
)
_COOKIE_RE = re.compile(
    r"""document\.cookie\s*=|cookie\s*\.\s*set\s*\(\s*['"]([A-Za-z0-9_\-]{2,64})['"]""", re.I
)

#: Configuration keys that are *normally* public and must not be reported
#: as credential leaks on their own.
PUBLIC_CONFIG_KEYS = frozenset(
    {
        "apiurl",
        "apibaseurl",
        "baseurl",
        "base_url",
        "host",
        "hostname",
        "endpoint",
        "env",
        "environment",
        "version",
        "build",
        "commit",
        "locale",
        "lang",
        "language",
        "theme",
        "darkmode",
        "debug",
        "features",
        "flags",
        "cdn",
        "assets",
        "publickey",
        "public_key",
        "clientid",
        "client_id",
        "appid",
        "app_id",
        "siteurl",
        "site_url",
        "graphqlurl",
        "graphql_url",
        "wsurl",
        "wssurl",
        "sentrydsn",
        "gtm",
        "gaid",
        "logourl",
        "api_base",
        "apibase",
        "base",
        "base_uri",
        "server",
        "serverurl",
    }
)

#: Key suffixes that indicate public configuration rather than a credential.
PUBLIC_CONFIG_SUFFIXES = (
    "_url",
    "_uri",
    "_endpoint",
    "_base",
    "_host",
    "_cdn",
    "_origin",
    "_prefix",
)

#: Keys whose value is very likely a credential.
CREDENTIAL_KEY_RE = re.compile(
    r"(?i)(secret|password|passwd|pwd|private_key|privatekey|client_secret|"
    r"api_key|apikey|access_key|secret_key|auth_token|bearer_token|"
    r"signing_key|encryption_key|master_key|session_secret|salt)"
)

_ASSIGNMENT_RE = re.compile(
    r"""(?P<key>[A-Za-z_$][A-Za-z0-9_$]{1,60})\s*[:=]\s*(?P<q>['"`])(?P<value>[^'"`\n]{4,200})(?P=q)"""
)

#: Value shapes that identify a credential regardless of the variable name.
#: A key called ``AWS_KEY`` holding an ``AKIA...`` value is a credential even
#: though "aws_key" is not itself a sensitive-looking name.
_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"^(?:AKIA|ASIA)[0-9A-Z]{16}$"),
    re.compile(r"^gh[pousr]_[A-Za-z0-9]{16,}$"),
    re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
    re.compile(r"^(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}$"),
    re.compile(r"^AIza[0-9A-Za-z_\-]{30,}$"),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
)


def _looks_like_credential_value(value: str) -> bool:
    """Return ``True`` when the value itself has a credential shape."""
    candidate = value.strip()
    return any(pattern.match(candidate) for pattern in _CREDENTIAL_VALUE_PATTERNS)


def _strip_comments(source: str) -> str:
    """Remove JavaScript comments without corrupting string literals.

    A naive ``//`` stripper treats the ``//`` in ``https://example.com``
    as the start of a comment and silently destroys the rest of the line,
    which hides real routes and API paths.  This implementation walks the
    source and only removes comments that are outside a string literal.
    """
    out: list[str] = []
    index = 0
    length = len(source)
    quote = ""
    while index < length:
        char = source[index]
        if quote:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(source[index + 1])
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "'\"`":
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < length:
            following = source[index + 1]
            if following == "/":
                end = source.find("\n", index)
                index = length if end == -1 else end
                continue
            if following == "*":
                end = source.find("*/", index + 2)
                index = length if end == -1 else end + 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


def analyze_javascript(source: str, *, url: str = "") -> dict[str, Any]:
    """Extract routes, methods, parameters and security-relevant hints from JS."""
    if not source:
        return {"url": url, "size_bytes": 0, "error": "empty source"}

    stripped = _strip_comments(source)
    raw_strings = [m.group("body") for m in _STRING_RE.finditer(stripped)]

    # --- routes ------------------------------------------------------
    routes: set[str] = set()
    for match in _ABSOLUTE_PATH_RE.finditer(stripped):
        routes.add(match.group(1))
    for match in _ANY_PATH_RE.finditer(stripped):
        candidate = match.group(1)
        if len(candidate) > 2 and not candidate.startswith("//"):
            routes.add(candidate)
    absolute_urls: set[str] = set()
    for match in _FULL_URL_RE.finditer(stripped):
        absolute_urls.add(match.group(1))

    # --- HTTP methods -------------------------------------------------
    methods: set[str] = set()
    for match in _AXIOS_METHOD_RE.finditer(stripped):
        methods.add(match.group(1).upper())
    for match in _FETCH_METHOD_RE.finditer(stripped):
        methods.add(match.group(1).upper())
    for match in _METHOD_RE.finditer(stripped):
        candidate = match.group(1).upper()
        if candidate in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            methods.add(candidate)

    # --- parameters ----------------------------------------------------
    parameters: set[str] = set()
    for key_match in _PARAM_KEY_RE.finditer(stripped):
        block = key_match.group(1)
        for key in re.finditer(r"([A-Za-z_$][A-Za-z0-9_$]{0,40})\s*:", block):
            parameters.add(key.group(1))
    for match in _QUERY_PARAM_RE.finditer(stripped):
        parameters.add(match.group(1))
    for match in _URL_TEMPLATE_RE.finditer(stripped):
        parameters.add(f"template:{match.group(0)}")

    # --- GraphQL --------------------------------------------------------
    graphql_ops: list[dict[str, str]] = []
    for match in _GRAPHQL_RE.finditer(stripped):
        body = match.group(1)
        op = _GRAPHQL_OP_RE.search(body)
        graphql_ops.append(
            {
                "operation": op.group(1).lower() if op else "anonymous",
                "name": op.group(2) if op and op.group(2) else "",
                "length": str(len(body)),
            }
        )
    for _graphql_ref in re.finditer(r"/graphql\b", stripped):
        routes.add("/graphql")

    # --- source maps ------------------------------------------------------
    sourcemaps = [m.group(1) for m in _SOURCEMAP_RE.finditer(source)]

    # --- auth-related logic ------------------------------------------------
    lowered = stripped.lower()
    auth_signals = sorted({token for token in _AUTH_TOKENS if token in lowered})
    storage_keys = sorted({m.group(1) for m in _STORAGE_RE.finditer(stripped)})
    cookie_names = sorted({m.group(1) for m in _COOKIE_RE.finditer(stripped)})

    # --- hardcoded values, classified -----------------------------------------
    secrets: list[dict[str, Any]] = []
    public_config: list[dict[str, Any]] = []
    for match in _ASSIGNMENT_RE.finditer(stripped):
        key = match.group("key")
        value = match.group("value")
        normalized = key.lower().replace("-", "_")
        entry = {
            "key": key,
            "line_hint": stripped[: match.start()].count("\n") + 1,
            "value_preview": redact_text(value[:8] + "…") if len(value) > 8 else "***",
        }
        if CREDENTIAL_KEY_RE.search(key) or _looks_like_credential_value(value):
            secrets.append(entry)
        elif normalized in PUBLIC_CONFIG_KEYS or normalized.endswith(PUBLIC_CONFIG_SUFFIXES):
            public_config.append(entry)

    return {
        "url": url,
        "size_bytes": len(source),
        "routes": sorted(routes)[:400],
        "route_count": len(routes),
        "absolute_urls": sorted(absolute_urls)[:200],
        "http_methods": sorted(methods),
        "parameters": sorted(parameters)[:400],
        "parameter_count": len(parameters),
        "graphql_operations": graphql_ops[:50],
        "source_maps": sourcemaps[:20],
        "auth_signals": auth_signals,
        "storage_keys": storage_keys[:50],
        "cookie_names": cookie_names[:50],
        "credential_candidates": secrets[:50],
        "public_config": public_config[:50],
        "string_literal_count": len(raw_strings),
    }


# ----------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------
_FORM_RE = re.compile(r"<form\b([^>]*)>", re.I)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r"""(\w[\w:-]*)\s*=\s*(?P<q>['"])(.*?)(?P=q)""", re.S)
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*(['"])(.*?)\1""", re.I)
_LINK_HREF_RE = re.compile(r"""<a\b[^>]*\bhref\s*=\s*(['"])(.*?)\1""", re.I)
_META_RE = re.compile(r"""<meta\b([^>]*)>""", re.I)


def analyze_html(source: str, *, url: str = "") -> dict[str, Any]:
    """Extract forms, inputs, scripts and links from an HTML document."""
    forms: list[dict[str, Any]] = []
    for match in _FORM_RE.finditer(source):
        attrs = {m.group(1).lower(): m.group(3) for m in _ATTR_RE.finditer(match.group(1))}
        forms.append(
            {
                "action": attrs.get("action", ""),
                "method": (attrs.get("method", "get") or "get").lower(),
                "id": attrs.get("id", ""),
                "name": attrs.get("name", ""),
                "enctype": attrs.get("enctype", ""),
            }
        )

    inputs: list[dict[str, Any]] = []
    for match in _INPUT_RE.finditer(source):
        attrs = {m.group(1).lower(): m.group(3) for m in _ATTR_RE.finditer(match.group(1))}
        inputs.append(
            {
                "name": attrs.get("name", ""),
                "type": (attrs.get("type", "text") or "text").lower(),
                "id": attrs.get("id", ""),
                "value_present": "value" in attrs,
                "autocomplete": attrs.get("autocomplete", ""),
            }
        )

    scripts = [m.group(2) for m in _SCRIPT_SRC_RE.finditer(source)]
    links = [m.group(2) for m in _LINK_HREF_RE.finditer(source)]
    metas = []
    for match in _META_RE.finditer(source):
        attrs = {m.group(1).lower(): m.group(3) for m in _ATTR_RE.finditer(match.group(1))}
        if attrs.get("name") or attrs.get("http-equiv"):
            metas.append(attrs)

    return {
        "url": url,
        "forms": forms,
        "form_count": len(forms),
        "inputs": inputs,
        "input_count": len(inputs),
        "scripts": scripts[:100],
        "script_count": len(scripts),
        "links": links[:200],
        "meta": metas[:30],
    }


# ----------------------------------------------------------------------
# OpenAPI / GraphQL
# ----------------------------------------------------------------------
def analyze_openapi(source: str) -> dict[str, Any]:
    """Summarise an OpenAPI/Swagger document."""
    try:
        document = json.loads(source)
    except ValueError as exc:
        raise ToolError(f"the OpenAPI document is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ToolError("the OpenAPI document must be a JSON object")

    version = str(document.get("openapi") or document.get("swagger") or "")
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    servers = []
    for server in document.get("servers") or []:
        if isinstance(server, dict) and server.get("url"):
            servers.append(str(server["url"]))

    paths = document.get("paths") or {}
    operations: list[dict[str, Any]] = []
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            operation = operation if isinstance(operation, dict) else {}
            operation_id = operation.get("operationId", "")
            parameters = []
            for parameter in operation.get("parameters") or []:
                if isinstance(parameter, dict):
                    parameters.append(parameter.get("name", ""))
            body_schema = ""
            content = operation.get("requestBody") or {}
            if isinstance(content, dict):
                for media_type, media in (content.get("content") or {}).items():
                    if isinstance(media, dict) and "schema" in media:
                        body_schema = media_type
                        break
            operations.append(
                {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation_id,
                    "summary": operation.get("summary", ""),
                    "parameters": [p for p in parameters if p],
                    "request_content_type": body_schema,
                    "security": bool(operation.get("security")),
                }
            )

    components = document.get("components") or {}
    schemas = list((components.get("schemas") or {}).keys()) if isinstance(components, dict) else []
    security_schemes = (
        list((components.get("securitySchemes") or {}).keys()) if isinstance(components, dict) else []
    )

    return {
        "openapi_version": version,
        "title": info.get("title", "") if isinstance(info, dict) else "",
        "version": info.get("version", "") if isinstance(info, dict) else "",
        "servers": servers,
        "operations": operations,
        "operation_count": len(operations),
        "schema_names": schemas[:200],
        "security_schemes": security_schemes,
    }


def analyze_graphql_schema(source: str) -> dict[str, Any]:
    """Summarise a GraphQL introspection document."""
    try:
        document = json.loads(source)
    except ValueError as exc:
        raise ToolError(f"the GraphQL document is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ToolError("the GraphQL document must be a JSON object")

    schema = document.get("data", {}).get("__schema") or document.get("__schema") or {}
    types = schema.get("types") or []
    type_names: list[str] = []
    queries: list[str] = []
    mutations: list[str] = []
    for entry in types:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        if name and not name.startswith("__"):
            type_names.append(name)
        if entry.get("name") == "Query":
            queries = _graphql_field_names(entry)
        if entry.get("name") == "Mutation":
            mutations = _graphql_field_names(entry)
    directives = [d.get("name", "") for d in schema.get("directives") or [] if isinstance(d, dict)]
    return {
        "type_count": len(type_names),
        "types": sorted(type_names)[:300],
        "query_fields": queries,
        "mutation_fields": mutations,
        "directives": directives[:50],
    }


def _graphql_field_names(entry: dict[str, Any]) -> list[str]:
    names = []
    for field in entry.get("fields") or []:
        if isinstance(field, dict) and field.get("name"):
            names.append(str(field["name"]))
    return names


# ----------------------------------------------------------------------
# Tool entry points
# ----------------------------------------------------------------------
ANALYZE_JS_SCHEMA = {
    "type": "object",
    "properties": {
        "source": {"type": "string", "description": "JavaScript source to analyse."},
        "url": {"type": "string", "default": "", "description": "Origin URL of the asset."},
        "max_chars": {"type": "integer", "default": 2_000_000},
    },
    "required": ["source"],
    "additionalProperties": False,
}


def analyze_javascript_tool(
    source: str,
    url: str = "",
    max_chars: int = 2_000_000,
    *,
    context: ToolContext | None = None,
) -> dict[str, Any]:
    """Static analysis of a JavaScript asset."""
    if len(source) > max_chars:
        source = source[:max_chars]
    return analyze_javascript(source, url=url)


ANALYZE_HTML_SCHEMA = {
    "type": "object",
    "properties": {
        "source": {"type": "string"},
        "url": {"type": "string", "default": ""},
    },
    "required": ["source"],
    "additionalProperties": False,
}


def analyze_html_tool(source: str, url: str = "", *, context: ToolContext | None = None) -> dict[str, Any]:
    """Extract forms, inputs and assets from an HTML document."""
    return analyze_html(source, url=url)


PARSE_DOCUMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "source": {"type": "string"},
        "format": {
            "type": "string",
            "enum": ["auto", "html", "json", "openapi", "graphql", "xml"],
            "default": "auto",
        },
        "url": {"type": "string", "default": ""},
    },
    "required": ["source"],
    "additionalProperties": False,
}


def parse_document(
    source: str,
    format: str = "auto",
    url: str = "",
    *,
    context: ToolContext | None = None,
) -> dict[str, Any]:
    """Parse an arbitrary document into a structured summary."""
    chosen = (format or "auto").lower()
    if chosen == "auto":
        text = source.lstrip()
        if text.startswith("{") and '"__schema"' in text[:5000]:
            chosen = "graphql"
        elif text.startswith("{") and ('"openapi"' in text[:5000] or '"swagger"' in text[:5000]):
            chosen = "openapi"
        elif text.startswith("<"):
            chosen = "html" if not text.startswith("<?xml") else "xml"
        else:
            chosen = "json" if text.startswith(("{", "[")) else "text"

    if chosen == "html":
        return {"format": "html", **analyze_html(source, url=url)}
    if chosen == "openapi":
        return {"format": "openapi", **analyze_openapi(source)}
    if chosen == "graphql":
        return {"format": "graphql", **analyze_graphql_schema(source)}
    if chosen == "json":
        try:
            parsed = json.loads(source)
        except ValueError as exc:
            raise ToolError(f"the document is not valid JSON: {exc}") from exc
        return {"format": "json", "keys": _json_keys(parsed), "size": len(source)}
    if chosen == "xml":
        return {
            "format": "xml",
            "size": len(source),
            "tags": sorted(set(re.findall(r"<([A-Za-z_][\w\-]*)", source)))[:100],
        }
    return {"format": "text", "size": len(source), "preview": source[:2000]}


def _json_keys(value: Any, prefix: str = "", depth: int = 0) -> list[str]:
    keys: list[str] = []
    if depth > 6:
        return keys
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            keys.append(path)
            keys.extend(_json_keys(item, path, depth + 1))
    elif isinstance(value, list):
        for item in value[:20]:
            keys.extend(_json_keys(item, prefix, depth + 1))
    return keys[:500]
