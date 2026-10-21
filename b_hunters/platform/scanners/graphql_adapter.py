"""The GraphQL analysis adapter.

Three deterministic checks are performed against a GraphQL endpoint:

1. **Introspection** - is the schema exposed?
2. **Unauthenticated data exposure** - do query fields that return user
   records answer without a token?
3. **Error-based information disclosure** - do malformed arguments leak
   database errors, which is how a SQL injection is often confirmed?

The checks are read-only and bounded: a handful of small queries against
the endpoint that the operator authorised.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from ..security.scope import ScopeEnforcer
from .base import ScanRequest, ScanResult

log = logging.getLogger(__name__)

#: The introspection query.  It requests the field lists, because a query
#: that only asks for type names cannot tell whether the schema exposes
#: destructive mutations.
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
    directives { name }
  }
}
"""

#: Query fields that commonly return user records or audit trails.
SENSITIVE_QUERY_FIELDS = ("users", "audits", "me", "accounts", "tokens", "sessions")

#: Mutation fields that destroy or modify state.
DESTRUCTIVE_MUTATION_FIELDS = (
    "deleteallpastes",
    "deletepastes",
    "deletepaste",
    "deleterevision",
    "deleteuser",
    "deleteallusers",
    "dropdatabase",
    "resetdatabase",
)

#: Signatures of a database error leaking through an error message.
DATABASE_ERROR_PATTERNS = (
    re.compile(r"sqlite3\.\w*Error", re.I),
    re.compile(r"OperationalError", re.I),
    re.compile(r"ProgrammingError", re.I),
    re.compile(r"\bSQL:\s*SELECT\b", re.I),
    re.compile(r"\bSQL:\s*(?:INSERT|UPDATE|DELETE)\b", re.I),
    re.compile(r"unrecognized token", re.I),
    re.compile(r"You have an error in your SQL syntax", re.I),
    re.compile(r"psycopg2\.\w*Error", re.I),
    re.compile(r"pymysql\.\w*Error", re.I),
    re.compile(r"ORA-\d{5}", re.I),
)

GRAPHQL_PATHS = ("/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/gql")


def _fields_of(schema: dict[str, Any], type_name: str) -> list[str]:
    """Return the field names of one root type in an introspection result."""
    for entry in schema.get("types") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("name") != type_name:
            continue
        names = []
        for field in entry.get("fields") or []:
            if isinstance(field, dict) and field.get("name"):
                names.append(str(field["name"]))
        return names
    return []


def _arguments_of(schema: dict[str, Any], type_name: str) -> dict[str, list[str]]:
    """Return ``{field_name: [argument names]}`` for one root type.

    The adapter needs the argument names so that it probes the arguments
    that actually exist rather than guessing at them.
    """
    arguments: dict[str, list[str]] = {}
    for entry in schema.get("types") or []:
        if not isinstance(entry, dict) or entry.get("name") != type_name:
            continue
        for field in entry.get("fields") or []:
            if not isinstance(field, dict) or not field.get("name"):
                continue
            names = []
            for argument in field.get("args") or []:
                if isinstance(argument, dict) and argument.get("name"):
                    names.append(str(argument["name"]))
            arguments[str(field["name"])] = names
    return arguments


def _root_type_names(schema: dict[str, Any], kind: str) -> str:
    value = schema.get(kind) or {}
    if isinstance(value, dict):
        return str(value.get("name") or "")
    return ""


def record_count(payload: dict[str, Any], field: str) -> int:
    """Count the records a GraphQL field returned."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return 0
    value = data.get(field)
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return 1
    return 0


def detect_database_error(payload: dict[str, Any]) -> tuple[bool, str]:
    """Return ``(leaked, excerpt)`` when the response leaks a database error."""
    text = json.dumps(payload, default=str)
    for pattern in DATABASE_ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 120)
            return True, text[start : match.end() + 320]
    return False, ""


async def _post_graphql(
    client: httpx.AsyncClient, url: str, query: str, variables: dict[str, Any] | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    response = await client.post(url, json=body, headers={"Content-Type": "application/json"})
    try:
        payload = response.json()
    except ValueError:
        payload = {"raw": response.text[:2000]}
    if not isinstance(payload, dict):
        payload = {"raw": str(payload)[:2000]}
    return payload


async def graphql_analysis_executor(request: ScanRequest) -> ScanResult:
    """Introspect a GraphQL endpoint and review what it exposes."""
    scope: Optional[ScopeEnforcer] = request.scope
    items: list[dict[str, Any]] = []

    for target in request.targets:
        base = target if "://" in target else f"https://{target}"
        endpoint = ""
        schema: dict[str, Any] = {}
        reachable = False

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            verify=False,  # noqa: S501
        ) as client:
            for path in GRAPHQL_PATHS:
                url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                try:
                    if scope is not None:
                        decision = scope.evaluate_url(url)
                        if not decision.allowed:
                            continue
                    payload = await _post_graphql(client, url, INTROSPECTION_QUERY)
                except Exception as exc:
                    log.debug("graphql probe failed for %s: %s", url, exc)
                    continue

                introspection = (payload.get("data") or {}).get("__schema")
                if isinstance(introspection, dict):
                    endpoint = url
                    schema = introspection
                    reachable = True
                    break

            findings: list[dict[str, Any]] = []
            query_fields: list[str] = []
            mutation_fields: list[str] = []

            if reachable:
                query_type = _root_type_names(schema, "queryType")
                mutation_type = _root_type_names(schema, "mutationType")
                query_fields = _fields_of(schema, query_type)
                mutation_fields = _fields_of(schema, mutation_type)
                host = urlsplit(endpoint).hostname or ""

                # 1. Introspection is exposed.
                findings.append(
                    {
                        "title": "GraphQL introspection is enabled",
                        "vuln_class": "graphql",
                        "severity": "low",
                        "summary": (
                            "The GraphQL endpoint answers introspection queries, so the entire "
                            "schema - types, fields and directives - is available to any "
                            "unauthenticated client."
                        ),
                        "remediation": (
                            "Disable introspection in production, or gate it behind an "
                            "authenticated, authorised request."
                        ),
                        "host": host,
                        "affected_url": endpoint,
                        "confidence": 0.95,
                        "extra_key": "graphql:introspection",
                        "evidence": [
                            {
                                "kind": "graphql_schema",
                                "excerpt": (
                                    f"__schema queryType={query_type} mutationType={mutation_type} "
                                    f"types={len(schema.get('types') or [])}"
                                ),
                            }
                        ],
                    }
                )

                # 2. Destructive mutations are exposed.
                destructive = [
                    name for name in mutation_fields if name.strip().lower() in DESTRUCTIVE_MUTATION_FIELDS
                ]
                if destructive:
                    findings.append(
                        {
                            "title": "GraphQL exposes destructive mutations",
                            "vuln_class": "graphql",
                            "severity": "medium",
                            "summary": (
                                f"The mutation type exposes {len(destructive)} destructive "
                                f"field(s) ({', '.join(destructive)}); each resolver must be "
                                "checked for authorisation."
                            ),
                            "remediation": (
                                "Require an authenticated session and an explicit authorisation "
                                "check in every mutation resolver."
                            ),
                            "host": host,
                            "affected_url": endpoint,
                            "confidence": 0.7,
                            "extra_key": "graphql:destructive_mutations",
                            "evidence": [
                                {
                                    "kind": "graphql_schema",
                                    "excerpt": f"mutation fields: {', '.join(mutation_fields)}",
                                }
                            ],
                        }
                    )

                # 3. Unauthenticated query fields that return user records.
                exposed = [name for name in query_fields if name.strip().lower() in SENSITIVE_QUERY_FIELDS]
                for name in exposed:
                    probe_query = f"{{ {name} {{ id }} }}"
                    try:
                        probe = await _post_graphql(client, endpoint, probe_query)
                    except Exception as exc:
                        log.debug("graphql data probe failed for %s: %s", endpoint, exc)
                        continue
                    data = probe.get("data") or {}
                    records = data.get(name)
                    if isinstance(records, list) and records:
                        findings.append(
                            {
                                "title": (f"GraphQL field '{name}' returns records without authentication"),
                                "vuln_class": "access_control",
                                "severity": "medium",
                                "summary": (
                                    f"The '{name}' query field returned {len(records)} record(s) "
                                    "to an unauthenticated client."
                                ),
                                "remediation": (
                                    "Require an authenticated session in the resolver and scope the "
                                    "result to the requesting user."
                                ),
                                "host": host,
                                "affected_url": endpoint,
                                "confidence": 0.85,
                                "extra_key": f"graphql:unauthenticated:{name}",
                                "evidence": [
                                    {
                                        "kind": "graphql_response",
                                        "excerpt": f"{{{name}}} -> {len(records)} record(s)",
                                    }
                                ],
                            }
                        )

                # 4. An error that leaks a database error.
                #
                # The argument names come from the introspection result, so
                # the probe targets arguments that actually exist.
                arguments = _arguments_of(schema, query_type)
                for field in query_fields[:8]:
                    candidates = [
                        name for name in arguments.get(field, []) if name not in {"token", "public"}
                    ][:3]
                    for argument in candidates:
                        probe_query = f'{{ {field}({argument}: "bhmarker\' OR 1=1--") {{ id }} }}'
                        try:
                            probe = await _post_graphql(client, endpoint, probe_query)
                        except Exception as exc:
                            log.debug("graphql argument probe failed for %s: %s", endpoint, exc)
                            continue
                        leaked, excerpt = detect_database_error(probe)
                        if not leaked:
                            continue
                        findings.append(
                            {
                                "title": (
                                    f"GraphQL argument '{argument}' of '{field}' leaks a database error"
                                ),
                                "vuln_class": "sql_injection",
                                "severity": "high",
                                "summary": (
                                    f"Supplying a malformed value to the '{argument}' argument of "
                                    f"'{field}' returns a database error containing the generated "
                                    "SQL, which confirms that the argument is concatenated into a "
                                    "query."
                                ),
                                "remediation": (
                                    "Use parameterised queries and return a generic error message "
                                    "to the client."
                                ),
                                "host": host,
                                "affected_url": endpoint,
                                "confidence": 0.8,
                                "extra_key": f"graphql_sql:{field}:{argument}",
                                "evidence": [{"kind": "graphql_error", "excerpt": excerpt[:600]}],
                            }
                        )
                        break
                    else:
                        continue
                    break

                # 5. A boolean-based injection: the argument accepts a
                #    tautology and returns more records than a benign value
                #    does.  This is the common case, and it produces no
                #    error at all, so it needs a differential probe.
                if not any(item.get("vuln_class") == "sql_injection" for item in findings):
                    for field in query_fields[:8]:
                        candidates = [
                            name for name in arguments.get(field, []) if name not in {"token", "public"}
                        ][:3]
                        for argument in candidates:
                            benign_query = f'{{ {field}({argument}: "bhbenignvalue") {{ id }} }}'
                            inject_query = f"{{ {field}({argument}: \"' OR '1'='1\") {{ id }} }}"
                            try:
                                benign = await _post_graphql(client, endpoint, benign_query)
                                injected = await _post_graphql(client, endpoint, inject_query)
                            except Exception as exc:
                                log.debug("graphql differential probe failed for %s: %s", endpoint, exc)
                                continue
                            benign_count = record_count(benign, field)
                            injected_count = record_count(injected, field)
                            if injected_count > benign_count and injected_count > 0:
                                findings.append(
                                    {
                                        "title": (
                                            f"GraphQL argument '{argument}' of '{field}' is "
                                            "vulnerable to boolean-based SQL injection"
                                        ),
                                        "vuln_class": "sql_injection",
                                        "severity": "high",
                                        "summary": (
                                            f"Supplying a tautology to the '{argument}' argument of "
                                            f"'{field}' returned {injected_count} record(s) where a "
                                            f"benign value returned {benign_count}, which confirms "
                                            "that the argument is concatenated into a SQL query."
                                        ),
                                        "remediation": (
                                            "Use parameterised queries and return a generic error "
                                            "message to the client."
                                        ),
                                        "host": host,
                                        "affected_url": endpoint,
                                        "confidence": 0.85,
                                        "extra_key": f"graphql_sql_boolean:{field}:{argument}",
                                        "evidence": [
                                            {
                                                "kind": "graphql_differential",
                                                "excerpt": (
                                                    f"{field}({argument}) benign={benign_count} "
                                                    f"records, tautology={injected_count} records"
                                                ),
                                            }
                                        ],
                                    }
                                )
                                break
                        else:
                            continue
                        break

            items.append(
                {
                    "target": base,
                    "endpoint": endpoint,
                    "reachable": reachable,
                    "query_fields": query_fields,
                    "mutation_fields": mutation_fields,
                    "findings": findings,
                }
            )

    return ScanResult(
        scanner="graphql_analysis",
        ok=True,
        kind="url",
        items=items,
        metadata={"targets_checked": len(request.targets)},
    )
