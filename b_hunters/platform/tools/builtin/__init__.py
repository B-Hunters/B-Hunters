"""Registration of the built-in agent tools."""

from __future__ import annotations

from ..gateway import (
    CAPABILITY_NETWORK,
    CAPABILITY_READ,
    CAPABILITY_SHELL,
    CAPABILITY_WRITE,
    ToolRegistry,
)
from .files import LIST_FILES_SCHEMA, READ_FILE_SCHEMA, WRITE_FILE_SCHEMA, list_files, read_file, write_file
from .http import COMPARE_SCHEMA, HTTP_REQUEST_SCHEMA, compare_responses, http_request
from .parsing import (
    ANALYZE_HTML_SCHEMA,
    ANALYZE_JS_SCHEMA,
    PARSE_DOCUMENT_SCHEMA,
    analyze_html_tool,
    analyze_javascript_tool,
    parse_document,
)
from .scan import (
    LIST_ASSETS_SCHEMA,
    LIST_EVENTS_SCHEMA,
    LIST_FINDINGS_SCHEMA,
    TOOL_HEALTH_SCHEMA,
    list_assets,
    list_events,
    list_findings,
    list_tool_health,
)
from .shell import RUN_COMMAND_SCHEMA, run_command

__all__ = ["build_tool_registry"]


def build_tool_registry() -> ToolRegistry:
    """Build the registry with every built-in tool registered."""
    registry = ToolRegistry()

    registry.register(
        "http_request",
        "Send an HTTP request to an in-scope target and return the response with "
        "headers and body. Redirects are validated hop by hop and the request is "
        "rate limited.",
        HTTP_REQUEST_SCHEMA,
        http_request,
        capabilities={CAPABILITY_NETWORK},
        timeout=45.0,
        safety_note="Only in-scope hosts can be reached; out-of-scope requests are refused.",
    )
    registry.register(
        "compare_responses",
        "Fetch two URLs and compare their status, headers and body to detect "
        "authorisation differences between identities.",
        COMPARE_SCHEMA,
        compare_responses,
        capabilities={CAPABILITY_NETWORK},
        timeout=60.0,
    )
    registry.register(
        "analyze_javascript",
        "Statically analyse a JavaScript asset and extract routes, HTTP methods, "
        "parameter names, GraphQL operations, source maps, authentication logic and "
        "hardcoded credential candidates.",
        ANALYZE_JS_SCHEMA,
        analyze_javascript_tool,
        capabilities={CAPABILITY_READ},
        timeout=60.0,
    )
    registry.register(
        "analyze_html",
        "Extract forms, form inputs, script sources, links and meta tags from an HTML document.",
        ANALYZE_HTML_SCHEMA,
        analyze_html_tool,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "parse_document",
        "Parse a document as HTML, JSON, OpenAPI, GraphQL or XML and return a structured summary.",
        PARSE_DOCUMENT_SCHEMA,
        parse_document,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "read_file",
        "Read a file from your workspace. Paths outside the workspace are refused.",
        READ_FILE_SCHEMA,
        read_file,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "write_file",
        "Write a file into your workspace. Paths outside the workspace are refused.",
        WRITE_FILE_SCHEMA,
        write_file,
        capabilities={CAPABILITY_WRITE},
        timeout=30.0,
    )
    registry.register(
        "list_files",
        "List the files in your workspace.",
        LIST_FILES_SCHEMA,
        list_files,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "run_command",
        "Run an allow-listed command inside your workspace sandbox.",
        RUN_COMMAND_SCHEMA,
        run_command,
        capabilities={CAPABILITY_SHELL},
        timeout=90.0,
        safety_note=(
            "Commands are restricted to an allow-list and run in an isolated sandbox. "
            "Destructive commands, package installation and privilege escalation are refused."
        ),
    )
    registry.register(
        "list_findings",
        "List the findings that have already been recorded for this scan.",
        LIST_FINDINGS_SCHEMA,
        list_findings,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "list_assets",
        "List the assets (URLs, routes, hosts, technologies, JavaScript) discovered for this scan.",
        LIST_ASSETS_SCHEMA,
        list_assets,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "list_events",
        "List recent scan events such as worker output, agent messages and errors.",
        LIST_EVENTS_SCHEMA,
        list_events,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "list_tool_health",
        "Report the health and version of every registered scanner adapter.",
        TOOL_HEALTH_SCHEMA,
        list_tool_health,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    return registry
