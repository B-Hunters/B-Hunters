"""Registration of the built-in agent tools."""

from __future__ import annotations

from ..gateway import (
    CAPABILITY_NETWORK,
    CAPABILITY_READ,
    CAPABILITY_SHELL,
    CAPABILITY_VERIFY,
    CAPABILITY_WRITE,
    ToolRegistry,
)
from .callbacks import (
    CREATE_CALLBACK_SCHEMA,
    LIST_CALLBACKS_SCHEMA,
    create_callback,
    list_callbacks,
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
    RECORD_VERDICT_SCHEMA,
    RECORD_VERDICTS_SCHEMA,
    TOOL_HEALTH_SCHEMA,
    list_assets,
    list_events,
    list_findings,
    list_tool_health,
    record_verdict,
    record_verdicts,
)
from .shell import RUN_COMMAND_SCHEMA, run_command
from .worker_output import (
    LIST_WORKER_OUTPUT_SCHEMA,
    list_worker_output,
)

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
        "create_callback",
        "Create a callback address to watch. Put it in the request you are testing "
        "and then call list_callbacks to see whether the target reached back.",
        CREATE_CALLBACK_SCHEMA,
        create_callback,
        capabilities={CAPABILITY_NETWORK},
        timeout=30.0,
    )
    registry.register(
        "list_callbacks",
        "List the callbacks this scan received. A callback is the target reaching "
        "back: the evidence that a blind finding reproduces.",
        LIST_CALLBACKS_SCHEMA,
        list_callbacks,
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
    registry.register(
        "list_worker_output",
        "List what the scanner workers produced for this scan: the URLs the crawlers "
        "found, the paths the directory scanner found and the secrets the script "
        "scanner read.",
        LIST_WORKER_OUTPUT_SCHEMA,
        list_worker_output,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
    registry.register(
        "record_verdict",
        "Record what the verification established about one finding: a verdict of "
        "confirmed, likely, unverified, inconclusive or rejected, the severity it "
        "supports and a note saying what was done to decide.",
        RECORD_VERDICT_SCHEMA,
        record_verdict,
        capabilities={CAPABILITY_READ, CAPABILITY_VERIFY},
        timeout=30.0,
        safety_note="Only a role that holds the 'verify' capability may record a "
        "verdict, and only for a finding of its own scan.",
    )
    registry.register(
        "record_verdicts",
        "Record what the verification established about many findings at once. Use it "
        "after you have judged the findings: one call per finding leaves a judge with "
        "fifty findings to judge without the budget to record them.",
        RECORD_VERDICTS_SCHEMA,
        record_verdicts,
        capabilities={CAPABILITY_READ, CAPABILITY_VERIFY},
        timeout=60.0,
        safety_note="Only a role that holds the 'verify' capability may record a "
        "verdict, and only for a finding of its own scan.",
    )
    return registry
