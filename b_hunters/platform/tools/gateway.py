"""The agent tool gateway.

Every action an agent takes goes through :meth:`ToolGateway.execute`.
The gateway is the enforcement point - the agent's own instructions are
*not* trusted for this.  It performs, in order:

1. **Tool existence check** - unknown tools are rejected.
2. **Role permission check** - the agent role must be allowed to use the tool.
3. **Policy check** - capabilities such as ``network``, ``shell``,
   ``write_files`` or ``package_install`` must be granted by the policy.
4. **Argument validation** - arguments must satisfy the tool's JSON schema.
5. **Scope enforcement** - network tools must pass every destination through
   :class:`~b_hunters.platform.security.scope.ScopeEnforcer`.
6. **Timeout and output bounds** - the call is time limited and its output is
   truncated.
7. **Auditing** - the call, its outcome and a redacted summary are recorded.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import shlex
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from jsonschema import Draft202012Validator

from ..agents.schemas import Budget
from ..security.redact import redact_mapping, redact_text

log = logging.getLogger(__name__)

#: Capabilities a tool may require.
CAPABILITY_NETWORK = "network"
CAPABILITY_SHELL = "shell"
CAPABILITY_WRITE = "write_files"
CAPABILITY_READ = "read_files"
CAPABILITY_PACKAGE_INSTALL = "package_install"
CAPABILITY_EXTERNAL_DOWNLOAD = "external_download"
CAPABILITY_STATE_CHANGING = "state_changing"
#: Recording what a verification established about a finding.  It is its
#: own capability: a role that may judge a finding may not write files.
CAPABILITY_VERIFY = "verify"

KNOWN_CAPABILITIES = frozenset(
    {
        CAPABILITY_NETWORK,
        CAPABILITY_SHELL,
        CAPABILITY_WRITE,
        CAPABILITY_READ,
        CAPABILITY_PACKAGE_INSTALL,
        CAPABILITY_EXTERNAL_DOWNLOAD,
        CAPABILITY_STATE_CHANGING,
        CAPABILITY_VERIFY,
    }
)


class ToolError(Exception):
    """Raised when a tool cannot be executed."""

    def __init__(self, message: str, *, code: str = "tool_error") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class ToolPermissionError(ToolError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="permission_denied")


class ToolScopeError(ToolError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="scope_violation")


class ToolTimeout(ToolError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="timeout")


class ToolNotFound(ToolError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="unknown_tool")


@dataclass
class ToolPermissions:
    """What an agent role is allowed to do."""

    capabilities: set[str] = field(default_factory=set)
    #: Explicit allow-list of tool names.  Empty means "any tool that the
    #: capabilities permit".
    tools: set[str] = field(default_factory=set)
    #: Explicit deny-list, applied last.
    denied_tools: set[str] = field(default_factory=set)
    #: When true the role may request capabilities that are not pre-granted,
    #: but only from the list below.
    escalation_capabilities: set[str] = field(default_factory=set)
    #: Maximum bytes a single tool output may contain.
    max_output_bytes: int = 512 * 1024

    def allows_tool(self, name: str, required: Iterable[str]) -> tuple[bool, str]:
        if name in self.denied_tools:
            return False, f"tool '{name}' is explicitly denied for this role"
        if self.tools and name not in self.tools:
            return False, f"tool '{name}' is not in the role's allow-list"
        for capability in required:
            if capability not in KNOWN_CAPABILITIES:
                return False, f"tool '{name}' declares unknown capability '{capability}'"
            if capability in self.capabilities:
                continue
            if capability in self.escalation_capabilities:
                continue
            return False, f"role lacks the '{capability}' capability required by tool '{name}'"
        return True, ""


@dataclass
class ToolContext:
    """Everything a tool needs to know about who is calling it."""

    scan_id: str
    task_id: str
    role: str
    instance: str = ""
    workspace: Path = field(default_factory=lambda: Path("/tmp"))
    permissions: ToolPermissions = field(default_factory=ToolPermissions)
    budget: Budget = field(default_factory=Budget)
    scope: Any = None  # ScopeEnforcer
    #: Evidence already gathered, keyed by a short handle.
    evidence: dict[str, Any] = field(default_factory=dict)
    #: The artifacts the tools produced, by the same short handles.
    artifacts: list[str] = field(default_factory=list)
    #: The set of tools the agent was offered.
    allowed_tools: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """The outcome of a tool call."""

    tool: str
    ok: bool
    output: Any = ""
    error: str = ""
    duration_ms: int = 0
    call_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "ok": self.ok,
            "output": self.output,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "call_id": self.call_id,
            "metadata": self.metadata,
        }


@dataclass
class ToolDefinition:
    """A callable tool with its contract."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[..., Any]
    #: Capabilities the tool requires from the calling role.
    capabilities: set[str] = field(default_factory=set)
    #: Per-call timeout in seconds.
    timeout: float = 60.0
    #: Roles allowed to use the tool (empty = any role with the capability).
    allowed_roles: set[str] = field(default_factory=set)
    #: Whether the tool can mutate state on the target.
    state_changing: bool = False
    #: Human readable safety note shown to the model.
    safety_note: str = ""

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description + (f" {self.safety_note}" if self.safety_note else ""),
                "parameters": self.parameters,
            },
        }


ToolHandler = Callable[..., Any]


def bound_output(text: str, limit: int) -> tuple[str, bool, int]:
    """Cut a rendered output to the limit, in bytes.

    Returns the text to store, whether it had to be cut and how many
    bytes the whole output had.  The model saw the rendered output and
    nothing beyond the limit, so the platform stores that output and
    never more of it.  A cut is never silent: the row says that it was
    cut and how big the output really was.
    """
    raw = str(text).encode("utf-8", errors="ignore")
    size = len(raw)
    if size <= limit:
        return str(text), False, size
    return raw[:limit].decode("utf-8", errors="ignore"), True, size


class ToolRegistry:
    """Holds the available tool implementations."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: ToolHandler,
        *,
        capabilities: Iterable[str] = (),
        timeout: float = 60.0,
        allowed_roles: Iterable[str] = (),
        state_changing: bool = False,
        safety_note: str = "",
    ) -> ToolDefinition:
        definition = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters or {"type": "object", "properties": {}},
            handler=handler,
            capabilities=set(capabilities),
            timeout=timeout,
            allowed_roles=set(allowed_roles),
            state_changing=state_changing,
            safety_note=safety_note,
        )
        self._tools[name] = definition
        return definition

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[ToolDefinition]:
        return [self._tools[name] for name in sorted(self._tools)]

    def for_role(self, role: str, allowed: Iterable[str] = ()) -> list[ToolDefinition]:
        allowed_set = set(allowed)
        result = []
        for definition in self.all():
            if allowed_set and definition.name not in allowed_set:
                continue
            if definition.allowed_roles and role not in definition.allowed_roles:
                continue
            result.append(definition)
        return result


class ToolGateway:
    """Executes tool calls with permission, scope and budget enforcement."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        audit: Optional[Callable[[dict[str, Any]], None]] = None,
        default_timeout: float = 60.0,
    ) -> None:
        self.registry = registry
        self._audit = audit
        self.default_timeout = default_timeout

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def validate_arguments(self, definition: ToolDefinition, arguments: dict[str, Any]) -> None:
        validator = Draft202012Validator(definition.parameters)
        errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.path))
        if errors:
            detail = "; ".join(
                f"{'/'.join(str(p) for p in error.path) or '<root>'}: {error.message}" for error in errors[:8]
            )
            raise ToolError(f"invalid arguments for '{definition.name}': {detail}", code="invalid_arguments")

    def check_permission(self, definition: ToolDefinition, context: ToolContext) -> None:
        if context.allowed_tools and definition.name not in context.allowed_tools:
            raise ToolPermissionError(
                f"tool '{definition.name}' was not offered to the '{context.role}' agent"
            )
        if definition.allowed_roles and context.role not in definition.allowed_roles:
            raise ToolPermissionError(f"the '{context.role}' role may not use tool '{definition.name}'")
        allowed, reason = context.permissions.allows_tool(definition.name, definition.capabilities)
        if not allowed:
            raise ToolPermissionError(reason)
        if definition.state_changing and not context.permissions.capabilities & {CAPABILITY_STATE_CHANGING}:
            raise ToolPermissionError(
                f"tool '{definition.name}' changes target state, which is not permitted for this role"
            )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    async def execute(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        context: ToolContext,
        call_id: str = "",
    ) -> ToolResult:
        """Execute a tool call.

        Every failure - an unknown tool, a denied permission, invalid
        arguments or a timeout - is returned as a failed
        :class:`ToolResult` rather than raised.  The agent runtime feeds
        the error text back to the model so that it can adapt, instead of
        aborting the whole run on a single mistake.
        """
        started = time.monotonic()
        record: dict[str, Any] = {
            "scan_id": context.scan_id,
            "task_id": context.task_id,
            "agent_role": context.role,
            "tool": tool_name,
            "call_id": call_id,
            "status": "error",
            "arguments": redact_mapping(arguments),
            "at": time.time(),
            # The output of the call.  It is filled in when the call
            # succeeds; a call that failed has none.
            "output": "",
            "output_bytes": 0,
            "output_truncated": False,
        }

        definition = self.registry.get(tool_name)
        if definition is None:
            message = f"unknown tool '{tool_name}'"
            record["error"] = message
            record["duration_ms"] = int((time.monotonic() - started) * 1000)
            self._emit(record)
            return ToolResult(
                tool=tool_name, ok=False, error=message, duration_ms=record["duration_ms"], call_id=call_id
            )

        try:
            self.check_permission(definition, context)
            self.validate_arguments(definition, arguments)
        except ToolError as exc:
            record["error"] = exc.message
            record["duration_ms"] = int((time.monotonic() - started) * 1000)
            self._emit(record)
            return ToolResult(
                tool=tool_name,
                ok=False,
                error=exc.message,
                duration_ms=record["duration_ms"],
                call_id=call_id,
            )

        timeout = definition.timeout or self.default_timeout

        try:
            output = await self._invoke(definition, arguments, context, timeout)
        except ToolError as exc:
            record["error"] = exc.message
            record["duration_ms"] = int((time.monotonic() - started) * 1000)
            self._emit(record)
            return ToolResult(
                tool=definition.name,
                ok=False,
                error=exc.message,
                duration_ms=record["duration_ms"],
                call_id=call_id,
            )
        except Exception as exc:  # pragma: no cover - defensive
            record["error"] = f"{type(exc).__name__}: {exc}"
            record["duration_ms"] = int((time.monotonic() - started) * 1000)
            self._emit(record)
            return ToolResult(
                tool=definition.name,
                ok=False,
                error=record["error"],
                duration_ms=record["duration_ms"],
                call_id=call_id,
            )

        rendered = self._render(output, context)
        stored, truncated, size = bound_output(str(rendered), context.permissions.max_output_bytes)
        record["status"] = "ok"
        record["duration_ms"] = int((time.monotonic() - started) * 1000)
        record["output_summary"] = redact_text(str(rendered))[:2000]
        # The full output, next to the summary.  The transcript shows
        # the full text; the console lists the summary.  What is stored
        # is what the model saw and never more than that.
        record["output"] = stored
        record["output_truncated"] = truncated
        record["output_bytes"] = size
        self._emit(record)

        return ToolResult(
            tool=definition.name,
            ok=True,
            output=rendered,
            duration_ms=record["duration_ms"],
            call_id=call_id,
        )

    async def _invoke(
        self,
        definition: ToolDefinition,
        arguments: dict[str, Any],
        context: ToolContext,
        timeout: float,
    ) -> Any:
        kwargs = dict(arguments)
        kwargs["context"] = context
        handler = definition.handler
        if inspect.iscoroutinefunction(handler):
            coroutine = handler(**kwargs)
        else:
            loop = asyncio.get_running_loop()
            # Run a synchronous handler off the event loop, then await it if
            # it turned out to be a coroutine function wrapped in a lambda.
            coroutine = loop.run_in_executor(None, lambda: handler(**kwargs))
        try:
            result = await asyncio.wait_for(coroutine, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise ToolTimeout(f"tool '{definition.name}' exceeded its {timeout:.0f}s timeout") from exc
        except asyncio.CancelledError:
            raise
        except ToolError:
            raise
        except Exception as exc:
            # The type of the exception is part of the explanation: an
            # exception with an empty message would otherwise become a
            # failure the platform cannot name.
            raise ToolError(f"tool '{definition.name}' failed: {type(exc).__name__}: {exc}") from exc

        if inspect.isawaitable(result):
            try:
                result = await asyncio.wait_for(result, timeout=timeout)
            except asyncio.TimeoutError as exc:
                raise ToolTimeout(f"tool '{definition.name}' exceeded its {timeout:.0f}s timeout") from exc
            except Exception as exc:
                raise ToolError(f"tool '{definition.name}' failed: {exc}") from exc
        return result

    def _render(self, output: Any, context: ToolContext) -> Any:
        """Render and redact a tool result before it reaches the model.

        Redaction happens at the gateway boundary rather than only inside
        individual tools: a tool that returns raw content (an HTTP body, a
        file, a directory listing) may contain a credential, and the model
        must never see it verbatim.
        """
        limit = context.permissions.max_output_bytes
        if isinstance(output, str):
            text = redact_text(output)
        elif isinstance(output, (dict, list, tuple)):
            text = json.dumps(redact_mapping(output), ensure_ascii=False, default=str)
        else:
            try:
                text = json.dumps(output, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                text = redact_text(str(output))
        if len(text.encode("utf-8", errors="ignore")) > limit:
            text = text[:limit] + f"\n... [truncated at {limit} bytes]"
        return text

    def _emit(self, record: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit(record)
        except Exception:  # pragma: no cover - auditing must never break a scan
            log.exception("tool audit hook failed")


# ----------------------------------------------------------------------
# Workspace helpers
# ----------------------------------------------------------------------
def resolve_workspace_path(context: ToolContext, relative: str) -> Path:
    """Resolve *relative* inside the agent workspace.

    Raises :class:`ToolPermissionError` when the result would escape the
    workspace - this is the control that stops an agent from reading
    ``/etc/shadow`` or writing to ``/usr/bin``.
    """
    if not relative:
        raise ToolPermissionError("a path argument is required")
    candidate = Path(relative)
    if candidate.is_absolute():
        raise ToolPermissionError(
            f"absolute paths are not allowed; use a path relative to the workspace (got '{relative}')"
        )
    workspace = Path(context.workspace).resolve()
    target = (workspace / candidate).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise ToolPermissionError(f"path '{relative}' escapes the assigned workspace") from exc
    if any(part == ".." for part in candidate.parts):
        raise ToolPermissionError(f"path '{relative}' contains a parent traversal")
    return target


def ensure_workspace(context: ToolContext) -> Path:
    """Create the agent workspace directory if needed and return it."""
    workspace = Path(context.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def shell_command_is_allowed(
    command: str, *, allowlist: Sequence[str], deny_patterns: Sequence[str]
) -> tuple[bool, str]:
    """Check a shell command against a simple allow/deny policy."""
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return False, f"could not parse command: {exc}"
    if not parts:
        return False, "empty command"
    program = os.path.basename(parts[0])
    for pattern in deny_patterns:
        if pattern in command:
            return False, f"command matches the denied pattern '{pattern}'"
    if allowlist and program not in allowlist:
        return False, f"program '{program}' is not in the shell allow-list"
    return True, ""
