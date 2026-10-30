"""Sandboxed shell execution for agents.

The agent never receives an unrestricted host shell.  Commands are:

* executed with the workspace as the working directory,
* restricted to an allow-list of programs,
* filtered against deny patterns (destructive utilities, package managers,
  privilege escalation),
* time limited and output capped.

A container/sandbox boundary is available for deployments that need it (see
``docs/deployment.md``); the in-process runner here is the fallback for
environments where the worker already runs inside an isolated container.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Optional

from ..gateway import ToolContext, ToolError, ToolPermissionError

#: Programs an agent may run.
DEFAULT_ALLOWLIST: tuple[str, ...] = (
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "grep",
    "rg",
    "find",
    "sort",
    "uniq",
    "cut",
    "sed",
    "awk",
    "jq",
    "python3",
    "node",
    "curl",
    "openssl",
    "file",
    "stat",
    "diff",
    "sha256sum",
    "md5sum",
)

#: Substrings that cause a command to be refused outright.
DEFAULT_DENY_PATTERNS: tuple[str, ...] = (
    "rm ",
    "rm -",
    "chmod ",
    "chown ",
    "sudo ",
    "su ",
    "mkfs",
    "dd if=",
    ":(){",
    "shutdown",
    "reboot",
    "curl ",
    "wget ",
    "nc ",
    "ncat ",
    "pip install",
    "pip3 install",
    "apt-get",
    "apt ",
    "npm install",
    "yarn add",
    "systemctl",
    "docker ",
    "mount ",
)

MAX_OUTPUT_BYTES = 256 * 1024

RUN_COMMAND_SCHEMA = {
    "type": "object",
    "properties": {
        "command": {"type": "string", "description": "The command line to execute."},
        "timeout": {"type": "number", "default": 60, "description": "Timeout in seconds."},
    },
    "required": ["command"],
    "additionalProperties": False,
}


def _split_command(command: str) -> list[str]:
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ToolError(f"could not parse the command: {exc}") from exc
    if not parts:
        raise ToolError("the command is empty")
    return parts


#: A URL in a command line.
_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://(?P<host>[^/\s:\"']+)(?::(?P<port>\d+))?", re.I)

#: An IPv4 address in a command line.
_IP_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")

#: A name that looks like a host name.
_NAME_RE = re.compile(r"(?<![\w./-])([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)(?![\w./-])", re.I)


def _hosts_in(command: str, workspace: Optional[Path] = None) -> set[str]:
    """The hosts a command names.

    A name that is a file of the agent's own workspace is not a host:
    ``python3 script.py`` must not be refused because ``script.py`` looks
    like a domain name.
    """
    hosts: set[str] = set()
    for match in _URL_RE.finditer(command):
        hosts.add(match.group("host").lower())
    for match in _IP_RE.finditer(command):
        hosts.add(match.group(1))
    for match in _NAME_RE.finditer(command):
        token = match.group(1)
        if workspace is not None and (workspace / token).exists():
            continue
        hosts.add(token.lower())
    return hosts


def check_command(
    command: str,
    *,
    allowlist: Sequence[str],
    deny_patterns: Sequence[str],
    host_allowed: Optional[Callable[[str], bool]] = None,
    workspace: Optional[Path] = None,
) -> list[str]:
    """Validate a command line against the shell policy.

    A command that names a host outside the scan's scope is refused: the
    shell can reach any host, and the scope is the platform's guarantee
    about what may be touched.
    """
    lowered = command.lower()
    for pattern in deny_patterns:
        if pattern.lower() in lowered:
            raise ToolPermissionError(f"the command contains the denied operation '{pattern.strip()}'")
    if host_allowed is not None:
        for host in _hosts_in(command, workspace):
            if not host_allowed(host):
                raise ToolPermissionError(
                    f"the command names '{host}', which is outside the scope of this scan"
                )
    parts = _split_command(command)
    program = os.path.basename(parts[0])
    if program not in allowlist:
        raise ToolPermissionError(
            f"program '{program}' is not in the shell allow-list ({', '.join(sorted(allowlist))})"
        )
    return parts


async def run_command(
    command: str,
    timeout: float = 60.0,
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """Run an allow-listed command inside the agent workspace."""
    allowlist = tuple(context.metadata.get("shell_allowlist", DEFAULT_ALLOWLIST))
    deny_patterns = tuple(context.metadata.get("shell_deny_patterns", DEFAULT_DENY_PATTERNS))

    workspace = await asyncio.to_thread(_prepare_workspace, context.workspace)

    # The shell can reach any host, so a command that names one outside the
    # scan's scope is refused: the scope is the platform's guarantee about
    # what may be touched, and `http_request` is not the only way out.
    scope = getattr(context, "scope", None)
    policy = getattr(scope, "policy", None)
    host_allowed: Optional[Callable[[str], bool]] = None
    authorized_hosts = getattr(policy, "authorized_hosts", None)
    if policy is not None and authorized_hosts:
        host_allowed = policy.matches_host

    parts = check_command(
        command,
        allowlist=allowlist,
        deny_patterns=deny_patterns,
        host_allowed=host_allowed,
        workspace=workspace,
    )

    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(workspace),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "BHUNTERS_SANDBOX": "1",
    }

    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *parts,
            cwd=str(workspace),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"program '{parts[0]}' is not installed in the sandbox") from exc
    except PermissionError as exc:
        raise ToolPermissionError(f"not permitted to execute '{parts[0]}': {exc}") from exc

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        try:
            process.kill()
        except ProcessLookupError:  # pragma: no cover - race
            pass
        raise ToolError(f"the command exceeded its {timeout:.0f}s timeout") from exc

    duration_ms = int((time.monotonic() - started) * 1000)
    out = (stdout or b"").decode("utf-8", errors="replace")
    err = (stderr or b"").decode("utf-8", errors="replace")
    if len(out) > MAX_OUTPUT_BYTES:
        out = out[:MAX_OUTPUT_BYTES] + "\n... [output truncated]"
    if len(err) > MAX_OUTPUT_BYTES:
        err = err[:MAX_OUTPUT_BYTES] + "\n... [stderr truncated]"

    return {
        "command": command,
        "exit_code": process.returncode,
        "stdout": out,
        "stderr": err,
        "duration_ms": duration_ms,
        "cwd": str(workspace),
    }


def _prepare_workspace(raw_workspace) -> Path:
    """Create and resolve the agent workspace directory."""
    workspace = Path(raw_workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace
