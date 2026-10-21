"""Workspace file tools.

Agents may only read and write inside the workspace that the orchestrator
assigned to them.  ``resolve_workspace_path`` rejects absolute paths and
parent traversals, so an agent cannot reach ``/etc`` or a sibling agent's
workspace.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ...security.redact import redact_text
from ..gateway import ToolContext, ToolError, resolve_workspace_path

MAX_READ_BYTES = 512 * 1024
MAX_WRITE_BYTES = 2 * 1024 * 1024


READ_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "Path relative to the workspace."},
        "max_bytes": {"type": "integer", "default": MAX_READ_BYTES},
    },
    "required": ["path"],
    "additionalProperties": False,
}


def read_file(path: str, max_bytes: int = MAX_READ_BYTES, *, context: ToolContext) -> dict[str, Any]:
    """Read a file from the agent workspace."""
    target = resolve_workspace_path(context, path)
    if not target.exists():
        raise ToolError(f"file '{path}' does not exist in the workspace")
    if target.is_dir():
        raise ToolError(f"'{path}' is a directory")
    size = target.stat().st_size
    with target.open("rb") as handle:
        raw = handle.read(max(1, min(int(max_bytes), MAX_READ_BYTES)))
    return {
        "path": str(target.relative_to(Path(context.workspace).resolve())),
        "size_bytes": size,
        "truncated": size > len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content": redact_text(raw.decode("utf-8", errors="replace")),
    }


WRITE_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "Path relative to the workspace."},
        "content": {"type": "string", "description": "File content."},
        "append": {"type": "boolean", "default": False},
    },
    "required": ["path", "content"],
    "additionalProperties": False,
}


def write_file(path: str, content: str, append: bool = False, *, context: ToolContext) -> dict[str, Any]:
    """Write a file into the agent workspace."""
    payload = content or ""
    if len(payload.encode("utf-8")) > MAX_WRITE_BYTES:
        raise ToolError(f"refusing to write more than {MAX_WRITE_BYTES} bytes")
    target = resolve_workspace_path(context, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with target.open(mode, encoding="utf-8") as handle:
        handle.write(payload)
    return {
        "path": str(target.relative_to(Path(context.workspace).resolve())),
        "bytes_written": len(payload.encode("utf-8")),
        "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }


LIST_FILES_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "default": ".", "description": "Directory relative to the workspace."},
        "recursive": {"type": "boolean", "default": False},
    },
    "additionalProperties": False,
}


def list_files(path: str = ".", recursive: bool = False, *, context: ToolContext) -> dict[str, Any]:
    """List files in the agent workspace."""
    target = resolve_workspace_path(context, path or ".")
    if not target.exists():
        return {"path": path, "entries": [], "count": 0}
    entries: list[dict[str, Any]] = []
    if target.is_file():
        return {
            "path": path,
            "entries": [{"name": target.name, "size_bytes": target.stat().st_size, "is_dir": False}],
            "count": 1,
        }
    walker = target.rglob("*") if recursive else target.iterdir()
    for item in sorted(walker)[:1000]:
        try:
            stat = item.stat()
        except OSError:
            continue
        entries.append(
            {
                "name": str(item.relative_to(Path(context.workspace).resolve())),
                "size_bytes": stat.st_size,
                "is_dir": item.is_dir(),
            }
        )
    return {"path": path, "entries": entries, "count": len(entries)}
