"""Compatibility layer for providers without native tool calling.

Not every OpenAI-compatible endpoint implements the ``tools`` parameter.
When the native path is unavailable the runtime asks the model to emit a
tool call as a JSON object in its message content and parses it here.

The important property is that the compatibility path is *not* a bypass:
the extracted call goes through exactly the same
:class:`~b_hunters.platform.tools.gateway.ToolGateway`, the same JSON schema
validation and the same permission checks as a native call.  A provider
therefore cannot gain capabilities by not supporting ``tools``.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Sequence
from typing import Any

from ..tools.gateway import ToolDefinition
from .provider import ChatMessage, ToolCall

#: Instruction appended to the system prompt in compat mode.
COMPAT_INSTRUCTION = """\
You can call tools. To call one, reply with a single JSON object and nothing else:

{"tool": "<tool name>", "arguments": {<arguments object>}}

Use only the tools listed below. Arguments must match the documented schema.
If you do not need a tool, reply with plain text. Never invent a tool name.
"""

_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.S)
_OBJECT_RE = re.compile(r"\{.*\}", re.S)


def build_compat_instruction(tools: Sequence[ToolDefinition]) -> str:
    """Render the tool catalogue for the compat prompt."""
    lines = [COMPAT_INSTRUCTION, "Available tools:"]
    for definition in tools:
        schema = definition.parameters or {}
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        arguments = ", ".join(f"{name}" + ("" if name in required else "?") for name in properties)
        lines.append(f"- {definition.name}({arguments}): {definition.description.strip()}")
    return "\n".join(lines)


def extract_tool_call(content: str) -> ToolCall | None:
    """Extract a single tool call from a message body.

    Handles the plain JSON object, a fenced code block and a message that
    contains JSON alongside prose.
    """
    if not content:
        return None

    candidates: list[str] = []
    stripped = content.strip()
    candidates.append(stripped)
    for match in _FENCE_RE.finditer(content):
        candidates.append(match.group(1).strip())
    for match in _OBJECT_RE.finditer(content):
        candidates.append(match.group(0).strip())

    for candidate in candidates:
        parsed = _try_parse(candidate)
        if parsed is None:
            continue
        name = parsed.get("tool") or parsed.get("name") or parsed.get("function")
        if isinstance(name, dict):
            name = name.get("name")
        if not isinstance(name, str) or not name:
            continue
        arguments = parsed.get("arguments")
        if arguments is None:
            arguments = parsed.get("parameters")
        if arguments is None:
            arguments = parsed.get("args")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments) if arguments.strip() else {}
            except ValueError:
                continue
        if not isinstance(arguments, dict):
            arguments = {"value": arguments}
        return ToolCall(
            id=str(parsed.get("id") or f"compat_{uuid.uuid4().hex[:12]}"),
            name=name,
            arguments=arguments,
            origin="compat",
        )
    return None


def _try_parse(text: str) -> dict[str, Any] | None:
    if not text.startswith("{"):
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def merge_native_and_compat(message: ChatMessage) -> ChatMessage:
    """Ensure a message carries a tool call when one can be derived.

    If the provider produced native tool calls they are kept.  Otherwise the
    message body is inspected for a compat-style call.
    """
    if message.tool_calls:
        return message
    call = extract_tool_call(message.content)
    if call is not None:
        message.tool_calls = [call]
        message.content = ""
    return message
