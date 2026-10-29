"""The note on a tool is read by the model.

``record_verdict`` carries a note that says who may record a verdict.  A
note that names the wrong role stops the role that has the capability
from using the tool at all: the adjudicator read "only the verification
role may record a verdict", concluded that it was not that role, and
never recorded a verdict - so every finding stayed unverified.
"""

from __future__ import annotations

from b_hunters.platform.tools.builtin import build_tool_registry


def _record_verdict() -> object:
    registry = build_tool_registry()
    return registry.get("record_verdict")


def test_the_tool_exists() -> None:
    assert _record_verdict() is not None


def test_the_note_does_not_restrict_the_tool_to_one_role() -> None:
    # The note is appended to the description the model reads.
    description = _record_verdict().to_openai()["function"]["description"]
    assert "verification role" not in description.lower()
    assert "verify' capability" in description.lower()


def test_the_capability_is_what_gates_the_tool() -> None:
    definition = _record_verdict()
    capabilities = getattr(definition, "capabilities", set())
    assert "verify" in capabilities
