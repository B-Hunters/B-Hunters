"""Tools that let agents inspect what has already been discovered.

These tools are read-only views over the platform's own database: the
findings, assets and events produced by the deterministic scanner workers.
Agents use them to avoid redoing work and to ground their hypotheses in
real observations.
"""

from __future__ import annotations

from typing import Any, Optional

from ..gateway import ToolContext, ToolError

LIST_FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "array",
            "items": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "default": [],
        },
        "vuln_class": {"type": "string", "default": ""},
        "host": {"type": "string", "default": ""},
        "verification_status": {"type": "string", "default": ""},
        "limit": {"type": "integer", "default": 50, "maximum": 500},
    },
    "additionalProperties": False,
}


def list_findings(
    severity: Optional[list[str]] = None,
    vuln_class: str = "",
    host: str = "",
    verification_status: str = "",
    limit: int = 50,
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """List findings already recorded for this scan."""
    repo = context.metadata.get("findings_repository")
    if repo is None:
        raise ToolError("the findings repository is not available in this context")
    findings = repo.list(
        context.scan_id,
        severity=severity or (),
        verification_status=(verification_status,) if verification_status else (),
        vuln_class=vuln_class,
        host=host,
        limit=limit,
    )
    return {
        "count": len(findings),
        "findings": [_finding_view(item) for item in findings],
    }


#: How much of one piece of evidence the judge is shown.  It has to read
#: enough to judge the finding and not so much that the list of the
#: findings of a whole scan does not fit in the context.
EVIDENCE_EXCERPT_LIMIT = 400


def _finding_view(item: dict[str, Any]) -> dict[str, Any]:
    """One finding, with the evidence that supports it.

    The judge needs the evidence to reach a verdict.  Without it here it
    went looking for the evidence of every finding in the event log, one
    tool call at a time, and ran out of rounds before it had judged a
    third of them.
    """
    evidence = []
    for entry in item.get("evidence") or []:
        if not isinstance(entry, dict):
            continue
        excerpt = str(entry.get("excerpt") or "")
        evidence.append(
            {
                "kind": str(entry.get("kind") or "note"),
                "excerpt": excerpt[:EVIDENCE_EXCERPT_LIMIT],
            }
        )
    view = {
        "finding_id": item.get("finding_id"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "vuln_class": item.get("vuln_class"),
        "severity": item.get("severity"),
        "host": item.get("host"),
        "path": item.get("path"),
        "parameter": item.get("parameter"),
        "cwe": item.get("cwe"),
        "confidence": item.get("confidence"),
        "verification_status": item.get("verification_status"),
        "verification_notes": item.get("verification_notes"),
        "detected_by": item.get("detected_by"),
        "detection_source": item.get("detection_source"),
        "affected_url": item.get("affected_url"),
        "remediation": item.get("remediation"),
        "evidence": evidence[:4],
    }
    return {key: value for key, value in view.items() if value not in (None, "", [], {})}


LIST_ASSETS_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {
            "type": "string",
            "enum": [
                "",
                # The names the tool used before.  They ask for everything.
                "url",
                "route",
                "host",
                "technology",
                # The names of the inventory.
                "javascript",
                "page",
                "js",
                "image",
                "css",
                "api",
                "other",
            ],
            "default": "",
        },
        "limit": {"type": "integer", "default": 100, "maximum": 1000},
    },
    "additionalProperties": False,
}

#: What the names the tool used before ask for now.  They have no
#: counterpart in the inventory - the inventory holds one row per URL -
#: so they ask for every asset.  ``javascript`` is the one name that
#: does have a counterpart: it is the JavaScript of the inventory.
ASSET_KIND_ALIASES = {
    "javascript": "js",
    "url": "",
    "route": "",
    "host": "",
    "technology": "",
}


def list_assets(kind: str = "", limit: int = 100, *, context: ToolContext) -> dict[str, Any]:
    """List the assets discovered so far for this scan.

    The inventory holds one row per URL, with what the asset is, the
    scope it is in, its status and the tools that saw it.  The result
    also carries the number of assets per kind, so that an agent can see
    the shape of the surface before it lists it.
    """
    requested = ASSET_KIND_ALIASES.get(kind, kind)
    repo = context.metadata.get("asset_repository")
    if repo is None:
        # There is no inventory to read.  The answer is that nothing was
        # found, not an error: a tool that cannot answer must not stop
        # the scan.
        return {"kind": requested or "all", "count": 0, "by_kind": {}, "assets": []}
    scan_id = str(context.metadata.get("scan_id") or context.scan_id)
    rows = repo.list_for_scan(scan_id, kind=requested, limit=limit)
    return {
        "kind": requested or "all",
        "count": len(rows),
        "by_kind": repo.counts_for_scan(scan_id),
        "assets": rows,
    }


LIST_EVENTS_SCHEMA = {
    "type": "object",
    "properties": {
        "limit": {"type": "integer", "default": 40, "maximum": 200},
        "kind": {"type": "string", "default": ""},
    },
    "additionalProperties": False,
}


def list_events(kind: str = "", limit: int = 40, *, context: ToolContext) -> dict[str, Any]:
    """List recent scan events (worker output, agent messages, errors)."""
    repo = context.metadata.get("events_repository")
    if repo is None:
        raise ToolError("the events repository is not available in this context")
    events = repo.recent(limit=limit, scan_id=context.scan_id)
    if kind:
        events = [event for event in events if event.get("kind") == kind]
    return {
        "count": len(events),
        "events": [
            {
                "seq": event.get("seq"),
                "kind": event.get("kind"),
                "at": event.get("at"),
                "payload": event.get("payload"),
            }
            for event in events
        ],
    }


TOOL_HEALTH_SCHEMA = {
    "type": "object",
    "properties": {"include_disabled": {"type": "boolean", "default": False}},
    "additionalProperties": False,
}


def list_tool_health(include_disabled: bool = False, *, context: ToolContext) -> dict[str, Any]:
    """Report the health of the registered scanner adapters."""
    registry = context.metadata.get("scanner_registry")
    if registry is None:
        raise ToolError("the scanner registry is not available in this context")
    return registry.health(include_disabled=include_disabled)


RECORD_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {
            "type": "string",
            "description": "The finding_id of the finding being judged, from list_findings.",
        },
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "likely", "unverified", "inconclusive", "rejected"],
            "description": "What the verification established about the finding.",
        },
        "severity": {
            "type": "string",
            "enum": ["", "critical", "high", "medium", "low", "info"],
            "default": "",
            "description": "The severity the verification supports, if it differs.",
        },
        "notes": {
            "type": "string",
            "default": "",
            "description": "What was done to decide, and what was observed.",
        },
        "false_positive_reason": {
            "type": "string",
            "default": "",
            "description": "Set when the verdict is 'rejected'.",
        },
    },
    "required": ["finding_id", "verdict"],
    "additionalProperties": False,
}


RECORD_VERDICTS_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "description": "The verdicts to record, one per finding.",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The finding_id of the finding being judged, from list_findings.",
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["confirmed", "likely", "unverified", "inconclusive", "rejected"],
                        "description": "What the verification established about the finding.",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["", "critical", "high", "medium", "low", "info"],
                        "default": "",
                        "description": "The severity the verification supports, if it differs.",
                    },
                    "notes": {
                        "type": "string",
                        "default": "",
                        "description": "What was done to decide, and what was observed.",
                    },
                    "false_positive_reason": {
                        "type": "string",
                        "default": "",
                        "description": "Set when the verdict is 'rejected'.",
                    },
                },
                "required": ["finding_id", "verdict"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}


def record_verdict(
    finding_id: str,
    verdict: str,
    severity: str = "",
    notes: str = "",
    false_positive_reason: str = "",
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """Record what the verification established about one finding.

    A verdict that only exists in the conclusion of a role is prose: it
    never reaches the finding, and the finding stays unverified forever.
    Recording it here writes it to the finding itself.
    """
    repo = context.metadata.get("findings_repository")
    if repo is None:
        raise ToolError("the findings repository is not available in this context")
    finding = repo.get(finding_id)
    if finding is None:
        raise ToolError(f"no finding with the identifier '{finding_id}'")
    if finding.get("scan_id") != context.scan_id:
        raise ToolError("that finding belongs to another scan")
    if repo.set_verification(
        finding_id,
        status=verdict,
        notes=notes,
        verified_by=context.role,
        severity=severity,
        false_positive_reason=false_positive_reason,
    ):
        return {
            "finding_id": finding_id,
            "title": finding.get("title", ""),
            "verification_status": verdict,
            "severity": severity or finding.get("severity", ""),
        }
    raise ToolError("the verdict could not be recorded")


def record_verdicts(verdicts: list[dict[str, Any]], *, context: ToolContext) -> dict[str, Any]:
    """Record what the verification established about many findings at once.

    A judge that has fifty findings to judge cannot record them one at
    a time within its budget: it reads the list, judges a few, reads
    the list again and never gets to the verdicts.  Recording them in
    one call is the difference between a report with verdicts and a
    report with findings nobody judged.

    The entries that cannot be recorded - an unknown finding, a finding
    of another scan - are named in the answer, so the judge can correct
    them instead of losing them.
    """
    repo = context.metadata.get("findings_repository")
    if repo is None:
        raise ToolError("the findings repository is not available in this context")
    recorded: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for entry in verdicts or []:
        if not isinstance(entry, dict):
            refused.append({"finding_id": "", "reason": "the entry is not an object"})
            continue
        finding_id = str(entry.get("finding_id") or "")
        verdict = str(entry.get("verdict") or "")
        if not finding_id or not verdict:
            refused.append({"finding_id": finding_id, "reason": "the finding_id or the verdict is missing"})
            continue
        finding = repo.get(finding_id)
        if finding is None:
            refused.append({"finding_id": finding_id, "reason": "no finding with that identifier"})
            continue
        if finding.get("scan_id") != context.scan_id:
            refused.append({"finding_id": finding_id, "reason": "that finding belongs to another scan"})
            continue
        if not repo.set_verification(
            finding_id,
            status=verdict,
            notes=str(entry.get("notes") or ""),
            verified_by=context.role,
            severity=str(entry.get("severity") or ""),
            false_positive_reason=str(entry.get("false_positive_reason") or ""),
        ):
            refused.append({"finding_id": finding_id, "reason": "the verdict could not be recorded"})
            continue
        recorded.append(
            {
                "finding_id": finding_id,
                "title": finding.get("title", ""),
                "verification_status": verdict,
                "severity": entry.get("severity") or finding.get("severity", ""),
            }
        )
    return {
        "recorded": len(recorded),
        "refused": len(refused),
        "verdicts": recorded,
        "problems": refused[:20],
    }
