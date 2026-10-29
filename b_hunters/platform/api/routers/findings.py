"""Findings, reports and exports."""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ...db.repositories import SEVERITIES, VERIFICATION_STATUSES
from ..deps import CurrentUser, Services, current_user, enforce_csrf, get_services, require_role
from .assets import (
    agent_report,
    integrity_report,
    participation_report,
    transcript_appendix,
)

router = APIRouter(tags=["findings"])


@router.get("/findings")
async def list_findings(
    scan_id: str = "",
    severity: list[str] = Query(default_factory=list),
    verification_status: list[str] = Query(default_factory=list),
    vuln_class: str = "",
    host: str = "",
    detected_by: str = "",
    confidence_min: Optional[float] = None,
    limit: int = 100,
    offset: int = 0,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Filter findings across scans."""
    for value in severity:
        if value not in SEVERITIES:
            raise HTTPException(status_code=400, detail=f"unknown severity '{value}'")
    for value in verification_status:
        if value not in VERIFICATION_STATUSES:
            raise HTTPException(status_code=400, detail=f"unknown verification status '{value}'")

    findings = services.findings.list(
        scan_id,
        severity=severity,
        verification_status=verification_status,
        vuln_class=vuln_class,
        host=host,
        detected_by=detected_by,
        confidence_min=confidence_min,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [_finding_public(item) for item in findings],
        "count": len(findings),
        "total": services.findings.count(scan_id),
        "severity_counts": services.findings.severity_counts(scan_id),
        "class_counts": services.findings.class_counts(scan_id),
    }


def _finding_public(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": item.get("finding_id"),
        "scan_id": item.get("scan_id"),
        "fingerprint": item.get("fingerprint"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "vuln_class": item.get("vuln_class"),
        "severity": item.get("severity"),
        "confidence": item.get("confidence"),
        "cwe": item.get("cwe"),
        "host": item.get("host"),
        "path": item.get("path"),
        "parameter": item.get("parameter"),
        "affected_url": item.get("affected_url"),
        "detected_by": item.get("detected_by", []),
        "detection_source": item.get("detection_source"),
        "verification_status": item.get("verification_status"),
        "verification_notes": item.get("verification_notes"),
        "verified_by": item.get("verified_by"),
        "false_positive_reason": item.get("false_positive_reason"),
        "remediation": item.get("remediation"),
        "evidence": item.get("evidence", []),
        "first_seen_at": item.get("first_seen_at"),
        "last_seen_at": item.get("last_seen_at"),
    }


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """Return one finding with its evidence."""
    finding = services.findings.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="the finding does not exist")
    public = _finding_public(finding)
    public["evidence_records"] = services.findings.evidence_for(finding_id)
    return public


class UpdateVerification(BaseModel):
    status: str = Field(description="confirmed, likely, unverified, inconclusive or rejected")
    notes: str = Field(default="", max_length=8000)
    severity: str = Field(default="", max_length=32)
    false_positive_reason: str = Field(default="", max_length=8000)


@router.post("/findings/{finding_id}/verification")
async def update_verification(
    finding_id: str,
    payload: UpdateVerification,
    user: CurrentUser = Depends(require_role("operator")),
    services: Services = Depends(get_services),
    csrf: None = Depends(enforce_csrf),
) -> dict[str, Any]:
    """Record the verification decision for a finding."""
    finding = services.findings.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="the finding does not exist")
    if payload.status not in VERIFICATION_STATUSES:
        raise HTTPException(status_code=400, detail=f"invalid status '{payload.status}'")
    if payload.severity and payload.severity not in SEVERITIES:
        raise HTTPException(status_code=400, detail=f"invalid severity '{payload.severity}'")

    services.findings.set_verification(
        finding_id,
        status=payload.status,
        notes=payload.notes,
        verified_by=user.username,
        severity=payload.severity,
        false_positive_reason=payload.false_positive_reason,
    )
    services.audit.record(
        action="finding.verify",
        actor=user.username,
        target_type="finding",
        target_id=finding_id,
        detail={"status": payload.status, "severity": payload.severity},
    )
    updated = services.findings.get(finding_id)
    return _finding_public(updated or {})


@router.get("/scans/{scan_id}/report")
async def export_report(
    scan_id: str,
    format: str = Query(default="json", pattern="^(json|html|sarif)$"),
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> Response:
    """Export the findings of a scan as JSON, HTML or SARIF.

    The report is more than the findings: it carries the assets the
    scan saw, the tools that took part in it, the outcome of every
    agent role and the verdict of the error ledger.  The SARIF export
    is left alone - it is a findings format and has no place for the
    rest.
    """
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    findings = services.findings.list(scan_id, limit=5000)
    public = [_finding_public(item) for item in findings]
    sections = _report_sections(services, scan)

    if format == "json":
        payload = {
            "scan": scan.public(),
            "generated_at": time.time(),
            "finding_count": len(public),
            "findings": public,
            **sections,
        }
        return Response(
            content=json.dumps(payload, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'},
        )

    if format == "sarif":
        return Response(
            content=json.dumps(_to_sarif(scan.public(), public), indent=2, default=str),
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.sarif"'},
        )

    html = _to_html(scan.public(), public, **sections)
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.html"'},
    )


@router.get("/scans/{scan_id}/report.pdf")
async def export_report_pdf(
    scan_id: str,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> Response:
    """Export the report of a scan as a PDF.

    The report is printed by the same browser that renders the
    console.  The print has a budget: when it takes longer than it
    may, the fallback - the summary with the transcript as plain text
    - is printed instead, so that the endpoint answers with a document
    rather than with nothing.
    """
    from ...pdf import PdfRenderError, render_pdf_async

    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    findings = services.findings.list(scan_id, limit=5000)
    public = [_finding_public(item) for item in findings]
    sections = _report_sections(services, scan)

    html = _to_html(scan.public(), public, **sections)
    fallback = _to_fallback_html(scan.public(), public, **sections)
    try:
        document, _variant = await render_pdf_async(html, fallback_html=fallback)
    except PdfRenderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return Response(
        content=document,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.pdf"'},
    )


def _report_sections(services: Services, scan: Any) -> dict[str, Any]:
    """The collections the report carries besides the findings."""
    from ...db.assets import AssetRepository

    repository = AssetRepository(services.db)
    agents = agent_report(services, scan)
    roles = [str(row.get("role", "")) for row in agents.get("roles", []) if row.get("role")]
    appendix, omitted = transcript_appendix(services, scan.scan_id, roles=roles)
    return {
        "assets": repository.list_for_scan(scan.scan_id, limit=2000),
        "asset_counts": repository.counts_for_scan(scan.scan_id),
        "participation": participation_report(services, scan),
        "agents": agents,
        "integrity": integrity_report(services, scan),
        "transcript": appendix,
        "transcript_omitted_bytes": omitted,
    }


#: SARIF severity mapping.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _to_sarif(scan: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule_id = finding.get("vuln_class") or "unknown"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "properties": {"cwe": finding.get("cwe", "")},
            },
        )
        location: dict[str, Any] = {}
        if finding.get("affected_url"):
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["affected_url"]},
                }
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(finding.get("severity", "info"), "note"),
                "message": {"text": finding.get("summary") or finding.get("title", "")},
                "locations": [location] if location else [],
                "properties": {
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "verification_status": finding.get("verification_status"),
                    "fingerprint": finding.get("fingerprint"),
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "B-Hunters",
                        "informationUri": "https://github.com/B-Hunters/B-Hunters",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"scan": {"id": scan.get("scan_id"), "name": scan.get("name")}},
            }
        ],
    }


_HTML_ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}


def _escape(value: Any) -> str:
    text = str(value if value is not None else "")
    for needle, replacement in _HTML_ESCAPE.items():
        text = text.replace(needle, replacement)
    return text


def _to_html(
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    assets: Optional[list[dict[str, Any]]] = None,
    asset_counts: Optional[dict[str, int]] = None,
    participation: Optional[dict[str, Any]] = None,
    agents: Optional[dict[str, Any]] = None,
    integrity: Optional[dict[str, Any]] = None,
    transcript: Optional[list[dict[str, Any]]] = None,
    transcript_omitted_bytes: int = 0,
) -> str:
    """The report of a scan as an HTML document.

    The document is more than the findings: it carries the assets the
    scan saw, the tools that took part in it, the outcome of every
    agent role, the verdict of the error ledger and the transcript of
    every role.
    """
    assets = list(assets or [])
    asset_counts = dict(asset_counts or {})
    participation = dict(participation or {})
    agents = dict(agents or {})
    integrity = dict(integrity or {})
    transcript = list(transcript or [])

    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td><span class='sev sev-{_escape(finding.get('severity'))}'>"
            f"{_escape(finding.get('severity'))}</span></td>"
            f"<td>{_escape(finding.get('title'))}</td>"
            f"<td>{_escape(finding.get('vuln_class'))}</td>"
            f"<td>{_escape(finding.get('host'))}{_escape(finding.get('path'))}</td>"
            f"<td>{_escape(finding.get('verification_status'))}</td>"
            f"<td>{_escape(finding.get('summary'))}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>B-Hunters report - {_escape(scan.get("name"))}</title>
<style>
 body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;margin:2rem;color:#e6edf3;background:#0d1117}}
 h1{{font-size:1.4rem}} h2{{font-size:1.1rem;margin-top:2rem}} table{{border-collapse:collapse;width:100%;margin-top:1rem;font-size:.9rem}}
 th,td{{border-bottom:1px solid #30363d;padding:.5rem .6rem;text-align:left;vertical-align:top}}
 th{{color:#8b949e;font-weight:600}} .sev{{padding:.1rem .45rem;border-radius:.3rem;font-size:.75rem;text-transform:uppercase}}
 .sev-critical,.sev-high{{background:#6e2530;color:#ffd7de}} .sev-medium{{background:#5a3a10;color:#ffe0b3}}
 .sev-low{{background:#1f3b5c;color:#cfe4ff}} .sev-info{{background:#2b2b2b;color:#c9c9c9}}
 .meta{{color:#8b949e;font-size:.85rem}} pre{{white-space:pre-wrap;word-break:break-word;background:#161b22;padding:.6rem;border-radius:.4rem}}
 .pass{{color:#3fb950}} .fail{{color:#f85149}}
 @media print{{ body{{background:#fff;color:#111}} th{{color:#555}} pre{{background:#f6f8fa}} }}
</style></head><body>
<h1>B-Hunters report</h1>
<p class="meta">Scan <strong>{_escape(scan.get("name"))}</strong> ({_escape(scan.get("scan_id"))}) -
{len(findings)} finding(s) - status {_escape(scan.get("status"))}</p>
{_summary_html(scan, findings, asset_counts, participation, agents, integrity)}
<table><thead><tr><th>Severity</th><th>Title</th><th>Class</th><th>Location</th><th>Verification</th><th>Summary</th></tr></thead>
<tbody>{"".join(rows) or '<tr><td colspan="6">No findings were recorded.</td></tr>'}</tbody></table>
{_assets_html(assets)}
{_participation_html(participation)}
{_agents_html(agents)}
{_transcript_html(scan, transcript, transcript_omitted_bytes)}
</body></html>"""


def _summary_html(
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    asset_counts: dict[str, int],
    participation: dict[str, Any],
    agents: dict[str, Any],
    integrity: dict[str, Any],
) -> str:
    """The summary block: what the scan saw and how it ended."""
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    kinds = ", ".join(f"{kind} {count}" for kind, count in sorted(asset_counts.items()))
    severities = ", ".join(f"{name} {count}" for name, count in sorted(severity_counts.items()))
    coverage = str((participation.get("coverage") or {}).get("line", ""))
    stop_reasons = ", ".join(
        f"{reason} {count}" for reason, count in sorted((agents.get("stop_reasons") or {}).items())
    )
    verdict = str(integrity.get("verdict", ""))
    unexplained = int(integrity.get("unexplained", 0) or 0)

    return (
        "<h2>Summary</h2>"
        "<table><tbody>"
        f"<tr><td>Assets</td><td>{_escape(kinds or 'none')}</td></tr>"
        f"<tr><td>Findings by severity</td><td>{_escape(severities or 'none')}</td></tr>"
        f"<tr><td>Coverage</td><td>{_escape(coverage or 'not recorded')}</td></tr>"
        f"<tr><td>Stop reasons</td><td>{_escape(stop_reasons or 'none')}</td></tr>"
        f"<tr><td>Integrity</td><td><span class='{_escape(verdict)}'>{_escape(verdict or 'unknown')}"
        f"</span> ({unexplained} unexplained)</td></tr>"
        f"<tr><td>Roles</td><td>{_escape(agents.get('built_in_roles', 0))} built in, "
        f"{_escape(agents.get('planned_roles', 0))} planned</td></tr>"
        "</tbody></table>"
    )


def _assets_html(assets: list[dict[str, Any]]) -> str:
    """The table of the URLs the scan saw."""
    if not assets:
        return "<h2>Assets</h2><p class='meta'>No assets were recorded.</p>"
    rows = []
    for asset in assets:
        sources = ", ".join(str(item) for item in (asset.get("sources") or []))
        rows.append(
            "<tr>"
            f"<td>{_escape(asset.get('url'))}</td>"
            f"<td>{_escape(asset.get('kind'))}</td>"
            f"<td>{_escape(asset.get('scope'))}</td>"
            f"<td>{_escape(asset.get('status_code'))}</td>"
            f"<td>{_escape(asset.get('content_type'))}</td>"
            f"<td>{_escape(asset.get('size_bytes'))}</td>"
            f"<td>{_escape(sources)}</td>"
            "</tr>"
        )
    return (
        "<h2>Assets</h2>"
        "<table><thead><tr><th>URL</th><th>Kind</th><th>Scope</th><th>Status</th>"
        "<th>Content type</th><th>Size</th><th>Sources</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _participation_html(participation: dict[str, Any]) -> str:
    """The table of the tools that took part in the scan."""
    workers = list(participation.get("workers") or [])
    adapters = list(participation.get("native_adapters") or [])
    if not workers and not adapters:
        return "<h2>Participation</h2><p class='meta'>No tool took part in this scan.</p>"

    worker_rows = []
    for worker in workers:
        worker_rows.append(
            "<tr>"
            f"<td>{_escape(worker.get('worker'))}</td>"
            f"<td>{_escape(worker.get('reason'))}</td>"
            f"<td>{_escape(worker.get('tasks'))}</td>"
            f"<td>{_escape(worker.get('items'))}</td>"
            f"<td>{_escape(worker.get('findings'))}</td>"
            f"<td>{_escape(worker.get('expected_version'))}</td>"
            "</tr>"
        )
    adapter_rows = []
    for adapter in adapters:
        adapter_rows.append(
            "<tr>"
            f"<td>{_escape(adapter.get('name'))}</td>"
            f"<td>{_escape(adapter.get('status'))}</td>"
            f"<td>{_escape(adapter.get('version'))}</td>"
            f"<td>{_escape(adapter.get('items'))}</td>"
            f"<td>{_escape(adapter.get('findings'))}</td>"
            "<td></td>"
            "</tr>"
        )
    coverage = str((participation.get("coverage") or {}).get("line", ""))
    return (
        "<h2>Participation</h2>"
        f"<p class='meta'>{_escape(coverage)}</p>"
        "<table><thead><tr><th>Worker</th><th>Reason</th><th>Tasks</th><th>Items</th>"
        "<th>Findings</th><th>Expected version</th></tr></thead>"
        f"<tbody>{''.join(worker_rows)}</tbody></table>"
        "<table><thead><tr><th>Native adapter</th><th>Status</th><th>Version</th><th>Items</th>"
        f"<th>Findings</th><th></th></tr></thead><tbody>{''.join(adapter_rows)}</tbody></table>"
    )


def _agents_html(agents: dict[str, Any]) -> str:
    """The table of the agent roles and how they stopped."""
    roles = list(agents.get("roles") or [])
    if not roles:
        return "<h2>Agents</h2><p class='meta'>No agent role took part in this scan.</p>"
    rows = []
    for role in roles:
        rows.append(
            "<tr>"
            f"<td>{_escape(role.get('role'))}</td>"
            f"<td>{_escape(role.get('status'))}</td>"
            f"<td>{_escape(role.get('stop_reason'))}</td>"
            f"<td>{_escape(role.get('tasks'))}</td>"
            f"<td>{_escape(role.get('rounds'))}</td>"
            f"<td>{_escape(role.get('tool_calls'))}</td>"
            f"<td>{_escape(role.get('tokens'))}</td>"
            f"<td>{_escape(role.get('findings_raised'))}</td>"
            f"<td>{_escape(role.get('findings_confirmed'))}</td>"
            f"<td>{_escape(role.get('conclusion'))}</td>"
            "</tr>"
        )
    return (
        "<h2>Agents</h2>"
        "<table><thead><tr><th>Role</th><th>Status</th><th>Stop reason</th><th>Tasks</th>"
        "<th>Rounds</th><th>Tool calls</th><th>Tokens</th><th>Findings</th><th>Confirmed</th>"
        f"<th>Conclusion</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _transcript_html(
    scan: dict[str, Any],
    transcript: list[dict[str, Any]],
    omitted_bytes: int,
) -> str:
    """The transcript of every role, with what did not fit."""
    scan_id = str(scan.get("scan_id", ""))
    note = (
        f"<p class='meta'>The complete transcript is available from "
        f"<span class='mono'>/api/v1/scans/{_escape(scan_id)}/transcript</span>.</p>"
    )
    if omitted_bytes:
        note = (
            f"<p class='meta'>{omitted_bytes} byte(s) of the transcript were left out of this "
            "report. The complete transcript is available from "
            f"<span class='mono'>/api/v1/scans/{_escape(scan_id)}/transcript</span>.</p>"
        )
    if not transcript:
        return f"<h2>Transcript</h2>{note}<p class='meta'>No transcript was recorded.</p>"

    blocks = []
    for entry in transcript:
        role = str(entry.get("role", ""))
        text = str(entry.get("text", "") or "")
        blocks.append(
            f"<h3>{_escape(role)}</h3>"
            f"<pre>{_escape(text) if text else '(nothing was recorded for this role)'}</pre>"
        )
    return f"<h2>Transcript</h2>{note}{''.join(blocks)}"


def _to_fallback_html(
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    assets: Optional[list[dict[str, Any]]] = None,
    asset_counts: Optional[dict[str, int]] = None,
    participation: Optional[dict[str, Any]] = None,
    agents: Optional[dict[str, Any]] = None,
    integrity: Optional[dict[str, Any]] = None,
    transcript: Optional[list[dict[str, Any]]] = None,
    transcript_omitted_bytes: int = 0,
) -> str:
    """The small report the PDF falls back to.

    The transcript makes the full report large, and a browser that
    cannot print it in time still has to print something.  The
    fallback is the summary and the transcript as plain text.
    """
    assets = list(assets or [])
    asset_counts = dict(asset_counts or {})
    participation = dict(participation or {})
    agents = dict(agents or {})
    integrity = dict(integrity or {})
    transcript = list(transcript or [])

    kinds = ", ".join(f"{kind} {count}" for kind, count in sorted(asset_counts.items()))
    coverage = str((participation.get("coverage") or {}).get("line", ""))
    stop_reasons = ", ".join(
        f"{reason} {count}" for reason, count in sorted((agents.get("stop_reasons") or {}).items())
    )
    verdict = str(integrity.get("verdict", ""))
    lines = [
        f"B-Hunters report - {scan.get('name')} ({scan.get('scan_id')})",
        f"{len(findings)} finding(s) - status {scan.get('status')}",
        f"Assets: {kinds or 'none'}",
        f"Coverage: {coverage or 'not recorded'}",
        f"Stop reasons: {stop_reasons or 'none'}",
        f"Integrity: {verdict or 'unknown'} ({integrity.get('unexplained', 0)} unexplained)",
        "",
        f"Assets ({len(assets)}):",
    ]
    for asset in assets:
        lines.append(
            f"  {asset.get('url')} [{asset.get('kind')}/{asset.get('scope')}] "
            f"status {asset.get('status_code')} {asset.get('content_type')}"
        )
    lines.append("")
    lines.append("Transcript:")
    for entry in transcript:
        lines.append(f"--- {entry.get('role')}")
        text = str(entry.get("text", "") or "")
        lines.append(text if text else "(nothing was recorded for this role)")
    if transcript_omitted_bytes:
        lines.append("")
        lines.append(
            f"{transcript_omitted_bytes} byte(s) of the transcript were left out. The complete "
            f"transcript is available from /api/v1/scans/{scan.get('scan_id')}/transcript."
        )

    body = _escape("\n".join(lines))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>B-Hunters report</title>
<style> body{{font-family:sans-serif;margin:12mm}} pre{{white-space:pre-wrap;word-break:break-word}} </style>
</head><body><h1>B-Hunters report</h1><pre>{body}</pre></body></html>"""
