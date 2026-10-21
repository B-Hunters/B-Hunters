"""Findings, reports and exports."""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ...db.repositories import SEVERITIES, VERIFICATION_STATUSES
from ..deps import CurrentUser, Services, current_user, enforce_csrf, get_services, require_role

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
    """Export the findings of a scan as JSON, HTML or SARIF."""
    scan = services.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    findings = services.findings.list(scan_id, limit=5000)
    public = [_finding_public(item) for item in findings]

    if format == "json":
        payload = {
            "scan": scan.public(),
            "generated_at": __import__("time").time(),
            "finding_count": len(public),
            "findings": public,
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

    html = _to_html(scan.public(), public)
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.html"'},
    )


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


def _to_html(scan: dict[str, Any], findings: list[dict[str, Any]]) -> str:
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
 h1{{font-size:1.4rem}} table{{border-collapse:collapse;width:100%;margin-top:1rem;font-size:.9rem}}
 th,td{{border-bottom:1px solid #30363d;padding:.5rem .6rem;text-align:left;vertical-align:top}}
 th{{color:#8b949e;font-weight:600}} .sev{{padding:.1rem .45rem;border-radius:.3rem;font-size:.75rem;text-transform:uppercase}}
 .sev-critical,.sev-high{{background:#6e2530;color:#ffd7de}} .sev-medium{{background:#5a3a10;color:#ffe0b3}}
 .sev-low{{background:#1f3b5c;color:#cfe4ff}} .sev-info{{background:#2b2b2b;color:#c9c9c9}}
 .meta{{color:#8b949e;font-size:.85rem}}
</style></head><body>
<h1>B-Hunters report</h1>
<p class="meta">Scan <strong>{_escape(scan.get("name"))}</strong> ({_escape(scan.get("scan_id"))}) -
{len(findings)} finding(s) - status {_escape(scan.get("status"))}</p>
<table><thead><tr><th>Severity</th><th>Title</th><th>Class</th><th>Location</th><th>Verification</th><th>Summary</th></tr></thead>
<tbody>{"".join(rows) or '<tr><td colspan="6">No findings were recorded.</td></tr>'}</tbody></table>
</body></html>"""
