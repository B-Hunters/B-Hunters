"""API integration tests.

These run against a real MongoDB and exercise the authenticated API end to
end: login, session handling, CSRF, role enforcement, scan creation with
server-side scope validation, the event stream and the report exports.
"""

from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.integration


def _scan_payload(**overrides):
    payload = {
        "name": f"integration scan {int(time.time() * 1000)}",
        "targets": {
            "urls": ["https://demo.test/"],
            "authorized_hosts": ["demo.test"],
            "excluded_paths": [],
        },
        "profile": "standard",
        "scanners": ["security_headers"],
        "agent_roles": ["recon"],
        "max_concurrency": 2,
        "max_requests_per_second": 5,
        "request_timeout": 10,
        "max_duration_seconds": 120,
        "safe_mode": True,
        "allow_state_changing": False,
        "test_environment": False,
        "test_accounts": [],
    }
    payload.update(overrides)
    return payload


# ----------------------------------------------------------------------
# Authentication
# ----------------------------------------------------------------------
def test_protected_endpoints_require_a_session(client) -> None:
    for path in [
        "/api/v1/dashboard",
        "/api/v1/scans",
        "/api/v1/findings",
        "/api/v1/karton/state",
        "/api/v1/admin/users",
        "/api/v1/benchmarks",
    ]:
        response = client.get(path)
        assert response.status_code == 401, path


def test_login_with_valid_credentials_succeeds(client, admin_user) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["role"] == "admin"
    assert payload["csrf_token"]
    assert "bh_session" in response.cookies or "bh_session" in client.cookies


def test_login_with_a_wrong_password_is_rejected(client, admin_user) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_login_with_an_unknown_user_is_rejected(client) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"username": "nobody-here", "password": "whatever12345"}
    )
    assert response.status_code == 401


def test_logout_invalidates_the_session(client, admin_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.post("/api/v1/auth/logout").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_password_change_requires_the_current_password(client, admin_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    csrf = client.get("/api/v1/auth/me").json()["csrf_token"]
    response = client.post(
        "/api/v1/auth/password",
        json={"current_password": "wrong", "new_password": "AnotherStrongPass123!"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 403


# ----------------------------------------------------------------------
# CSRF
# ----------------------------------------------------------------------
def test_unsafe_requests_require_a_csrf_token(client, admin_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    response = client.post("/api/v1/scans", json=_scan_payload())
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_unsafe_requests_reject_a_wrong_csrf_token(client, admin_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    response = client.post("/api/v1/scans", json=_scan_payload(), headers={"X-CSRF-Token": "not-the-token"})
    assert response.status_code == 403


def test_safe_requests_do_not_require_a_csrf_token(client, admin_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    assert client.get("/api/v1/scans").status_code == 200


# ----------------------------------------------------------------------
# Role enforcement
# ----------------------------------------------------------------------
def test_viewer_cannot_create_a_scan(client, viewer_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": viewer_user["username"], "password": viewer_user["password"]},
    )
    csrf = client.get("/api/v1/auth/me").json()["csrf_token"]
    response = client.post("/api/v1/scans", json=_scan_payload(), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 403


def test_operator_cannot_manage_users(client, operator_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": operator_user["username"], "password": operator_user["password"]},
    )
    assert client.get("/api/v1/admin/users").status_code == 403


def test_admin_can_manage_users(client, admin_user) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"username": admin_user["username"], "password": admin_user["password"]},
    )
    assert client.get("/api/v1/admin/users").status_code == 200


# ----------------------------------------------------------------------
# Scope validation
# ----------------------------------------------------------------------
def test_a_target_outside_the_authorised_hosts_is_refused(client, admin_user, auth_headers) -> None:
    response = client.post(
        "/api/v1/scans/preview",
        json=_scan_payload(
            targets={
                "urls": ["https://evil.test/"],
                "authorized_hosts": ["demo.test"],
                "excluded_paths": [],
            }
        ),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["out_of_scope"]
    assert body["accepted_urls"] == []


def test_a_target_inside_the_authorised_hosts_is_accepted(client, admin_user, auth_headers) -> None:
    response = client.post("/api/v1/scans/preview", json=_scan_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["accepted_urls"] == ["https://demo.test/"]
    assert body["out_of_scope"] == []


def test_creating_a_scan_with_an_out_of_scope_target_is_refused(client, admin_user, auth_headers) -> None:
    response = client.post(
        "/api/v1/scans",
        json=_scan_payload(
            targets={
                "urls": ["https://evil.test/"],
                "authorized_hosts": ["demo.test"],
                "excluded_paths": [],
            }
        ),
        headers=auth_headers,
    )
    assert response.status_code == 400


def test_a_scan_without_authorised_hosts_is_refused(client, admin_user, auth_headers) -> None:
    response = client.post(
        "/api/v1/scans",
        json=_scan_payload(
            targets={"urls": ["https://demo.test/"], "authorized_hosts": [], "excluded_paths": []}
        ),
        headers=auth_headers,
    )
    assert response.status_code == 400


def test_a_discovered_host_is_not_implicitly_authorised(client, admin_user, auth_headers) -> None:
    """Only the declared hosts may be scanned, never a discovered one."""
    response = client.post(
        "/api/v1/scans/preview",
        json=_scan_payload(
            targets={
                "urls": ["https://demo.test/", "https://cdn.elsewhere.test/app.js"],
                "authorized_hosts": ["demo.test"],
                "excluded_paths": [],
            }
        ),
    )
    body = response.json()
    assert body["accepted_urls"] == ["https://demo.test/"]
    assert len(body["out_of_scope"]) == 1
    assert body["out_of_scope"][0]["url"] == "https://cdn.elsewhere.test/app.js"


# ----------------------------------------------------------------------
# Scan lifecycle
# ----------------------------------------------------------------------
def test_a_scan_can_be_created_and_fetched(client, admin_user, auth_headers) -> None:
    created = client.post("/api/v1/scans", json=_scan_payload(), headers=auth_headers)
    assert created.status_code == 201
    scan_id = created.json()["scan_id"]

    fetched = client.get(f"/api/v1/scans/{scan_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["status"] == "queued"
    assert body["scope"]["authorized_hosts"] == ["demo.test"]
    assert "finding_counts" in body
    assert "task_counts" in body


def test_scans_can_be_listed(client, admin_user, auth_headers) -> None:
    client.post("/api/v1/scans", json=_scan_payload(), headers=auth_headers)
    response = client.get("/api/v1/scans")
    assert response.status_code == 200
    assert response.json()["count"] >= 1


def test_every_endpoint_returns_json_serialisable_documents(
    client, authenticated, services
) -> None:
    """No endpoint may leak a BSON ObjectId into a JSON response.

    A raw MongoDB document carries an ``_id`` that the JSON encoder cannot
    represent, so every endpoint that returns repository output must strip
    it.  This test walks the whole authenticated surface.
    """
    scan = services.scans.create(
        {
            "name": "serialisation fixture",
            "status": "running",
            "created_by": authenticated["username"],
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    services.agents.upsert(
        scan_id=scan.scan_id, role="recon", status="idle", conclusion="done"
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title="Finding",
        summary="s",
        vuln_class="xss",
        severity="high",
        host="demo.test",
    )
    services.messages.append(
        {
            "scan_id": scan.scan_id,
            "task_id": "t",
            "sender_role": "recon",
            "kind": "observation",
            "hypothesis": "h",
        }
    )
    services.tool_calls.record(
        {"scan_id": scan.scan_id, "task_id": "t", "agent_role": "recon", "tool": "list_findings", "status": "ok"}
    )

    paths = [
        "/api/v1/dashboard",
        "/api/v1/scans",
        f"/api/v1/scans/{scan.scan_id}",
        f"/api/v1/scans/{scan.scan_id}/tasks",
        f"/api/v1/scans/{scan.scan_id}/agents",
        f"/api/v1/scans/{scan.scan_id}/messages",
        f"/api/v1/scans/{scan.scan_id}/tool-calls",
        f"/api/v1/scans/{scan.scan_id}/events",
        f"/api/v1/findings?scan_id={scan.scan_id}",
        "/api/v1/karton/state",
        "/api/v1/karton/analyses",
        "/api/v1/admin/users",
        "/api/v1/admin/providers",
        "/api/v1/admin/agent-definitions",
        "/api/v1/admin/audit",
        "/api/v1/benchmarks",
        "/api/v1/benchmarks/runs",
    ]
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, f"{path} -> {response.status_code} {response.text[:200]}"
        # A 500 here means the response contained an unserialisable value.
        assert response.headers["content-type"].startswith("application/json"), path
        response.json()


def test_a_missing_scan_returns_404(client, authenticated) -> None:
    assert client.get("/api/v1/scans/does-not-exist").status_code == 404


def test_scan_events_are_replayable(client, admin_user, auth_headers) -> None:
    created = client.post("/api/v1/scans", json=_scan_payload(), headers=auth_headers)
    scan_id = created.json()["scan_id"]

    events = client.get(f"/api/v1/scans/{scan_id}/events")
    assert events.status_code == 200
    body = events.json()
    assert body["events"], "the scan creation must produce an event"
    first_seq = body["events"][0]["seq"]

    # Replaying from the first sequence returns only later events.
    replay = client.get(f"/api/v1/scans/{scan_id}/events?after={first_seq}")
    assert replay.status_code == 200
    assert all(event["seq"] > first_seq for event in replay.json()["events"])


def test_pause_resume_and_stop_are_reflected_in_the_backend(client, admin_user, auth_headers) -> None:
    created = client.post("/api/v1/scans", json=_scan_payload(), headers=auth_headers)
    scan_id = created.json()["scan_id"]

    paused = client.post(f"/api/v1/scans/{scan_id}/pause", headers=auth_headers)
    assert paused.status_code == 200
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "paused"

    resumed = client.post(f"/api/v1/scans/{scan_id}/resume", headers=auth_headers)
    assert resumed.status_code == 200
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "running"

    stopped = client.post(f"/api/v1/scans/{scan_id}/stop", headers=auth_headers)
    assert stopped.status_code == 200
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] in {"stopping", "cancelled"}


def test_a_scan_cannot_be_started_twice(client, admin_user, auth_headers) -> None:
    created = client.post("/api/v1/scans", json=_scan_payload(), headers=auth_headers)
    scan_id = created.json()["scan_id"]
    first = client.post(f"/api/v1/scans/{scan_id}/start", headers=auth_headers)
    assert first.status_code == 200
    second = client.post(f"/api/v1/scans/{scan_id}/start", headers=auth_headers)
    assert second.status_code == 409


# ----------------------------------------------------------------------
# Findings and reports
# ----------------------------------------------------------------------
def test_findings_can_be_filtered(client, admin_user, auth_headers, services) -> None:
    scan = services.scans.create(
        {
            "name": "finding fixture",
            "status": "completed",
            "created_by": admin_user["username"],
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
        }
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title="Reflected XSS",
        summary="The parameter is reflected unescaped",
        vuln_class="xss",
        severity="high",
        host="demo.test",
        path="/search",
        confidence=0.8,
        detected_by=["scanner:x"],
        affected_url="https://demo.test/search?q=1",
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title="Missing CSP",
        summary="No Content-Security-Policy header",
        vuln_class="security_headers",
        severity="low",
        host="demo.test",
        confidence=0.9,
        detected_by=["scanner:y"],
    )

    response = client.get(f"/api/v1/findings?scan_id={scan.scan_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2

    high = client.get(f"/api/v1/findings?scan_id={scan.scan_id}&severity=high")
    assert high.json()["count"] == 1

    xss = client.get(f"/api/v1/findings?scan_id={scan.scan_id}&vuln_class=xss")
    assert xss.json()["count"] == 1


def test_an_unknown_severity_filter_is_rejected(client, authenticated) -> None:
    response = client.get("/api/v1/findings?severity=catastrophic")
    assert response.status_code == 400


def test_a_finding_can_be_verified(client, admin_user, auth_headers, services) -> None:
    scan = services.scans.create(
        {
            "name": "verification fixture",
            "status": "completed",
            "created_by": admin_user["username"],
            "definition": {},
            "scope": {},
        }
    )
    _document, _created = services.findings.upsert(
        scan_id=scan.scan_id,
        title="Candidate",
        summary="s",
        vuln_class="xss",
        severity="medium",
        host="demo.test",
    )
    finding_id = services.findings.list(scan.scan_id)[0]["finding_id"]

    response = client.post(
        f"/api/v1/findings/{finding_id}/verification",
        json={
            "status": "rejected",
            "notes": "the value is escaped",
            "severity": "info",
            "false_positive_reason": "the response escapes the value",
        },
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["verification_status"] == "rejected"
    assert response.json()["severity"] == "info"


def test_reports_can_be_exported_as_json_sarif_and_html(client, admin_user, auth_headers, services) -> None:
    scan = services.scans.create(
        {
            "name": "export fixture",
            "status": "completed",
            "created_by": admin_user["username"],
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {},
        }
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title="SQL injection",
        summary="The parameter is injectable",
        vuln_class="sql_injection",
        severity="critical",
        cwe="CWE-89",
        host="demo.test",
        path="/item",
        affected_url="https://demo.test/item?id=1",
    )

    json_response = client.get(f"/api/v1/scans/{scan.scan_id}/report?format=json")
    assert json_response.status_code == 200
    payload = json_response.json()
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["vuln_class"] == "sql_injection"

    sarif = client.get(f"/api/v1/scans/{scan.scan_id}/report?format=sarif")
    assert sarif.status_code == 200
    document = sarif.json()
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "sql_injection"
    assert document["runs"][0]["results"][0]["level"] == "error"

    html = client.get(f"/api/v1/scans/{scan.scan_id}/report?format=html")
    assert html.status_code == 200
    assert "SQL injection" in html.text


# ----------------------------------------------------------------------
# Dashboard and monitoring
# ----------------------------------------------------------------------
def test_the_dashboard_reports_real_counts(client, admin_user, auth_headers, services) -> None:
    scan = services.scans.create(
        {
            "name": "dashboard fixture",
            "status": "running",
            "created_by": admin_user["username"],
            "definition": {},
            "scope": {},
        }
    )
    services.findings.upsert(
        scan_id=scan.scan_id,
        title="Finding",
        summary="s",
        vuln_class="xss",
        severity="high",
        host="demo.test",
    )

    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["scans"]["total"] >= 1
    assert body["scans"]["running"] >= 1
    assert body["findings"]["total"] >= 1
    assert body["findings"]["by_severity"]["high"] >= 1
    assert "karton" in body
    assert "tools" in body
    assert "agents" in body


def test_karton_state_is_reported_or_declared_unavailable(client, authenticated) -> None:
    response = client.get("/api/v1/karton/state")
    assert response.status_code == 200
    body = response.json()
    if not body.get("available"):
        assert body.get("error")
    else:
        assert "queues" in body
        assert "totals" in body


def test_agent_roles_are_exposed(client, authenticated) -> None:
    response = client.get("/api/v1/admin/agent-roles")
    assert response.status_code == 200
    roles = response.json()["roles"]
    assert len(roles) >= 10
    assert all("system_prompt" in role for role in roles)


def test_scanner_specs_are_exposed(client, authenticated) -> None:
    response = client.get("/api/v1/scans/scanner-specs")
    assert response.status_code == 200
    scanners = response.json()["scanners"]
    assert len(scanners) >= 17
    assert all(item["license"] for item in scanners)
    assert all(item["version"] for item in scanners)


def test_the_audit_log_records_privileged_actions(client, admin_user, auth_headers) -> None:
    client.post("/api/v1/scans", json=_scan_payload(), headers=auth_headers)
    response = client.get("/api/v1/admin/audit?action=scan.create")
    assert response.status_code == 200
    assert response.json()["count"] >= 1
    entry = response.json()["items"][0]
    assert entry["actor"] == admin_user["username"]
    assert entry["outcome"] == "success"


def test_the_health_endpoint_reports_the_database(client) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["database"] is True
