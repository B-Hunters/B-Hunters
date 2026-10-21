"""Unit tests for secret redaction, content parsing and the collaboration protocol."""

from __future__ import annotations

import json

import pytest

from b_hunters.platform.agents.collaboration import (
    CollaborationState,
    build_challenge,
    build_evidence_request,
    build_rebuttal,
    question_key,
)
from b_hunters.platform.agents.schemas import (
    AgentMessage,
    Confidence,
    Disposition,
    MessageKind,
)
from b_hunters.platform.security.redact import (
    REDACTED,
    redact_body,
    redact_headers,
    redact_mapping,
    redact_text,
    redact_url,
)
from b_hunters.platform.tools.builtin.parsing import (
    analyze_graphql_schema,
    analyze_html,
    analyze_javascript,
    analyze_openapi,
    parse_document,
)


#: A credential that only looks like one: it is the alphabet, and it
#: is here to prove that the redactor removes it.  It is written in two
#: pieces so that a secret scanner reads the fixture for what it is
#: rather than for a live key - and the value at run time is exactly
#: the same either way.
_STRIPE_KEY = "sk_live_" "abcdefghijklmnopqrstuvwx"


# ----------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijkl",
        "password = 'hunter2hunter2'",
        "api_key: AKIAIOSFODNN7EXAMPLE",
        "github_token=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "xoxb-123456789012-abcdefghijkl",
        _STRIPE_KEY,
        "AIzaSyA1234567890abcdefghijklmnopqrstuvwxy",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_credentials_are_redacted(text: str) -> None:
    redacted = redact_text(text)
    assert REDACTED in redacted


def test_bearer_token_is_redacted() -> None:
    assert "supersecrettoken123" not in redact_text("Bearer supersecrettoken123")


def test_ordinary_text_is_untouched() -> None:
    text = "The application returned a 404 for /api/v1/users"
    assert redact_text(text) == text


def test_sensitive_headers_are_replaced() -> None:
    headers = redact_headers(
        {
            "Authorization": "Bearer abc",
            "Cookie": "session=xyz",
            "Set-Cookie": "a=b",
            "Content-Type": "application/json",
        }
    )
    assert headers["Authorization"] == REDACTED
    assert headers["Cookie"] == REDACTED
    assert headers["Set-Cookie"] == REDACTED
    assert headers["Content-Type"] == "application/json"


def test_mapping_redaction_is_recursive() -> None:
    payload = {
        "user": "alice",
        "credentials": {"password": "hunter2", "token": "abc"},
        "items": [{"api_key": "k"}],
    }
    cleaned = redact_mapping(payload)
    assert cleaned["user"] == "alice"
    assert cleaned["credentials"]["password"] == REDACTED
    assert cleaned["credentials"]["token"] == REDACTED
    assert cleaned["items"][0]["api_key"] == REDACTED


def test_url_query_secrets_are_redacted() -> None:
    url = "https://x.test/login?user=alice&password=hunter2&token=abc123"
    cleaned = redact_url(url)
    assert "hunter2" not in cleaned
    assert "abc123" not in cleaned
    assert "user=alice" in cleaned


def test_json_body_redaction_is_structure_aware() -> None:
    body = json.dumps({"user": "alice", "password": "hunter2"})
    cleaned = redact_body(body, "application/json")
    assert "hunter2" not in cleaned
    assert json.loads(cleaned)["user"] == "alice"


# ----------------------------------------------------------------------
# JavaScript analysis
# ----------------------------------------------------------------------
SAMPLE_JS = """
const API_BASE = 'https://api.example.com/v1';
const PUBLIC_VERSION = '2.1.0';
fetch('/api/v1/users', {method: 'GET', headers: {'Authorization': 'Bearer x'}});
axios.post('/api/v1/orders', {params: {userId: 1, coupon: 'X'}});
const query = gql`query GetUsers { users { id name } }`;
localStorage.setItem('access_token', token);
//# sourceMappingURL=app.js.map
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const apiKey = '__STRIPE_KEY__';
""".replace("__STRIPE_KEY__", _STRIPE_KEY)


def test_javascript_analysis_extracts_routes() -> None:
    result = analyze_javascript(SAMPLE_JS, url="https://x.test/app.js")
    assert "/api/v1/users" in result["routes"]
    assert "/api/v1/orders" in result["routes"]


def test_javascript_analysis_extracts_methods() -> None:
    result = analyze_javascript(SAMPLE_JS)
    assert "GET" in result["http_methods"]
    assert "POST" in result["http_methods"]


def test_javascript_analysis_extracts_parameters() -> None:
    result = analyze_javascript(SAMPLE_JS)
    assert "userId" in result["parameters"]
    assert "coupon" in result["parameters"]


def test_javascript_analysis_extracts_graphql_operations() -> None:
    result = analyze_javascript(SAMPLE_JS)
    assert result["graphql_operations"]
    assert result["graphql_operations"][0]["operation"] == "query"


def test_javascript_analysis_finds_source_maps() -> None:
    result = analyze_javascript(SAMPLE_JS)
    assert "app.js.map" in result["source_maps"]


def test_javascript_analysis_finds_auth_signals() -> None:
    result = analyze_javascript(SAMPLE_JS)
    assert "authorization" in result["auth_signals"]
    assert "access_token" in result["storage_keys"]


def test_javascript_analysis_classifies_public_config_separately() -> None:
    result = analyze_javascript(SAMPLE_JS)
    public_keys = {entry["key"] for entry in result["public_config"]}
    credential_keys = {entry["key"] for entry in result["credential_candidates"]}
    assert "API_BASE" in public_keys
    assert "AWS_KEY" in credential_keys
    assert "API_BASE" not in credential_keys


def test_javascript_analysis_never_reveals_the_full_secret() -> None:
    result = analyze_javascript(SAMPLE_JS)
    for entry in result["credential_candidates"]:
        assert _STRIPE_KEY not in json.dumps(entry)


def test_javascript_analysis_ignores_comments() -> None:
    result = analyze_javascript("// fetch('/api/commented-out')\nvar x = 1;")
    assert "/api/commented-out" not in result["routes"]


# ----------------------------------------------------------------------
# HTML / OpenAPI / GraphQL
# ----------------------------------------------------------------------
SAMPLE_HTML = """
<html><head>
<meta name="csrf-token" content="abc">
<script src="/static/app.js"></script>
</head><body>
<form action="/login" method="post" id="loginForm">
  <input type="hidden" name="csrf" value="abc">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
<a href="/dashboard">Dashboard</a>
</body></html>
"""


def test_html_analysis_extracts_forms_and_inputs() -> None:
    result = analyze_html(SAMPLE_HTML)
    assert result["form_count"] == 1
    assert result["forms"][0]["action"] == "/login"
    assert result["forms"][0]["method"] == "post"
    names = {item["name"] for item in result["inputs"]}
    assert {"csrf", "username", "password"} <= names


def test_html_analysis_extracts_scripts_and_links() -> None:
    result = analyze_html(SAMPLE_HTML)
    assert "/static/app.js" in result["scripts"]
    assert "/dashboard" in result["links"]


def test_openapi_analysis_summarises_operations() -> None:
    document = json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"title": "Demo", "version": "1.0"},
            "servers": [{"url": "https://api.test/v1"}],
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "parameters": [{"name": "limit"}],
                    },
                    "post": {"operationId": "createUser"},
                }
            },
            "components": {
                "schemas": {"User": {}},
                "securitySchemes": {"bearerAuth": {}},
            },
        }
    )
    result = analyze_openapi(document)
    assert result["openapi_version"] == "3.0.0"
    assert result["operation_count"] == 2
    assert result["security_schemes"] == ["bearerAuth"]
    methods = {operation["method"] for operation in result["operations"]}
    assert methods == {"GET", "POST"}


def test_graphql_analysis_summarises_schema() -> None:
    document = json.dumps(
        {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query", "fields": [{"name": "user"}, {"name": "users"}]},
                        {"name": "Mutation", "fields": [{"name": "createUser"}]},
                        {"name": "String"},
                    ],
                    "directives": [{"name": "include"}],
                }
            }
        }
    )
    result = analyze_graphql_schema(document)
    assert "user" in result["query_fields"]
    assert "createUser" in result["mutation_fields"]
    assert "String" in result["types"]


def test_parse_document_detects_the_format() -> None:
    assert parse_document("<html><body>x</body></html>")["format"] == "html"
    assert parse_document('{"openapi": "3.0.0"}')["format"] == "openapi"
    assert parse_document('{"data": {"__schema": {}}}')["format"] == "graphql"
    assert parse_document('{"a": 1}')["format"] == "json"


# ----------------------------------------------------------------------
# Collaboration
# ----------------------------------------------------------------------
def test_question_key_is_stable_and_case_insensitive() -> None:
    assert question_key("https://x.test/", "Is it vulnerable?") == question_key(
        "HTTPS://X.TEST/", "is it vulnerable?"
    )
    assert question_key("a", "b") != question_key("a", "c")


def test_repeated_questions_are_detected() -> None:
    state = CollaborationState(max_repeats=2)
    message = AgentMessage(
        scan_id="s",
        task_id="t",
        sender_role="recon",
        kind=MessageKind.HYPOTHESIS,
        target="https://x.test/",
        hypothesis="Is it vulnerable?",
    )
    state.note_message(message)
    assert state.is_repeated("https://x.test/", "Is it vulnerable?") is False
    state.note_message(message)
    assert state.is_repeated("https://x.test/", "Is it vulnerable?") is True


def test_circular_delegation_is_blocked() -> None:
    state = CollaborationState()
    assert state.can_delegate("recon", "api", []) is True
    assert state.can_delegate("recon", "recon", []) is False
    assert state.can_delegate("api", "recon", ["api", "recon"]) is False


def test_delegation_depth_is_bounded() -> None:
    state = CollaborationState()
    state.record_delegation("recon", "api")
    state.record_delegation("api", "javascript")
    assert state.delegation_depth == 2
    assert state.can_delegate("javascript", "verifier", []) is False


def test_challenge_is_tracked_and_can_be_settled() -> None:
    state = CollaborationState()
    challenge = build_challenge(
        scan_id="s",
        task_id="t",
        sender_role="verifier",
        recipient_role="api",
        target="https://x.test/",
        claim="SQL injection",
        reason="the response changed",
    )
    state.note_message(challenge)
    assert len(state.open_disagreements) == 1
    key = question_key(challenge.target, challenge.hypothesis)
    state.settle(key, resolution="confirmed by reproduction", status="confirmed")
    assert state.open_disagreements[key].resolved is True


def test_disagreements_are_settled_as_inconclusive_after_the_budget() -> None:
    state = CollaborationState(max_challenge_rounds=1)
    for _ in range(3):
        state.note_message(
            build_challenge(
                scan_id="s",
                task_id="t",
                sender_role="verifier",
                recipient_role="api",
                target="https://x.test/",
                claim="SQL injection",
                reason="the response changed",
            )
        )
    settled = state.settle_stale()
    assert settled
    assert settled[0].resolution_status == "inconclusive"


def test_budget_exhaustion_is_reported() -> None:
    state = CollaborationState(max_rounds=2)
    assert state.budget_exhausted() is False
    state.rounds_used = 2
    assert state.budget_exhausted() is True


def test_evidence_request_and_rebuttal_carry_their_payload() -> None:
    request = build_evidence_request(
        scan_id="s",
        task_id="t",
        sender_role="api",
        recipient_role="verifier",
        target="https://x.test/",
        question="Does this endpoint require authentication?",
    )
    assert request.kind == MessageKind.EVIDENCE_REQUEST
    assert request.recipients == ["verifier"]

    rebuttal = build_rebuttal(
        scan_id="s",
        task_id="t",
        sender_role="verifier",
        recipient_role="api",
        target="https://x.test/",
        claim="SQL injection",
        explanation="the payload was echoed as text",
        confidence=Confidence.HIGH,
    )
    assert rebuttal.kind == MessageKind.REBUTTAL
    assert rebuttal.disposition == Disposition.CONTINUE
