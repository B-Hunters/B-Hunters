# Authenticated Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the platform log in as a real user, crawl the authenticated surface, and prove an access-control difference between two identities — with every stored credential encrypted, every browser request inside the authorised scope, and no secret ever reaching the model, the API or a report.

**Architecture:** An identity vault stores target credentials encrypted with the deployment's secret key; the API accepts secrets and returns only masks. A login recorder runs as a runner job: it decrypts inside the runner, drives Playwright against the target's login page, verifies the session against a protected URL, and stores the encrypted browser state on the identity. The browser runs with Playwright request routing that checks every URL, method and redirect hop against the scan's `ScopePolicy`, and behind a local CONNECT proxy that validates the destination address. Agents reach the target through an `http_request` tool that injects the stored cookies and headers at call time.

**Tech Stack:** Python 3.10+, FastAPI, pymongo, Playwright (Chromium, already installed), `cryptography` (AES-GCM), `pyotp` for one-time passwords.

**Spec:** `docs/superpowers/specs/2026-10-29-single-operator-platform-design.md` — §5 (authenticated assessment) and §3.1 items 2, 3, 6, 7, 9. Read §5 and §3.1 before starting; they settle the design.

**Preconditions.** The durable foundation (the job queue, the runner, the secret key) and the asset workstream must be in place.

## Global Constraints

- Secrets are encrypted at rest with `BHUNTERS_SECRET_KEY` (AES-GCM). The API accepts them and never returns them.
- Storage state and cookies never enter model context, an event payload, a log line or a report.
- Every browser request goes through Playwright routing **and** the CONNECT proxy. Neither layer may be optional.
- The login recorder is the only path allowed to issue a state-changing request by default, and only to the configured `login_url`.
- A scan's `allow_state_changing` flag gates every other state-changing request.
- ruff clean; mypy must not gain new errors; every new module has a docstring and `from __future__ import annotations`.

---

### Task 1: The identity vault

**Files:** Create `b_hunters/platform/db/identities.py`; modify `b_hunters/platform/db/client.py`, `b_hunters/platform/api/deps.py`; test `tests/integration/test_identities.py`.

**Interfaces:**
- `IdentityRepository` with
  - `create(*, name, kind, login_url="", username="", password="", totp_secret="", headers=None, cookies=None, username_field="", password_field="", success_url="", success_selector="", verify_url="", verify_selector="", verify_text="") -> dict` — the secrets are encrypted before they are stored;
  - `get(identity_id)`, `list() -> list[dict]`, `update(identity_id, changes) -> bool`, `delete(identity_id) -> bool`;
  - `secrets_for(identity_id) -> dict[str, str]` — the decrypted secrets, for the runner only;
  - `public(identity) -> dict` — masked, never the secrets.
- The document: `identity_id`, `name`, `kind`, `login_url`, `username`, `password_ciphertext`, `totp_secret_ciphertext`, `headers_ciphertext`, `cookies_ciphertext`, `storage_state_ciphertext`, `username_field`, `password_field`, `success_url`, `success_selector`, `verify_url`, `verify_selector`, `verify_text`, `status`, `last_login_at`, `last_used_at`, `created_at`, `updated_at`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_secret_is_never_returned(services):
    identity = services.identities.create(name="webgoat", kind="form", password="hunter2", totp_secret="JBSWY3DPEHPK3PXP")
    public = services.identities.public(services.identities.get(identity["identity_id"]))
    assert "hunter2" not in str(public)
    assert "JBSWY3DPEHPK3PXP" not in str(public)
    assert public["has_password"] is True
    assert services.identities.secrets_for(identity["identity_id"])["password"] == "hunter2"


def test_a_secret_is_stored_encrypted(services):
    identity = services.identities.create(name="webgoat", kind="form", password="hunter2")
    document = services.identities.get(identity["identity_id"])
    assert document["password_ciphertext"].startswith("bh1.")
    assert "hunter2" not in str(document)
```

- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement. The repository takes the `SecretBox` from the services container. Every secret field is encrypted on write and decrypted only by `secrets_for`. `public` reports `has_password`, `has_totp`, `has_storage_state` instead of the values.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): keep the target credentials in a vault"`.

---

### Task 2: The identity API

**Files:** Create `b_hunters/platform/api/routers/identities.py`; modify `b_hunters/platform/api/app.py`; test `tests/integration/test_identity_api.py`.

**Interfaces:** `POST /api/v1/identities` (secrets in, masked out), `GET /api/v1/identities`, `GET /api/v1/identities/{id}`, `PATCH /api/v1/identities/{id}`, `DELETE /api/v1/identities/{id}`, `POST /api/v1/identities/{id}/login` → `202` with a job id.

- [ ] **Step 1:** write the failing tests (the response never carries the secret; the login endpoint returns 202 and a job).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement. The login endpoint enqueues `kind="identity_login"` with `{"identity_id": ...}` and returns `202 {"job_id": ...}`. Every use of an identity is audited with the scan id and the role, never the values.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): manage the identities through the API"`.

---

### Task 3: The login recorder

**Files:** Create `b_hunters/platform/browser/login.py`; modify `b_hunters/platform/runner.py`; test `tests/integration/test_login_recorder.py`.

**Interfaces:**
- `b_hunters.platform.browser.login.record_login(*, identity: dict, secrets: dict, settings: Settings) -> dict` → `{"status": "verified" | "failed", "reason": str, "storage_state": dict | None}`. It launches Chromium, navigates to `login_url`, fills `username_field`/`password_field` (the defaults are `username`/`password`), submits, waits for `success_url` or `success_selector`, then verifies the session by loading `verify_url` and checking `verify_selector`/`verify_text` — a `success_url` alone is not proof. TOTP is generated with `pyotp` when a secret is configured.
- The runner handles `kind="identity_login"`: it decrypts the secrets, calls `record_login`, stores the encrypted storage state on the identity and records the outcome on the job.

- [ ] **Step 1:** write the failing test with a local HTTP server that serves a login form and a protected page: the recorder logs in, the session is verified, and the storage state is returned; a wrong password yields `failed` with a reason.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement. The browser is launched with `service_workers="block"` and the route handler of Task 4. The identity's `login_url` is the only URL allowed to receive a POST.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): log in as the target's user"`.

---

### Task 4: The scope-routed browser

**Files:** Create `b_hunters/platform/browser/scope.py`, `b_hunters/platform/browser/proxy.py`; test `tests/unit/test_browser_scope.py`, `tests/integration/test_browser_proxy.py`.

**Interfaces:**
- `b_hunters.platform.browser.scope.install_scope_routes(context, policy: ScopePolicy, enforcer: ScopeEnforcer, *, on_violation=None) -> None` — a `context.route("**/*", handler)` and a `route_web_socket` handler that check the full URL, the method and every redirect hop against the policy, and abort anything out of scope. The resolved address is checked with the same rules as `ScopeEnforcer`; the handler must resolve the host itself, because the browser resolves it again.
- `b_hunters.platform.browser.proxy.ScopeProxy(policy, enforcer)` — a local HTTP proxy on `127.0.0.1` that validates the host and the resolved address of every `CONNECT` before opening the tunnel, and refuses everything else. It exposes `base_url` and `close()`.
- The browser is always launched with `proxy={"server": proxy.base_url}`; there is no direct path.

- [ ] **Step 1: Write the failing tests**

```python
def test_an_out_of_scope_request_is_refused(services):
    policy = build_policy_from_scan(authorized_hosts=["demo.test"], excluded_paths=[], allow_private_network=False, allow_http=True)
    enforcer = ScopeEnforcer(policy)
    decision = enforcer.evaluate_url("https://evil.test/x")
    assert decision.allowed is False
```

and an integration test that starts the proxy, connects to it with `CONNECT evil.test:443`, and asserts the tunnel is refused.

- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement. The route handler aborts with `route.abort()` and records the refusal through `on_violation`. The proxy resolves the host itself and refuses a private, loopback, link-local, CGNAT or metadata address unless the policy allows it.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): keep the browser inside the scope"`.

---

### Task 5: The browser tool and `browser_crawl`

**Files:** Create `b_hunters/platform/browser/tool.py`, `b_hunters/platform/scanners/browser_adapter.py`; modify `b_hunters/platform/tools/builtin/__init__.py`, `b_hunters/platform/scanners/registry.py`; test `tests/unit/test_browser_tool.py`.

**Interfaces:**
- The agent-facing tool `browser` with the actions `goto`, `click`, `fill`, `press`, `wait`, `extract_text`, `extract_html`, `screenshot` and `session_status`. There is no `storage_state` action and no JavaScript evaluation. Every action is audited; a screenshot becomes an artifact; the outputs are redacted.
- `session_status` returns a boolean and a short summary — never cookies.
- The native adapter `browser_crawl` follows links, same-origin XHR/fetch targets and hash routes, and writes the discovered URLs into the asset inventory.

- [ ] **Step 1:** write the failing test (the tool's action list contains no `storage_state` and no `evaluate`; a `session_status` result contains no cookie).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): give the agents a browser inside the scope"`.

---

### Task 6: Identity injection

**Files:** Modify `b_hunters/platform/tools/builtin/http.py`, `b_hunters/platform/scanners/base.py`, `b_hunters/platform/agents/orchestrator.py`; test `tests/security/test_identity_injection.py`.

**Interfaces:** every agent HTTP call and every native adapter can name an identity; the gateway injects the stored cookies and headers at call time, so the model never sees the values. The scan definition carries `identity_ids` (a primary and a secondary).

- [ ] **Step 1:** write the failing test (the tool call the model makes contains no cookie; the request the server receives carries it).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement. The tool context carries the identity resolver; the headers are merged into the request after the arguments are validated and before the request is made.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): scan with the target's own session"`.

---

### Task 7: The access-control comparison

**Files:** Create `b_hunters/platform/agents/access_control.py`; modify `b_hunters/platform/agents/roles.py`; test `tests/integration/test_access_control.py`.

**Interfaces:** the `access_control` role, when the scan has two identities, requests the same URL with the primary and the secondary identity and records the difference as evidence on the finding.

- [ ] **Step 1:** write the failing test (two identities, one URL, a differing status produces a finding with both responses as evidence).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): compare two sessions on the same request"`.

---

### Task 8: The OAST callback listener

**Files:** Create `b_hunters/platform/callbacks.py` (the service), `b_hunters/platform/db/callbacks.py` (the repository); modify `docker-compose.platform.yml`; test `tests/integration/test_callbacks.py`.

**Interfaces:**
- `GET|POST /cb/{token}` records the method, the path, the headers, a bounded body, the source address and the time. Every other path returns 404.
- A token is created per scan and label, is unguessable (32 bytes, URL-safe) and expires.
- `platform_callback_tokens` and `platform_callbacks` hold the tokens and the hits.
- The tools `create_callback(label)` and `list_callbacks()` are agent-facing.
- The service runs as its own container in the compose file, and only it is exposed.

- [ ] **Step 1:** write the failing test (a callback is recorded for a known token, an unknown token gets a 404, and a hit attaches to the finding that used the token).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement the service, the repository and the tools.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): receive out-of-band callbacks"`.

---

### Task 9: The scan preflight and the documentation

**Files:** Modify `b_hunters/platform/runner.py`; create `docs/authenticated-scanning.md`, `docs/oast.md`; test `tests/integration/test_identity_preflight.py`.

**Interfaces:** before a scan that names an identity, the runner verifies the stored session against `verify_url`; when it is missing, expired or failing, the runner refreshes it through the login recorder. A failed refresh fails the scan unless the template sets `on_login_failure: continue_unauthenticated`; either way a notification is sent.

- [ ] **Step 1:** write the failing test (a scan with an expired session refreshes it before the worker phase; a failed refresh fails the scan).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement, and write the two documents.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): check the session before the scan starts"`.
