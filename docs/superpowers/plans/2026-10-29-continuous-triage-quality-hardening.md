# Continuous Assessment, Triage, Agent Quality and Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the platform run on its own (schedules, diffs, inventory, notifications, a CI entry point), make its output usable (triage lifecycle, comments, CVSS/OWASP, a PDF report, trends), make its agents efficient and measurable (early stop, a round cap, provider failover, cost), and make it safe to leave running (no credentials in git, pinned tooling, a production compose, a clean type check, a tested frontend).

**Architecture:** Each phase is additive and ships on its own. Schedules are claimed atomically by the runner's scheduler loop and enqueue the same jobs the API enqueues. Findings become durable issues, and the diff compares two comparable scans of the same target by the issue key. The triage state lives on the issue; the report renders the issue with its evidence. The agent runtime stops a role when it stops producing evidence, and the round budget becomes a cap instead of a floor. A provider pool tries providers in priority order and records which one answered.

**Tech Stack:** Python 3.10+, FastAPI, pymongo against MongoDB 7, `croniter` for schedules, Playwright (already installed) for the PDF report, `node --test` for the frontend, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-29-single-operator-platform-design.md` — §6 (continuous assessment), §7 (triage and reporting), §8 (agent quality), §9 (hardening), §10, §11, §13. Read it before starting: this plan maps its decisions onto files and tests.

**Preconditions.** The durable foundation (`docs/superpowers/plans/2026-10-29-durable-foundation.md`) and the asset workstream (`docs/superpowers/plans/2026-10-29-asset-collection-and-reporting.md`) must be in place: this plan uses the job queue, the runner, the durable issues and the asset inventory.

## Global Constraints

- Every new module starts with `from __future__ import annotations` and a module docstring.
- Python 3.10-compatible syntax; `ruff check b_hunters tests` and `ruff format --check b_hunters tests` pass before every commit.
- mypy must not gain new errors. The repository has pre-existing errors; do not fix them in this plan unless a task says so.
- Scope enforcement stays mandatory; the PDF renderer fetches nothing but the local report.
- Secrets never enter git, Mongo, an API response, a log line or a report.
- The legacy collections (`scans`, `domains`, `reports`, `js`) stay read-only.
- Every new collection is `platform_*` and registered in `PLATFORM_COLLECTIONS` and `INDEXES`.
- Test commands: `/home/sniper/pentest/.venv/bin/python -m pytest tests -q` with `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"`.

## Review Focus

1. **A schedule must not run twice** — pinned in Task 1 (`test_a_due_schedule_is_claimed_exactly_once`).
2. **A diff must not claim a fix when the two scans are not comparable** — pinned in Task 3 (`test_a_diff_against_a_different_profile_is_not_comparable`).
3. **A finding must not disappear from the triage view when it recurs** — pinned in Task 6 (`test_a_recurring_finding_reopens_its_issue`).
4. **A provider failure must fall over to the next provider without losing the scan** — pinned in Task 10 (`test_the_next_provider_answers_when_the_first_fails`).
5. **No credential may appear in a tracked file** — pinned in Task 12 (`test_no_tracked_file_contains_a_credential`).

---

## Phase 3 — Continuous assessment

### Task 1: Schedules

**Files:**
- Create: `b_hunters/platform/schedules.py`
- Modify: `b_hunters/platform/db/client.py`, `b_hunters/platform/api/routers/assets.py`, `b_hunters/platform/runner.py`, `requirements.txt`
- Test: `tests/integration/test_schedules.py`

**Interfaces:**
- Produces: `b_hunters.platform.schedules.ScheduleRepository` with `create(*, name, template, cron, timezone="UTC", enabled=True) -> dict`, `get(schedule_id)`, `list() -> list[dict]`, `update(schedule_id, changes) -> bool`, `delete(schedule_id) -> bool`, `claim_due(now: float) -> dict | None` (an atomic `find_one_and_update` on `next_run_at <= now` that advances `next_run_at` with `croniter`), `record_run(schedule_id, scan_id) -> bool`.
- Produces: `GET/POST /api/v1/schedules`, `POST /api/v1/schedules/{id}/run`, `PATCH /api/v1/schedules/{id}`.
- The runner's loop calls `claim_due` and enqueues a `kind="scan"` job with the schedule's template.

- [ ] **Step 1: Write the failing test**

```python
def test_a_due_schedule_is_claimed_exactly_once(services):
    repo = services.schedules
    repo.create(name="nightly", template={"targets": {"urls": ["https://demo.test/"]}}, cron="0 3 * * *")
    first = repo.claim_due(now=time.time() + 86400)
    second = repo.claim_due(now=time.time() + 86400)
    assert first is not None
    assert second is None


def test_an_invalid_cron_expression_is_refused(services):
    import pytest
    with pytest.raises(ValueError):
        services.schedules.create(name="bad", template={}, cron="not a cron")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_schedules.py -q`
Expected: FAIL — `services.schedules` does not exist.

- [ ] **Step 3: Implement the schedules**

`b_hunters/platform/schedules.py` holds the repository; the cron parsing uses `croniter` (add `croniter>=2,<7` to `requirements.txt` and the platform extras). `claim_due` uses `find_one_and_update` with `{"enabled": True, "next_run_at": {"$lte": now}}`, sorted by `next_run_at`, setting the new `next_run_at` computed with `croniter(cron, now)`. An invalid expression raises `ValueError` at create time and is refused by the API with a 400.

The runner calls `claim_due` in its loop and enqueues the job. The API endpoints create, list, update, delete and run-now a schedule.

- [ ] **Step 4: Run the test to verify it passes** — expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(platform): run the scans on a schedule"`.

---

### Task 2: Scan templates

**Files:** Create `b_hunters/platform/templates.py`; modify the API router; test `tests/integration/test_templates.py`.

**Interfaces:** `TemplateRepository` with `create(*, name, definition) -> dict`, `get`, `list`, `delete`; `GET/POST /api/v1/templates`. A template's `definition` is the scan request body, so "run this template" is "create a scan from this definition".

- [ ] **Step 1:** write the failing test (create, list, and a scan created from a template has the template's targets).
- [ ] **Step 2:** run it, expect FAIL.
- [ ] **Step 3:** implement the repository and the endpoints.
- [ ] **Step 4:** run it, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): save a scan as a template"`.

---

### Task 3: Scan diffing

**Files:** Create `b_hunters/platform/diffing.py`; modify the API router; test `tests/integration/test_diffing.py`.

**Interfaces:**
- `b_hunters.platform.diffing.comparison_key(scan: dict) -> str` — the hash of the target key, the scope, the profile, the scanner set, the role set and the identity ids.
- `b_hunters.platform.diffing.compare(*, current: dict, baseline: dict | None, issues_current: list[dict], issues_baseline: list[dict], comparable: bool, reason: str) -> dict` → `{"comparable": bool, "reason": str, "new": [...], "fixed": [...], "reopened": [...], "persistent": [...]}`.
- `GET /api/v1/scans/{id}/diff?against={other_id}`.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_diff_against_a_different_profile_is_not_comparable():
    result = compare(current={"comparison_key": "a"}, baseline={"comparison_key": "b"}, issues_current=[], issues_baseline=[], comparable=False, reason="the profile differs")
    assert result["comparable"] is False
    assert result["fixed"] == []


def test_a_issue_absent_from_the_current_scan_is_not_observed():
    result = compare(current={"comparison_key": "a"}, baseline={"comparison_key": "a"}, issues_current=[], issues_baseline=[{"issue_id": "i1", "fingerprint": "f"}], comparable=True, reason="")
    assert result["fixed"] == []
    assert result["not_observed"] == ["i1"]
```

- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement. A comparable pair needs the same `comparison_key` and a healthy worker phase in both. The groups: `new` (an issue whose first sighting is this scan), `persistent` (in both), `reopened` (an issue that was auto-closed or fixed and is observed again), `not_observed` (in the baseline, absent now). `fixed` is only produced by the auto-close rule of Task 6, never by absence alone.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): compare two scans of the same target"`.

---

### Task 4: The cross-scan inventory

**Files:** Modify `b_hunters/platform/api/routers/assets.py`; test `tests/integration/test_inventory.py`.

**Interfaces:** `GET /api/v1/inventory?host=&kind=` → `{"hosts": [{"host", "urls", "first_seen", "last_seen", "scans", "open_findings", "technologies", "ports"}], "count"}`, aggregated from `platform_assets`, `platform_services` and `platform_findings`.

- [ ] **Step 1:** write the failing test (a host seen in two scans is listed once with its first and last sighting).
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement the aggregation with a Mongo pipeline over `platform_assets`.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): list the assets across every scan"`.

---

### Task 5: Notifications and the CI entry point

**Files:** Create `b_hunters/platform/notifications.py`; modify the API router and the CLI; test `tests/integration/test_notifications.py`.

**Interfaces:**
- `NotificationRepository` with `create(*, name, kind, target, events, secret="", filters={}) -> dict`, `list()`, `update`, `delete`, and `due(now) -> list[dict]`.
- A delivery worker in the runner that posts the JSON payload (with an HMAC signature when a secret is set) and records every delivery in `platform_notification_deliveries`.
- `POST /api/v1/tokens` creating a hashed API token with scopes; the API accepts `Authorization: Bearer <token>` with CSRF exempt.
- `b-hunters ci scan --target ... --wait --fail-on high` in the CLI.

- [ ] **Step 1:** write the failing tests (a webhook receives a signed payload; a token authenticates a request; the CI command exits non-zero on a high finding).
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement. The token is stored as a SHA-256 hash; the plaintext is returned once. The CI command polls the scan and prints the findings.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): notify on the events that matter and scan from CI"`.

---

## Phase 4 — Triage and reporting

### Task 6: The triage lifecycle on the issue

**Files:** Modify `b_hunters/platform/db/issues.py`, `b_hunters/platform/api/routers/assets.py`; test `tests/integration/test_triage.py`.

**Interfaces:**
- `IssueRepository.set_triage(issue_id, *, status, assignee="", tags=(), due_at=None, note="") -> bool` — already present; extend it with `duplicate_of`.
- `IssueRepository.apply_scan_observations(...)` — already present; it must also **reopen** an issue that was `fixed` or `auto_closed` when it is observed again, and record the event.
- `POST /api/v1/issues/{id}/triage`, `POST /api/v1/issues/bulk`, `GET /api/v1/issues`, `GET /api/v1/issues/{id}/history`.

- [ ] **Step 1: Write the failing test**

```python
def test_a_recurring_finding_reopens_its_issue(services):
    issue, _ = services.issues.upsert_for_finding(scan_id=scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss")
    services.issues.set_triage(issue["issue_id"], status="fixed")
    services.issues.apply_scan_observations(scan_id=scan_id, target_key="demo.test", observed_fingerprints=["fp"])
    refreshed = services.issues.get(issue["issue_id"])
    assert refreshed["triage_status"] == "open"
    assert refreshed["observation_status"] == "observed"
```

- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement the reopen rule and the endpoints.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): triage a finding once, across every scan"`.

---

### Task 7: Comments

**Files:** Create `b_hunters/platform/db/comments.py`; modify the API router; test `tests/integration/test_comments.py`.

**Interfaces:** `CommentRepository` with `add(*, issue_id, scan_id, finding_id, author, body) -> dict`, `list_for_issue(issue_id) -> list[dict]`, `delete(comment_id, author) -> bool`; `GET/POST /api/v1/issues/{id}/comments`. A comment is editable only by its author; a delete is audited.

- [ ] **Step 1:** write the failing test.
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): comment on a finding"`.

---

### Task 8: CVSS and OWASP

**Files:** Create `b_hunters/platform/cvss.py`; test `tests/unit/test_cvss.py`.

**Interfaces:** `parse_vector(vector: str) -> dict[str, str]`, `base_score(vector: str) -> float`, `severity_from_score(score: float) -> str`, and `owasp_category(vuln_class: str) -> str` — a mapping from the platform's vulnerability classes to OWASP Top 10 (2021).

The calculator follows CVSS 3.1: the weights for AV, AC, PR, UI, S, C, I, A; the impact subscore with the 6.42 × (1 − (1 − C) × (1 − I) × (1 − A)); the exploitability subscore 8.22 × AV × AC × PR × UI; and the base score `0` when the impact is zero, otherwise `roundup(min(impact + exploitability, 10))`. The round-up is the 3.1 definition (round to one decimal, then add the smallest number that makes it a multiple of 0.1).

- [ ] **Step 1:** write the failing tests, including the published vectors (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8; `.../AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → 8.8; `.../AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L` → 3.9).
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement, without a dependency.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): score a finding with CVSS 3.1"`.

---

### Task 9: The PDF report

**Files:** Create `b_hunters/platform/pdf.py`; modify `b_hunters/platform/api/routers/findings.py`, `requirements.txt`, `setup.py`, `Dockerfile`; test `tests/integration/test_pdf.py`.

**Interfaces:** `render_pdf(html: str, *, timeout_seconds: int = 120) -> bytes` using Playwright's Chromium; `GET /api/v1/scans/{id}/report.pdf` returning `application/pdf`. When the render exceeds the timeout, the fallback HTML — the summary with the transcript as plain text — is rendered instead; the response says which one it is in a header.

The Dockerfile installs the browser: `playwright install --with-deps chromium` in the image build, and `playwright` is added to the platform requirements.

- [ ] **Step 1:** write the failing test (the endpoint returns a PDF whose bytes start with `%PDF`).
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement the renderer and the route.
- [ ] **Step 4:** run, expect PASS. If Chromium is missing in the test environment, the test skips with a clear message and the image build is verified separately.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): render the report as a PDF"`.

---

### Task 10: Trends

**Files:** Modify `b_hunters/platform/api/routers/dashboard.py`; test `tests/integration/test_trends.py`.

**Interfaces:** `GET /api/v1/dashboard/trends?days=30` → `{"open_by_severity": [...], "new_vs_fixed": [...], "verified_rate": 0.0, "mean_time_to_triage_seconds": 0}`.

- [ ] **Step 1:** write the failing test.
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement the aggregation over the issues.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): show the triage trend"`.

---

## Phase 5 — Agent quality

### Task 11: Stop when there is no new evidence, and a round cap

**Files:** Modify `b_hunters/platform/agents/runtime.py`, `b_hunters/platform/agents/roles.py`, `b_hunters/platform/settings.py`; test `tests/unit/test_agent_early_stop.py`.

**Interfaces:**
- The runtime counts a round that produced no new tool result, finding, observation or URL. Three in a row end the task with its current conclusion; the stop reason is `no_new_evidence`.
- `BHUNTERS_AGENT_MAX_ROUNDS` becomes a **cap**: the role's own rounds apply below it. A role that declares 24 and the deployment caps at 8 runs 8.

- [ ] **Step 1:** write the failing tests (a scripted provider that returns nothing new three times ends the task at three rounds; a role's rounds never exceed the cap).
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement. `AgentRuntime` keeps the set of the tool results, findings, observations and URLs it has already seen; the runtime compares each round against it.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): stop a role when it stops finding things"`.

---

### Task 12: Provider failover and cost

**Files:** Modify `b_hunters/platform/agents/provider.py`, `b_hunters/platform/db/repositories.py`, `b_hunters/platform/agents/factory.py`; test `tests/unit/test_provider_failover.py`.

**Interfaces:**
- `ProviderPool(providers: Sequence[Provider], *, on_use: Callable[[str], None] | None = None)` with `async def complete(...)` that tries each provider in priority order on an auth, rate-limit, timeout or server failure, and raises the last error when all fail.
- The provider document gains `priority`, `price_per_million_prompt`, `price_per_million_completion`.
- The scan records the tokens and the estimated cost per provider in `platform_provider_usage`.
- `GET /api/v1/usage` → the cost per scan, per role and per provider.

- [ ] **Step 1:** write the failing test — a pool with a failing primary and a working secondary completes through the secondary and records which one answered.
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): fall over to the next provider and count the cost"`.

---

### Task 13: The per-role benchmark

**Files:** Modify `b_hunters/platform/bench/runner.py`, `b_hunters/platform/bench/scoring.py`, `b_hunters/cli.py`; test `tests/integration/test_agent_benchmark.py`.

**Interfaces:** `b-hunters bench agents --applications dvga,webgoat --roles recon,api --provider <name> --runs 1` runs the agent phase against the benchmark manifest, attributes each finding to `detected_by`, and scores precision, recall and F1 per role and overall. The results go to `platform_benchmark_runs` with `mode="agent"`.

- [ ] **Step 1:** write the failing test (a scripted agent run produces a per-role score row).
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): measure every agent role"`.

---

## Phase 6 — Hardening

### Task 14: No credentials in the repository

**Files:** Modify `deploy/platform.ini`, `deploy/b-hunters.ini`, `.gitignore`, `scripts/render_config.py` (create); modify `b_hunters/cli.py` for `admin set-password` and `admin rotate-key`; test `tests/unit/test_no_tracked_credentials.py`.

**Interfaces:** `render_config.py` reads `.env` and writes the INI files from `*.example.ini` templates. The tracked files become `*.example.ini`; the real files are gitignored. `b-hunters admin rotate-key` re-encrypts every stored credential with a new key.

- [ ] **Step 1: Write the failing test**

```python
def test_no_tracked_file_contains_a_credential():
    import re
    import subprocess
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    pattern = re.compile(r"(?i)(password|api[_-]?key|secret|token)\s*=\s*[\"']?[A-Za-z0-9!@#$%^&*_\-]{8,}")
    offenders = [name for name in files if pattern.search(open(name, encoding="utf-8", errors="ignore").read())]
    assert offenders == []
```

The pattern must not match the example files' placeholders — the examples use `<...>` placeholders that the pattern does not accept.

- [ ] **Step 2:** run, expect FAIL (the deployment files carry the development credentials today).
- [ ] **Step 3:** implement — replace the tracked files with examples, add the renderer, gitignore the real files, and add the two CLI commands.
- [ ] **Step 4:** run, expect PASS.
- [ ] **Step 5:** commit — `git commit -m "security: keep the credentials out of the repository"`.

---

### Task 15: The pinned xray image and the pinned tooling

**Files:** Modify `repos/B-Hunters-xray/Dockerfile` (a different repository — do it there, in its own commit), `docs/supply-chain.md` (create).

**Interfaces:** The xray image downloads a pinned release and verifies its SHA-256; the binary is removed from git. The scanner tool versions and the base images are pinned in every worker Dockerfile.

- [ ] **Step 1:** write the verification script `scripts/check_supply_chain.py` that reads each worker Dockerfile and fails when a version or a base image is not pinned.
- [ ] **Step 2:** run it, expect FAIL.
- [ ] **Step 3:** pin the versions and remove the binary.
- [ ] **Step 4:** run it, expect PASS.
- [ ] **Step 5:** commit in each repository separately — `git commit -m "build: pin the scanner versions and the base images"`.

---

### Task 16: The production compose

**Files:** Create `docker-compose.prod.yml`, `deploy/caddy/Caddyfile`; modify `docs/tailnet-deployment.md`; test `tests/unit/test_prod_compose.py`.

**Interfaces:** Caddy in front of the platform with TLS and HSTS; no published Mongo, Redis or S3 ports; `BHUNTERS_SESSION_COOKIE_SECURE=true`; `BHUNTERS_ENVIRONMENT=production`; resource limits; a `mongodump` backup service; health checks for the runner and the callback service.

- [ ] **Step 1:** write the failing test (the compose file has no published database ports and sets the secure cookie).
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run, expect PASS and `docker compose -f docker-compose.prod.yml config` must succeed.
- [ ] **Step 5:** commit — `git commit -m "deploy: add a production compose with TLS"`.

---

### Task 17: A clean type check

**Files:** Modify the modules mypy reports on; modify `.github/workflows/ci.yml` to make the job blocking.

**Interfaces:** `mypy b_hunters/platform --ignore-missing-imports --no-strict-optional` reports no errors.

- [ ] **Step 1:** run mypy and record the 36 errors.
- [ ] **Step 2:** fix them, one module at a time, keeping the behaviour.
- [ ] **Step 3:** run mypy again — expected: no errors.
- [ ] **Step 4:** run the full suite — expected: every test still passes.
- [ ] **Step 5:** commit — `git commit -m "build: make the type check pass"`.

---

### Task 18: The frontend as modules, with tests

**Files:** Create `b_hunters/web/js/*.js`; modify `b_hunters/web/app.js`; test `tests/frontend/*.test.js`.

**Interfaces:** the console is split into `js/api.js`, `js/router.js`, `js/format.js`, `js/components.js`, `js/views/*.js` and `js/main.js`, all native ES modules with no bundler. `node --test tests/frontend/` runs the unit tests. The CI job runs them.

- [ ] **Step 1:** write the failing tests for the pure functions — escaping, formatting, route resolution, diff grouping, table rendering.
- [ ] **Step 2:** run `node --test tests/frontend/` — expect FAIL.
- [ ] **Step 3:** split the console, keeping every view working.
- [ ] **Step 4:** run the tests — expect PASS — and load the console in a browser to confirm the pages still render.
- [ ] **Step 5:** commit — `git commit -m "refactor(console): split the frontend into tested modules"`.

---

### Task 19: The documentation set

**Files:** Modify `README.md`, `STATUS.md`, `docs/implementation-report.md`, `docs/architecture-audit.md`, `docs/threat-model.md`; create `docs/schedules.md`, `docs/triage.md`, `docs/agent-evaluation.md`, `docs/supply-chain.md`.

**Interfaces:** every claim is a measured command output. The threat model gains the identity vault, the scope-routed browser and the OAST listener.

- [ ] **Step 1:** run the full suite, the linters and mypy, and record the numbers.
- [ ] **Step 2:** write the documents.
- [ ] **Step 3:** commit — `git commit -m "docs: describe the platform as it now is"`.
