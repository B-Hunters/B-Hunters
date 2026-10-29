# Durable Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the in-process scan execution with a durable, leased job system that runs in its own process, so a scan survives an API or runner restart, and lay the encrypted-secret and durable-issue foundations the later phases build on.

**Architecture:** A new `platform_jobs` collection is the queue. The API enqueues a job instead of calling `asyncio.create_task`; a new `b-hunters runner` process claims jobs with an atomic `find_one_and_update`, holds a lease on them, heartbeats that lease while it works, and releases it on completion. The runner owns one target lock at a time, so two scans of the same host never compete for the seventeen worker containers. The scan record gains a phase checkpoint (`workers` → `agents` → `verifying` → `reporting` → `completed`) and per-task status, so a reclaimed job resumes instead of restarting. MongoDB stays the only store; a separate `platform_issues` collection carries triage state across scans while `platform_findings` keeps the per-scan evidence.

**Tech Stack:** Python 3.10+, FastAPI, pymongo against MongoDB 7 (`find_one_and_update` for atomic claim), `cryptography` (AES-GCM) for secrets at rest, pytest + pytest-asyncio, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-29-single-operator-platform-design.md` — this plan implements §3.1 (resolved forks), §4 (durable execution), §7.1 (durable issues), §10 (data model), §11 (API surface). Later phases of the spec (authenticated assessment, continuous assessment, reporting, agent quality, hardening) are **not** in this plan; each gets its own plan when this one is finished.

## Global Constraints

- Every new module starts with `from __future__ import annotations` and a module docstring that says what the module is for.
- Python 3.10-compatible syntax. The codebase uses `typing.Optional`/`list[str]` style consistent with `ruff.toml` (line length 110, `UP` rules on, `UP045`/`UP007` ignored).
- `ruff check b_hunters tests` and `ruff format --check b_hunters tests` must pass before every commit.
- `mypy b_hunters/platform --ignore-missing-imports --no-strict-optional` currently reports **36 pre-existing errors** in 14 files (framework/runtime/provider code). This plan must not add new ones: run mypy on the touched modules only, e.g. `mypy b_hunters/platform/runner.py b_hunters/platform/db/jobs.py b_hunters/platform/db/issues.py b_hunters/platform/security/secrets.py b_hunters/platform/scan_keys.py b_hunters/platform/agents/factory.py --ignore-missing-imports --no-strict-optional` and require zero errors. Fixing the pre-existing 36 is Phase 6 work.
- Scope enforcement stays mandatory: every outbound request still goes through `b_hunters/platform/security/scope.py`. No new network call path may bypass `ScopeEnforcer`.
- Secrets never appear in an API response, an event payload, a log line, a scan event or a report. The existing `b_hunters/platform/security/redact.py` helpers are used for anything free-form.
- The legacy collections (`scans`, `domains`, `reports`, `js`) are untouched. Every new collection is namespaced `platform_*` and registered in `PLATFORM_COLLECTIONS` and `INDEXES` in `b_hunters/platform/db/client.py`.
- Test commands (run from `/home/sniper/pentest/repos/B-Hunters`):
  - unit only: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit -q`
  - full suite with Mongo: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests -q`
- Integration tests are skipped automatically when MongoDB is unreachable (`tests/conftest.py`); a skipped test is not a pass — check the summary line for `passed`.

## Review Focus

Five failure modes the spec implies that no task's tests obviously cover. Each line is pinned to a test in the owning task.

1. **A scan of a target that another scan is already running** must wait for the lock, not fail and not run in parallel — pinned in Task 6 (`test_the_runner_defers_a_scan_of_a_locked_target`).
2. **A runner killed mid-scan** must not lose the scan, duplicate the agent work, or spend the tokens twice — pinned in Task 4 (`test_a_job_whose_lease_expired_is_claimed_again`) and Task 7 (`test_a_succeeded_agent_task_is_not_run_again`).
3. **A provider key written before the secret key existed** must be migrated, and must never be returned by the API — pinned in Task 9 (`test_migrate_secrets_encrypts_an_existing_provider`, `test_the_api_never_returns_the_provider_key`).
4. **The same finding in two scans** must be one issue with one triage state and one history — pinned in Task 8 (`test_the_same_fingerprint_in_two_scans_shares_one_issue`).
5. **A scan stopped while it is still queued** must never run — pinned in Task 5 (`test_stopping_a_queued_scan_cancels_its_job`).

---

## File Structure

Created:

| File | Responsibility |
|---|---|
| `b_hunters/platform/security/secrets.py` | AES-GCM encryption of stored credentials; key loading and masking. |
| `b_hunters/platform/db/jobs.py` | `JobRepository` (durable queue with leases) and `TargetLockRepository` (one scan per target). |
| `b_hunters/platform/db/issues.py` | `IssueRepository`: durable findings, triage state, observation state, history. |
| `b_hunters/platform/runner.py` | The runner process: claim, execute, heartbeat, lock, drain. |
| `b_hunters/platform/agents/factory.py` | Builds a `ScanOrchestrator` and a `ScanContext` from a stored scan — shared by the API and the runner. |
| `b_hunters/platform/scan_keys.py` | `compute_target_key` / `compute_comparison_key` — the stable identities a diff compares on. |
| `tests/unit/test_secret_box.py` | Encryption round-trip, tamper detection, key validation. |
| `tests/unit/test_scan_keys.py` | Key stability and sensitivity. |
| `tests/integration/test_job_repository.py` | Claim, lease, retry, release, cancel semantics. |
| `tests/integration/test_runner.py` | Runner claim/heartbeat/retry/drain, two runners, expired lease. |
| `tests/integration/test_target_locks.py` | Lock exclusivity, expiry, deferral. |
| `tests/integration/test_scan_jobs.py` | The API enqueues instead of running; stop cancels. |
| `tests/integration/test_scan_resume.py` | Phase checkpoints and per-task resume. |
| `tests/integration/test_issues.py` | Issue creation, sharing, migration, auto-close. |
| `tests/integration/test_provider_secrets.py` | Provider key encryption and migration. |
| `docs/runner.md` | What the runner is, how it works, how to recover a stuck scan. |

Modified:

| File | Change |
|---|---|
| `b_hunters/platform/settings.py` | New settings: `secret_key`, `runner_*`, `job_max_attempts`, `auto_close_misses`. |
| `b_hunters/platform/db/client.py` | New collections and indexes: `platform_jobs`, `platform_target_locks`, `platform_issues`, `platform_runner_heartbeats`, plus `platform_findings.issue_id`. |
| `b_hunters/platform/db/repositories.py` | `ScanRecord.phase/coverage/target_key/comparison_key`, `ScanRepository.set_phase/set_coverage`, `TaskRepository.upsert`, `FindingRepository` links issues, `ProviderRepository` encrypts. |
| `b_hunters/platform/api/deps.py` | `Services` gains `jobs`, `locks`, `issues`, `secret_box`. |
| `b_hunters/platform/api/routers/scans.py` | `start` enqueues a job; `stop` cancels it; the orchestrator factory moves out. |
| `b_hunters/platform/agents/orchestrator.py` | Phase checkpoints, staged agent execution, per-task resume. |
| `b_hunters/cli.py` | `b-hunters runner`, `b-hunters runner status`, `b-hunters admin migrate-issues`, `b-hunters admin migrate-secrets`. |
| `requirements.txt`, `setup.py` | `cryptography>=42`. |
| `docker-compose.platform.yml` | The `runner` service, the secret key, the health check. |
| `docs/implementation-report.md`, `docs/architecture-audit.md`, `/home/sniper/pentest/STATUS.md` | Phase 1 result and the measured test count. |

---

### Task 1: Protect the existing work (Phase 0)

**Files:**
- Modify: `/home/sniper/pentest/STATUS.md` (outside the repository — the project handoff)
- Modify: `docs/implementation-report.md`
- Modify: `docs/architecture-audit.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a clean working tree, a tag `baseline-2026-10-29`, and a recorded baseline that every later task's numbers are compared against.

- [ ] **Step 1: Confirm what is uncommitted and that nothing sensitive is in it**

Run: `git status --porcelain` and `git diff --stat`

Expected: 21 modified files, 36 untracked paths, all under `b_hunters/`, `tests/`, `docs/`, `dashboard/`, `docker-compose.platform.yml` and `requirements.txt`.

Run: `git status --porcelain | grep -Ei '\.env$|secret|credential|\.pem$|\.key$'` — expected: no output.

- [ ] **Step 2: Run the full suite and the linters**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests -q`

Expected: `414 passed`. If the count differs, the number the command prints is the truth — record that one, not this one.

Run: `/home/sniper/pentest/.venv/bin/python -m ruff check b_hunters tests` and `/home/sniper/pentest/.venv/bin/python -m ruff format --check b_hunters tests`

Expected: no output from either command.

- [ ] **Step 3: Update the three status documents with the measured numbers**

Measure the numbers first:

```bash
git branch --show-current
git rev-list --count main..HEAD
git status --porcelain | wc -l
```

In `/home/sniper/pentest/STATUS.md`, `docs/implementation-report.md` and `docs/architecture-audit.md`, record: the branch name, the commit count ahead of `main`, the number of modified and untracked paths, the test count from Step 2, the benchmark scores already recorded (precision 1.0, recall 0.733, F1 0.846), and the new design and plan documents by path. Every number must be the output of a command you ran — do not restate a number you have not measured in this session.

- [ ] **Step 4: Commit the work in three commits**

```bash
git add b_hunters tests requirements.txt docker-compose.platform.yml docs/tailnet-deployment.md
git commit -m "feat(platform): persist worker output and record agent verdicts"

git add dashboard
git commit -m "feat(dashboard): add the Karton dashboard assets"

git add docs/superpowers
git commit -m "docs: add the single-operator platform design and plan"
```

Do not use `git add -A`. If `git status --porcelain` still lists files afterwards, look at each one and either add it to the appropriate commit above or report it.

- [ ] **Step 5: Tag the baseline**

```bash
git tag -a baseline-2026-10-29 -m "Verified baseline before the durable-foundation work"
git tag -l
git status --porcelain
```

Expected: the tag exists and the tree is clean.

---

### Task 2: The secret box and the new settings

**Files:**
- Create: `b_hunters/platform/security/secrets.py`
- Modify: `b_hunters/platform/settings.py`
- Modify: `requirements.txt`, `setup.py`
- Test: `tests/unit/test_secret_box.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `b_hunters.platform.security.secrets.SecretBox` with
    - `SecretBox.from_base64(value: str) -> SecretBox`
    - `SecretBox.from_settings(settings: Settings) -> SecretBox | None` (`None` when no key is configured)
    - `SecretBox.encrypt(plaintext: str) -> str`
    - `SecretBox.decrypt(token: str) -> str`
    - `SecretBox.is_encrypted(value: str) -> bool` (staticmethod)
  - `b_hunters.platform.security.secrets.SecretKeyError(RuntimeError)`
  - New `Settings` fields: `secret_key: str = ""`, `runner_concurrency: int = 1`, `runner_lease_seconds: int = 60`, `runner_heartbeat_seconds: int = 10`, `runner_poll_seconds: float = 2.0`, `runner_shutdown_grace_seconds: int = 300`, `job_max_attempts: int = 3`, `auto_close_misses: int = 2`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_secret_box.py`:

```python
from b_hunters.platform.security.secrets import SecretBox, SecretKeyError


def test_a_secret_round_trips():
    box = SecretBox.from_base64(base64_key())
    token = box.encrypt("hunter2")
    assert token != "hunter2"
    assert box.decrypt(token) == "hunter2"


def test_the_ciphertext_is_prefixed_and_marked():
    box = SecretBox.from_base64(base64_key())
    token = box.encrypt("hunter2")
    assert token.startswith("bh1.")
    assert SecretBox.is_encrypted(token)
    assert not SecretBox.is_encrypted("hunter2")


def test_a_tampered_ciphertext_is_refused():
    box = SecretBox.from_base64(base64_key())
    token = box.encrypt("hunter2")
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(SecretKeyError):
        box.decrypt(tampered)


def test_a_foreign_key_cannot_decrypt():
    token = SecretBox.from_base64(base64_key()).encrypt("hunter2")
    with pytest.raises(SecretKeyError):
        SecretBox.from_base64(base64_key(seed=7)).decrypt(token)


def test_a_short_key_is_refused():
    with pytest.raises(SecretKeyError):
        SecretBox.from_base64(base64.b64encode(b"too-short").decode())


def test_from_settings_returns_none_without_a_key(settings):
    assert SecretBox.from_settings(settings) is None
```

`base64_key(seed: int = 1) -> str` is a helper in the test file returning `base64.b64encode(bytes([seed]) * 32).decode()`.

Also add a test that the new settings are read from the environment and that the secret key is redacted:

```python
def test_the_new_settings_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("BHUNTERS_RUNNER_CONCURRENCY", "3")
    monkeypatch.setenv("BHUNTERS_RUNNER_POLL_SECONDS", "0.5")
    monkeypatch.setenv("BHUNTERS_SECRET_KEY", "abc")
    settings = load_settings(overrides={"mongo_uri": "mongodb://127.0.0.1:27017"})
    assert settings.runner_concurrency == 3
    assert settings.runner_poll_seconds == 0.5
    assert settings.secret_key == "abc"
    assert settings.redacted()["secret_key"] == "***redacted***"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_secret_box.py -q`

Expected: FAIL — `ModuleNotFoundError: No module named 'b_hunters.platform.security.secrets'`.

- [ ] **Step 3: Implement the secret box**

`b_hunters/platform/security/secrets.py`:

- `SecretKeyError(RuntimeError)` for a missing, short or wrong key and for a failed decryption.
- `SecretBox` is a frozen dataclass holding `key: bytes` (exactly 32 bytes).
- `from_base64(value)` decodes strict base64; a decode failure or a length other than 32 bytes raises `SecretKeyError`.
- `from_settings(settings)` returns `None` when `settings.secret_key` is empty, otherwise `from_base64`.
- `encrypt(plaintext)` uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM(self.key)` with a fresh 12-byte nonce from `os.urandom(12)` and associated data `b"b-hunters/secret/v1"`. The output is `"bh1." + base64.urlsafe_b64encode(nonce + ciphertext).decode()`. An empty plaintext still produces a token.
- `decrypt(token)` splits the prefix, raises `SecretKeyError` when the prefix is missing or the payload is not valid base64, and raises `SecretKeyError` when `AESGCM.decrypt` fails (tampered ciphertext or a foreign key).
- `is_encrypted(value)` is `value.startswith("bh1.")`.

- [ ] **Step 4: Add the settings and the dependency**

In `b_hunters/platform/settings.py`:

- Add the eight fields to `Settings` with the defaults from the Interfaces block, in a new `# --- runner / secrets ---` section after the `# --- sessions / auth ---` block.
- `load_settings` parses by field name, so the new names must be added to the existing name lists: the integer list gets `runner_concurrency`, `runner_lease_seconds`, `runner_heartbeat_seconds`, `runner_shutdown_grace_seconds`, `job_max_attempts`, `auto_close_misses`; the float list gets `runner_poll_seconds`. `secret_key` is a plain string and needs no list entry.
- `Settings.redacted()` already redacts any field whose name contains `secret`; assert that in the test rather than changing the helper.

In `requirements.txt` add `cryptography>=42,<47` to the platform section. In `setup.py`, add the same pin to the `platform` extras list.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_secret_box.py -q`

Expected: PASS.

Run: `/home/sniper/pentest/.venv/bin/python -m ruff check b_hunters tests && /home/sniper/pentest/.venv/bin/python -m ruff format --check b_hunters tests`

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add b_hunters/platform/security/secrets.py b_hunters/platform/settings.py tests/unit/test_secret_box.py requirements.txt setup.py
git commit -m "feat(platform): encrypt stored credentials with a deployment key"
```

---

### Task 3: The durable job queue

**Files:**
- Create: `b_hunters/platform/db/jobs.py`
- Modify: `b_hunters/platform/db/client.py`
- Test: `tests/integration/test_job_repository.py`

**Interfaces:**
- Consumes: `Database` (`b_hunters.platform.db.client.Database`), `utcnow`/`new_id` from `b_hunters.platform.db.repositories`.
- Produces: `b_hunters.platform.db.jobs.JobRepository` with
  - `enqueue(*, kind: str, payload: dict[str, Any], priority: int = 0, available_at: float | None = None, max_attempts: int = 3) -> dict[str, Any]`
  - `claim(*, owner: str, lease_seconds: int = 60, kinds: Sequence[str] = ()) -> dict[str, Any] | None`
  - `heartbeat(job_id: str, *, owner: str, lease_seconds: int = 60) -> bool`
  - `complete(job_id: str, *, owner: str, result: dict[str, Any] | None = None) -> bool`
  - `fail(job_id: str, *, owner: str, error: str, retry: bool = True) -> bool`
  - `release(job_id: str, *, owner: str, delay_seconds: float = 0.0) -> bool`
  - `cancel(job_id: str) -> bool`
  - `get(job_id: str) -> dict[str, Any] | None`
  - `find_live(scan_id: str) -> dict[str, Any] | None` — the queued/leased/running job whose `payload.scan_id` matches
  - `list(*, status: str = "", kind: str = "", limit: int = 50) -> list[dict[str, Any]]`

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_job_repository.py` — use the `database` fixture from `tests/conftest.py` and clean the collection between tests:

```python
@pytest.fixture(autouse=True)
def _clean(database):
    database.collection("platform_jobs").delete_many({})
    yield


def test_a_queued_job_is_claimed_exactly_once(database):
    repo = JobRepository(database)
    job = repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    first = repo.claim(owner="runner-a")
    second = repo.claim(owner="runner-b")
    assert first["job_id"] == job["job_id"]
    assert first["status"] == "leased"
    assert first["lease_owner"] == "runner-a"
    assert second is None


def test_claim_orders_by_priority_then_age(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "low"})
    repo.enqueue(kind="scan", payload={"scan_id": "high"}, priority=10)
    assert repo.claim(owner="r")["payload"]["scan_id"] == "high"


def test_an_expired_lease_is_claimed_again(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    repo.claim(owner="dead-runner", lease_seconds=0)
    time.sleep(0.05)
    assert repo.claim(owner="live-runner")["lease_owner"] == "live-runner"


def test_a_heartbeat_extends_the_lease(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    job = repo.claim(owner="runner-a", lease_seconds=1)
    time.sleep(0.05)
    assert repo.heartbeat(job["job_id"], owner="runner-a", lease_seconds=60)
    assert repo.claim(owner="runner-b") is None


def test_a_heartbeat_from_another_owner_is_refused(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    job = repo.claim(owner="runner-a")
    assert not repo.heartbeat(job["job_id"], owner="runner-b")


def test_a_failing_job_is_retried_until_the_attempt_limit(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"}, max_attempts=2)
    first = repo.claim(owner="runner-a")
    repo.fail(first["job_id"], owner="runner-a", error="boom")
    second = repo.claim(owner="runner-a")
    assert second["job_id"] == first["job_id"]
    assert second["attempts"] == 2
    repo.fail(second["job_id"], owner="runner-a", error="boom again")
    assert repo.get(first["job_id"])["status"] == "failed"
    assert repo.claim(owner="runner-a") is None


def test_release_returns_the_job_to_the_queue(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    job = repo.claim(owner="runner-a")
    repo.release(job["job_id"], owner="runner-a", delay_seconds=0)
    assert repo.get(job["job_id"])["status"] == "queued"
    assert repo.claim(owner="runner-b")["job_id"] == job["job_id"]


def test_a_cancelled_job_is_never_claimed(database):
    repo = JobRepository(database)
    job = repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    repo.cancel(job["job_id"])
    assert repo.claim(owner="runner-a") is None


def test_find_live_returns_the_job_of_a_scan(database):
    repo = JobRepository(database)
    repo.enqueue(kind="scan", payload={"scan_id": "s1"})
    repo.enqueue(kind="scan", payload={"scan_id": "s2"})
    assert repo.find_live("s1")["payload"]["scan_id"] == "s1"
    assert repo.find_live("s3") is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_job_repository.py -q`

Expected: FAIL — `ImportError: cannot import name 'JobRepository'`.

- [ ] **Step 3: Implement the repository and the indexes**

`b_hunters/platform/db/jobs.py`:

- The job document: `job_id`, `kind`, `status` (`queued`/`leased`/`running`/`succeeded`/`failed`/`cancelled`), `priority` (int, default 0), `available_at` (float epoch), `lease_owner`, `lease_expires_at`, `heartbeat_at`, `attempts`, `max_attempts`, `payload`, `result`, `error`, `created_at`, `updated_at`.
- `enqueue` inserts the document with `status="queued"`, `attempts=0`, `available_at` defaulting to `utcnow()`.
- `claim` uses one `find_one_and_update` with
  `{"$or": [{"status": "queued", "available_at": {"$lte": now}}, {"status": {"$in": ["leased", "running"]}, "lease_expires_at": {"$lte": now}}]}`,
  the `kinds` filter when given, sorted by `[("priority", DESCENDING), ("created_at", ASCENDING)]`, and the update `{"$set": {"status": "leased", "lease_owner": owner, "lease_expires_at": now + lease_seconds, "heartbeat_at": now, "updated_at": now}, "$inc": {"attempts": 1}}` with `return_document=ReturnDocument.AFTER`. When the claimed document's `attempts` is already above its `max_attempts`, mark it `failed` with the error `the job exceeded its attempt limit` and claim again (loop, bounded by 10 iterations).
- `heartbeat` updates only when `lease_owner` matches; it sets `heartbeat_at` and `lease_expires_at`.
- `complete` sets `status="succeeded"`, `result`, `finished_at`; it only matches a job whose `lease_owner` is the caller.
- `fail` sets `status="failed"` and `error`; when `retry` is true **and** `attempts < max_attempts`, it instead sets `status="queued"`, `lease_owner=""`, `lease_expires_at=0`, and `available_at=utcnow()` so the job is retried.
- `release` sets `status="queued"`, clears the lease, and sets `available_at = utcnow() + delay_seconds`.
- `cancel` sets `status="cancelled"` for a job that is not already finished.
- `find_live` returns the newest job with `payload.scan_id == scan_id` and status in `("queued", "leased", "running")`.
- `list` sorts by `created_at` descending.

In `b_hunters/platform/db/client.py`:

- Add `"platform_jobs"`, `"platform_target_locks"`, `"platform_issues"`, `"platform_runner_heartbeats"` to `PLATFORM_COLLECTIONS`.
- Add to `INDEXES`:
  - `platform_jobs`: `("job_id", ASCENDING)` unique; `("status", ASCENDING), ("available_at", ASCENDING), ("priority", DESCENDING)`; `("status", ASCENDING), ("lease_expires_at", ASCENDING)`; `("kind", ASCENDING), ("created_at", ASCENDING)`; `("payload.scan_id", ASCENDING)`.
  - `platform_target_locks`: `("target_key", ASCENDING)` unique; `("expires_at", ASCENDING)` with `expire_after_seconds=0`.
  - `platform_issues`: `("target_key", ASCENDING), ("fingerprint", ASCENDING)` unique; `("triage_status", ASCENDING), ("severity", ASCENDING)`; `("last_seen_at", DESCENDING)`.
  - `platform_runner_heartbeats`: `("runner_id", ASCENDING)` unique; `("last_seen_at", DESCENDING)`.
  - `platform_findings`: add `("issue_id", ASCENDING)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_job_repository.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/db/jobs.py b_hunters/platform/db/client.py tests/integration/test_job_repository.py
git commit -m "feat(platform): add a leased job queue and the target locks"
```

---

### Task 4: The runner process

**Files:**
- Create: `b_hunters/platform/runner.py`
- Create: `b_hunters/platform/agents/factory.py`
- Modify: `b_hunters/platform/api/routers/scans.py` (move `_build_orchestrator` and `_provider_config` into the factory)
- Modify: `b_hunters/platform/api/deps.py` (`Services` gains `jobs`, `locks`, `secret_box`)
- Modify: `b_hunters/cli.py` (`b-hunters runner`, `b-hunters runner status`)
- Test: `tests/integration/test_runner.py`

**Interfaces:**
- Consumes: `JobRepository` (Task 3), `SecretBox` (Task 2), `Services`.
- Produces:
  - `b_hunters.platform.runner.RunnerConfig` — frozen dataclass: `concurrency: int = 1`, `lease_seconds: int = 60`, `heartbeat_seconds: int = 10`, `poll_seconds: float = 2.0`, `shutdown_grace_seconds: int = 300`, `owner: str = ""` (default: `f"{socket.gethostname()}-{os.getpid()}"`).
  - `b_hunters.platform.runner.JobExecutor` — `Protocol` with `async def execute(self, job: dict[str, Any]) -> dict[str, Any]`.
  - `POST /api/v1/admin/runner/drain` — sets the drain flag so the runner stops claiming new jobs; `DELETE` on the same path clears it.
  - `b_hunters.platform.runner.Runner` — `__init__(self, services: Services, config: RunnerConfig, executor: JobExecutor | None = None)`, `async def run_once(self) -> dict[str, Any] | None`, `async def run_forever(self) -> None`, `def drain(self) -> None`, `def record_heartbeat(self) -> None`.
  - `b_hunters.platform.agents.factory.build_orchestrator(services: Services) -> ScanOrchestrator`
  - `b_hunters.platform.agents.factory.build_scan_context(scan, settings: Settings) -> ScanContext` — rebuilds the context from a stored scan; the API and the runner both use it.
  - `b_hunters.platform.agents.factory.provider_config_for(services: Services, provider_name: str = "") -> ProviderConfig`

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_runner.py`:

```python
class RecordingExecutor:
    def __init__(self, *, fail_times: int = 0, delay: float = 0.0):
        self.calls: list[dict] = []
        self.fail_times = fail_times
        self.delay = delay

    async def execute(self, job):
        self.calls.append(job)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("executor failed")
        return {"status": "completed"}


def test_the_runner_claims_and_completes_a_job(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    executor = RecordingExecutor()
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    result = asyncio.run(runner.run_once())
    assert result["status"] == "completed"
    assert jobs.list()[0]["status"] == "succeeded"


def test_a_failing_job_is_retried_and_then_fails(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"}, max_attempts=2)
    executor = RecordingExecutor(fail_times=2)
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    asyncio.run(runner.run_once())
    assert jobs.list()[0]["status"] == "queued"
    asyncio.run(runner.run_once())
    assert jobs.list()[0]["status"] == "failed"
    assert "executor failed" in jobs.list()[0]["error"]


def test_the_runner_heartbeats_the_lease(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    runner = Runner(services, RunnerConfig(owner="runner-a", heartbeat_seconds=0.05), RecordingExecutor(delay=0.2))
    asyncio.run(runner.run_once())
    job = jobs.list()[0]
    assert job["heartbeat_at"] >= job["created_at"]


def test_a_job_whose_lease_expired_is_claimed_again(services):
    jobs = services.jobs
    jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    jobs.claim(owner="dead-runner", lease_seconds=0)
    time.sleep(0.05)
    runner = Runner(services, RunnerConfig(owner="live-runner"), RecordingExecutor())
    asyncio.run(runner.run_once())
    assert jobs.list()[0]["status"] == "succeeded"


def test_two_runners_never_claim_the_same_job(services):
    jobs = services.jobs
    for index in range(5):
        jobs.enqueue(kind="scan", payload={"scan_id": f"s{index}"})
    first = Runner(services, RunnerConfig(owner="runner-a"), RecordingExecutor())
    second = Runner(services, RunnerConfig(owner="runner-b"), RecordingExecutor())
    async def run_both():
        await asyncio.gather(first.run_once(), second.run_once())
    asyncio.run(run_both())
    claimed = [job["lease_owner"] for job in jobs.list()]
    assert len(set(claimed)) == 2


def test_drain_stops_the_runner(services):
    services.jobs.enqueue(kind="scan", payload={"scan_id": "s1"})
    runner = Runner(services, RunnerConfig(owner="runner-a"), RecordingExecutor())
    runner.drain()
    asyncio.run(runner.run_once())
    assert services.jobs.list()[0]["status"] == "queued"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_runner.py -q`

Expected: FAIL — `ImportError: cannot import name 'Runner'`.

- [ ] **Step 3: Move the orchestrator factory out of the API router**

Create `b_hunters/platform/agents/factory.py` with:

- `build_orchestrator(services: Services) -> ScanOrchestrator` — the body of the current `_build_orchestrator` in `b_hunters/platform/api/routers/scans.py`, unchanged except that the `services` type is imported under `TYPE_CHECKING` to avoid a circular import.
- `provider_config_for(services: Services, provider_name: str = "") -> ProviderConfig` — the body of the current `_provider_config`.
- `build_scan_context(scan, settings: Settings) -> ScanContext` — the body of the `ScanContext(...)` construction in the current `start_scan` endpoint, taking the `ScanRecord` instead of the request payload.

In `b_hunters/platform/api/routers/scans.py`, delete `_build_orchestrator` and `_provider_config` and import the factory functions instead. Keep the module-level imports of the scanner adapters inside the factory, as they are now.

- [ ] **Step 4: Implement the runner**

`b_hunters/platform/runner.py`:

- `RunnerConfig` as specified; `owner` defaults to `f"{socket.gethostname()}-{os.getpid()}"` when empty.
- `Runner.__init__` stores `services`, `config`, `executor` (default `ScanJobExecutor(services)`) and `self._drained = False`.
- `run_once()` returns `None` immediately when the runner is drained, before it claims anything. Otherwise it claims one job (`services.jobs.claim(owner=..., lease_seconds=..., kinds=("scan", "benchmark"))`); when there is none it records a heartbeat and returns `None`. When the executor raises, `fail(job_id, owner=..., error=str(exc), retry=True)` is called and the error is logged; the method returns the job document. On success `complete(job_id, owner=..., result=...)` is called.
- While the executor runs, an `asyncio` task calls `services.jobs.heartbeat(job_id, owner=..., lease_seconds=...)` every `config.heartbeat_seconds`; it is cancelled in a `finally` block.
- `record_heartbeat()` upserts `{runner_id, last_seen_at, current_job_id, version}` into `platform_runner_heartbeats`.
- `run_forever()` loops: `await self.run_once()`; if it returned `None`, `await asyncio.sleep(config.poll_seconds)`; it stops when `drain()` was called and no job is running.
- `drain()` sets the drain flag; the current job is allowed to finish.
- `ScanJobExecutor.execute(job)` — for `kind == "scan"`: load the scan with `services.scans.get(job["payload"]["scan_id"])`; when the scan is missing, raise `RuntimeError("the scan does not exist")`; build the context with `build_scan_context(scan, services.settings)`; build the orchestrator with `build_orchestrator(services)`; `await orchestrator.run(context)`; return the result dict. For any other kind, return `{"status": "skipped", "kind": job["kind"]}`. The executor does not take the target lock — the runner takes it (Task 6), so a fake executor in a test exercises the same lock path as the real one.

In `b_hunters/platform/api/deps.py`, `Services.__init__` gains:

```python
self.jobs = JobRepository(self.db)
self.locks = TargetLockRepository(self.db)
self.secret_box = SecretBox.from_settings(self.settings)
```

(`JobRepository` and `TargetLockRepository` come from Task 3; `IssueRepository` is added in Task 8, together with the `FindingRepository` that depends on it.)

- [ ] **Step 5: Add the CLI commands**

In `b_hunters/cli.py`:

```python
runner_parser = subparsers.add_parser('runner', help=f"{Fore.CYAN}Run the durable job runner")
runner_parser.add_argument('--concurrency', type=int, default=None)
runner_parser.add_argument('--once', action='store_true', help="Claim and run a single job, then exit")
runner_parser.add_argument('--poll-seconds', type=float, default=None)
```

- `b-hunters runner` builds the `Services` with `_platform_services()`, creates a `RunnerConfig` from the settings (falling back to the command line), and runs `asyncio.run(runner.run_forever())`. It installs a SIGTERM handler that calls `runner.drain()`.
- `b-hunters runner --once` runs `asyncio.run(runner.run_once())` and exits 0 when a job was completed, 1 when there was no job.
- `b-hunters runner status` reads `platform_runner_heartbeats`, prints `runner_id`, the age of `last_seen_at` and the current job, and exits 0 when a heartbeat is younger than 90 seconds, 1 otherwise.

The parser needs a subparser for `runner` with its own `status` action: `runner_sub = runner_parser.add_subparsers(dest="runner_command", required=True)` with `runner_sub.add_parser("status")`, and the default (no subcommand) is the runner loop.

Add the drain endpoint in `b_hunters/platform/api/routers/admin.py`:

- `POST /api/v1/admin/runner/drain` sets the counter `runner:drain` to `1` in `platform_counters`; `DELETE /api/v1/admin/runner/drain` removes it. Both require the `admin` role and a CSRF token, and both audit the action.
- The runner reads that counter at the top of every loop iteration: when it is set, the runner calls `drain()` and stops claiming new jobs. The current job finishes.

The counter is written with `services.db.next_sequence` semantics — use a dedicated `update_one({"key": "runner:drain"}, {"$set": {"value": 1}}, upsert=True)` on `platform_counters`; the runner reads it with `find_one({"key": "runner:drain"})`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_runner.py -q`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add b_hunters/platform/runner.py b_hunters/platform/agents/factory.py b_hunters/platform/api/deps.py b_hunters/platform/api/routers/scans.py b_hunters/cli.py tests/integration/test_runner.py
git commit -m "feat(platform): run scans in a durable runner process"
```

---

### Task 5: The API enqueues jobs instead of running scans

**Files:**
- Modify: `b_hunters/platform/api/routers/scans.py`
- Test: `tests/integration/test_scan_jobs.py`

**Interfaces:**
- Consumes: `services.jobs` (Task 3), `build_scan_context`/`build_orchestrator` (Task 4).
- Produces:
  - `POST /api/v1/scans/{scan_id}/start` → `200 {"status": "queued", "scan_id": ..., "job_id": ...}`; the scan status becomes `queued`; exactly one `platform_jobs` document of `kind="scan"` exists with `payload={"scan_id": ...}`.
  - `POST /api/v1/scans/{scan_id}/stop` → cancels the live job and sets the scan status to `stopping`.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_scan_jobs.py`:

```python
def _create_scan(client, csrf):
    response = client.post(
        "/api/v1/scans",
        json={
            "name": "queued scan",
            "targets": {"urls": ["https://demo.test/"], "authorized_hosts": ["demo.test"], "excluded_paths": []},
            "profile": "standard",
            "scanners": ["security_headers"],
            "agent_roles": ["recon"],
            "test_accounts": [],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text
    return response.json()["scan_id"]


def test_starting_a_scan_enqueues_a_job(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    response = client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "queued"
    job = services.jobs.get(payload["job_id"])
    assert job["kind"] == "scan"
    assert job["payload"]["scan_id"] == scan_id
    assert job["status"] == "queued"
    assert services.scans.get(scan_id).status == "queued"


def test_starting_the_same_scan_twice_is_refused(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    response = client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 409


def test_stopping_a_queued_scan_cancels_its_job(client, csrf, services):
    scan_id = _create_scan(client, csrf)
    started = client.post(f"/api/v1/scans/{scan_id}/start", headers={"X-CSRF-Token": csrf}).json()
    response = client.post(f"/api/v1/scans/{scan_id}/stop", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert services.jobs.get(started["job_id"])["status"] == "cancelled"
    assert services.scans.get(scan_id).status in {"stopping", "cancelled"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_scan_jobs.py -q`

Expected: FAIL — the start endpoint still runs the scan in process and returns `{"status": "starting"}`.

- [ ] **Step 3: Change the start endpoint**

In `b_hunters/platform/api/routers/scans.py`:

- `start_scan` no longer builds an orchestrator and no longer calls `asyncio.create_task`. It:
  1. loads the scan and keeps the existing status check (`draft` or `queued`);
  2. refuses with `409` when `services.jobs.find_live(scan_id)` is not `None` — detail `"the scan already has a job in flight"`;
  3. enqueues `services.jobs.enqueue(kind="scan", payload={"scan_id": scan_id, "target_key": getattr(scan, "target_key", "")}, max_attempts=settings.job_max_attempts)` — the `target_key` field arrives with Task 7; until then the payload carries an empty string and the runner skips the lock;
  4. sets the scan status to `queued`;
  5. appends the event `scan.queued` with `{"job_id": ...}`;
  6. audits `scan.start` as before;
  7. returns `{"status": "queued", "scan_id": scan_id, "job_id": job["job_id"]}`.
- Delete the `_run_scan` helper and the `import asyncio` if it is no longer used in the module.
- `stop_scan`: when `services.jobs.find_live(scan_id)` is not `None`, cancel that job; set the scan status to `stopping`; mark the pending tasks `cancelled`; append the event `scan.stop_requested`. The orchestrator in the runner notices the scan status through the database and stops on its own.
- Remove `services.orchestrators` from `Services` in `b_hunters/platform/api/deps.py` and every use of it (grep for `orchestrators`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_scan_jobs.py tests/integration/test_api.py -q`

Expected: PASS. The existing API tests must still pass — the scan lifecycle test drives the orchestrator directly and is unaffected.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/api/routers/scans.py b_hunters/platform/api/deps.py tests/integration/test_scan_jobs.py
git commit -m "feat(platform): enqueue scans instead of running them in the API"
```

---

### Task 6: One scan per target

**Files:**
- Modify: `b_hunters/platform/db/jobs.py` (add `TargetLockRepository`)
- Modify: `b_hunters/platform/runner.py` (acquire and release the lock around a scan job)
- Test: `tests/integration/test_target_locks.py`

**Interfaces:**
- Consumes: `JobRepository` (Task 3), `Services` (Task 4).
- Produces: `b_hunters.platform.db.jobs.TargetLockRepository` with
  - `acquire(*, target_key: str, owner: str, ttl_seconds: int = 900) -> bool`
  - `release(*, target_key: str, owner: str) -> bool`
  - `holder(target_key: str) -> dict[str, Any] | None`

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_target_locks.py`:

```python
def test_a_lock_is_exclusive(database):
    locks = TargetLockRepository(database)
    assert locks.acquire(target_key="demo.test", owner="runner-a")
    assert not locks.acquire(target_key="demo.test", owner="runner-b")
    assert locks.holder("demo.test")["owner"] == "runner-a"


def test_release_frees_the_lock(database):
    locks = TargetLockRepository(database)
    locks.acquire(target_key="demo.test", owner="runner-a")
    assert locks.release(target_key="demo.test", owner="runner-a")
    assert locks.acquire(target_key="demo.test", owner="runner-b")


def test_a_lock_expires(database):
    locks = TargetLockRepository(database)
    locks.acquire(target_key="demo.test", owner="runner-a", ttl_seconds=0)
    time.sleep(0.05)
    assert locks.acquire(target_key="demo.test", owner="runner-b")


def test_the_runner_defers_a_scan_of_a_locked_target(services):
    services.locks.acquire(target_key="demo.test", owner="other-runner")
    job = services.jobs.enqueue(
        kind="scan", payload={"scan_id": "s1", "target_key": "demo.test"}
    )
    executor = RecordingExecutor()
    runner = Runner(services, RunnerConfig(owner="runner-a"), executor)
    asyncio.run(runner.run_once())
    assert executor.calls == []
    assert services.jobs.get(job["job_id"])["status"] == "queued"
```

(Import `RecordingExecutor` from `tests/integration/test_runner.py`.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_target_locks.py -q`

Expected: FAIL — `ImportError: cannot import name 'TargetLockRepository'`.

- [ ] **Step 3: Implement the lock repository**

`TargetLockRepository` in `b_hunters/platform/db/jobs.py`:

- The document: `target_key`, `owner`, `job_id`, `acquired_at`, `expires_at`.
- `acquire` uses `find_one_and_update` with the filter `{"target_key": target_key, "$or": [{"expires_at": {"$lte": now}}, {"owner": owner}]}` and the update `{"$set": {"owner": owner, "expires_at": now + ttl_seconds, "acquired_at": now}}` with `upsert=True`. A `DuplicateKeyError` from the unique index on `target_key` means another runner holds it and returns `False`.
- `release` deletes the document only when `owner` matches.
- `holder` returns the document when it exists and has not expired, else `None`.

- [ ] **Step 4: Use the lock in the runner**

In `b_hunters/platform/runner.py`, the **runner** takes the lock — not the executor — so that a fake executor in a test exercises the same path as the real one:

- Before calling the executor, `run_once` reads `target_key = str(job.get("payload", {}).get("target_key", ""))`. When it is empty, the job runs without a lock (a scan that was created before the target keys existed).
- When it is set, `services.locks.acquire(target_key=target_key, owner=config.owner, ttl_seconds=settings.runner_lease_seconds * 5)` decides the run. When the lock is refused, the runner calls `services.jobs.release(job_id, owner=config.owner, delay_seconds=30)` and returns without executing and without failing the job.
- When the lock was taken, the runner releases it in a `finally` block after the executor returns or raises.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_target_locks.py tests/integration/test_runner.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add b_hunters/platform/db/jobs.py b_hunters/platform/runner.py tests/integration/test_target_locks.py tests/integration/test_runner.py
git commit -m "feat(platform): keep one scan per target at a time"
```

---

### Task 7: Phase checkpoints, comparison keys and per-task resume

**Files:**
- Create: `b_hunters/platform/scan_keys.py`
- Modify: `b_hunters/platform/db/repositories.py` (`ScanRecord`, `ScanRepository`, `TaskRepository`)
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Modify: `b_hunters/platform/api/routers/scans.py` (compute the keys when a scan is created)
- Test: `tests/unit/test_scan_keys.py`, `tests/integration/test_scan_resume.py`

**Interfaces:**
- Consumes: `TaskRepository` (existing), `ScanRepository` (existing).
- Produces:
  - `b_hunters.platform.scan_keys.compute_target_key(*, authorized_hosts: Sequence[str], targets: Sequence[str]) -> str`
  - `b_hunters.platform.scan_keys.compute_comparison_key(*, target_key: str, excluded_paths: Sequence[str], profile: str, scanners: Sequence[str], agent_roles: Sequence[str], identity_ids: Sequence[str]) -> str`
  - `SCAN_PHASES = ("workers", "agents", "verifying", "reporting", "completed")` in `b_hunters.platform.agents.orchestrator`.
  - `ScanRecord` gains `phase: str`, `coverage: dict[str, Any]`, `target_key: str`, `comparison_key: str`.
  - `ScanRepository.set_phase(scan_id: str, phase: str) -> bool`
  - `ScanRepository.set_coverage(scan_id: str, coverage: dict[str, Any]) -> bool`
  - `TaskRepository.upsert(*, scan_id, task_id, title, kind="agent", agent_role="", depends_on=(), budget=None, input=None) -> dict[str, Any]` — creates the task, or keeps a `succeeded` task's status and result and resets any other status to `pending`.

- [ ] **Step 1: Write the failing unit test**

`tests/unit/test_scan_keys.py`:

```python
def test_the_target_key_is_stable_and_order_independent():
    first = compute_target_key(authorized_hosts=["demo.test", "api.demo.test"], targets=["https://api.demo.test/"])
    second = compute_target_key(authorized_hosts=["api.demo.test", "demo.test"], targets=["https://api.demo.test/"])
    assert first == second
    assert len(first) == 32


def test_a_different_target_has_a_different_key():
    assert compute_target_key(authorized_hosts=["demo.test"], targets=[]) != compute_target_key(
        authorized_hosts=["other.test"], targets=[]
    )


def test_the_comparison_key_changes_with_the_scanner_set():
    base = compute_comparison_key(
        target_key="k", excluded_paths=[], profile="standard", scanners=["nuclei"], agent_roles=["recon"], identity_ids=[]
    )
    changed = compute_comparison_key(
        target_key="k", excluded_paths=[], profile="standard", scanners=["nuclei", "katana"], agent_roles=["recon"], identity_ids=[]
    )
    assert base != changed


def test_the_comparison_key_changes_with_the_identities():
    without = compute_comparison_key(
        target_key="k", excluded_paths=[], profile="standard", scanners=[], agent_roles=[], identity_ids=[]
    )
    with_identity = compute_comparison_key(
        target_key="k", excluded_paths=[], profile="standard", scanners=[], agent_roles=[], identity_ids=["id-1"]
    )
    assert without != with_identity
```

- [ ] **Step 2: Write the failing integration test**

`tests/integration/test_scan_resume.py` — reuse the `ScriptedProvider` and `_context` helpers from `tests/integration/test_scan_lifecycle.py`:

```python
def test_a_succeeded_agent_task_is_not_run_again(services, orchestrator_parts):
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "resumed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "phase": "agents",
        }
    )
    services.tasks.upsert(
        scan_id=scan.scan_id,
        task_id=f"{scan.scan_id}:recon",
        title="Recon",
        agent_role="recon",
        budget={},
        input={},
    )
    services.tasks.set_status(f"{scan.scan_id}:recon", "succeeded", result={"role": "recon"})
    provider.script = [_conclusion("done"), _conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon", "api"]
    await orchestrator.run(context)
    roles = [call for call in provider.calls]
    assert roles  # the api role still ran
    tasks = {task["task_id"]: task for task in services.tasks.list_for_scan(scan.scan_id)}
    assert tasks[f"{scan.scan_id}:recon"]["status"] == "succeeded"
    assert tasks[f"{scan.scan_id}:api"]["status"] == "succeeded"


def test_a_scan_resumes_at_the_phase_it_reached(services, orchestrator_parts):
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create(
        {
            "name": "resumed scan",
            "status": "running",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "phase": "agents",
        }
    )
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon"]
    await orchestrator.run(context)
    kinds = {event["kind"] for event in services.events.list_after(scan.scan_id)}
    assert "workers.dispatched" not in kinds
    assert services.scans.get(scan.scan_id).phase == "completed"
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_scan_keys.py -q` and `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_scan_resume.py -q`

Expected: FAIL — `ImportError: cannot import name 'compute_target_key'` and, for the integration test, the orchestrator has no phase handling.

- [ ] **Step 4: Implement the key helpers**

`b_hunters/platform/scan_keys.py`:

- `compute_target_key(*, authorized_hosts, targets)`: build the material as `"|".join(sorted({h.strip().lower().rstrip(".") for h in authorized_hosts}) + sorted({t.strip() for t in targets}))` and return `hashlib.sha256(material.encode()).hexdigest()[:32]`.
- `compute_comparison_key(*, target_key, excluded_paths, profile, scanners, agent_roles, identity_ids)`: build the material as `"|".join([target_key, profile, ",".join(sorted(excluded_paths)), ",".join(sorted(scanners)), ",".join(sorted(agent_roles)), ",".join(sorted(identity_ids))])` and return the same 32-character hash.

- [ ] **Step 5: Add the scan fields and the task upsert**

In `b_hunters/platform/db/repositories.py`:

- `ScanRecord.from_document` reads `phase` (default `"pending"`), `coverage` (default `{}`), `target_key` and `comparison_key` (default `""`); `ScanRecord.public()` exposes them.
- `ScanRepository.set_phase(scan_id, phase)` sets `phase` and `updated_at`, and returns whether the scan exists.
- `ScanRepository.set_coverage(scan_id, coverage)` sets `coverage`.
- `TaskRepository.upsert(...)`: look up `{"task_id": task_id}`; when it does not exist, insert the same document shape as `create`; when it exists and its status is `succeeded`, leave `status` and `result` alone and update `title`, `budget` and `input`; otherwise set `status="pending"`, clear `result`, `error` and `finished_at`, and bump `attempts` to 0.

- [ ] **Step 6: Make the orchestrator phase-aware**

In `b_hunters/platform/agents/orchestrator.py`:

- Add `SCAN_PHASES = ("workers", "agents", "verifying", "reporting", "completed")`.
- `run()` reads the stored phase with `self.scans.get(context.scan_id)` and runs only the stages that have not completed:
  - `workers`: `_dispatch_scanners` then `_dispatch_workers`, then `set_phase("agents")`;
  - `agents`: the hypothesis roles, then `set_phase("verifying")`;
  - `verifying`: the verification roles, then `set_phase("reporting")`;
  - `reporting`: the reporting roles, then `set_phase("completed")`.
  A stage whose phase is already recorded as completed is skipped; `completed` skips everything.
- The plan is persisted with `self.tasks.upsert(...)` instead of `self.tasks.create(...)`.
- `_run_agent_tasks` is called once per stage with the tasks of that stage. Before running a task, `self.tasks.get(task.task_id)` is read; a task whose status is `succeeded` is skipped and its stored result is reused (the findings it produced are already persisted, so the candidate list is seeded from `self.findings.list(context.scan_id, limit=2000)` at the start of the stage).
- The candidate list is seeded from the persisted findings with the mapping `title`, `summary`, `vuln_class`, `severity`, `host`, `path`, `parameter`, `confidence` and `evidence` (the stored evidence list), skipping rows whose `vuln_class` is empty.
- The coverage summary is written after the worker stage: `{"hosts": <distinct hosts in platform_services>, "urls": <count of platform_services rows>, "worker_tasks_succeeded": <count of succeeded tasks of kind worker>, "worker_tasks_failed": <count of failed tasks>, "authenticated": False}`.

- [ ] **Step 7: Compute the keys when a scan is created**

In `b_hunters/platform/api/routers/scans.py`, in `create_scan`, add to the scan document:

```python
"target_key": compute_target_key(
    authorized_hosts=result["authorized_hosts"], targets=result["accepted_urls"]
),
"comparison_key": compute_comparison_key(
    target_key=<the value above>,
    excluded_paths=payload.targets.excluded_paths,
    profile=profile.name,
    scanners=profile.scanners,
    agent_roles=profile.agent_roles,
    identity_ids=[],  # the identity vault arrives in phase 2a
),
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_scan_keys.py -q` and `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_scan_resume.py tests/integration/test_scan_lifecycle.py -q`

Expected: PASS. The lifecycle test must still pass — it drives the orchestrator directly.

- [ ] **Step 9: Commit**

```bash
git add b_hunters/platform/scan_keys.py b_hunters/platform/db/repositories.py b_hunters/platform/agents/orchestrator.py b_hunters/platform/api/routers/scans.py tests/unit/test_scan_keys.py tests/integration/test_scan_resume.py
git commit -m "feat(platform): checkpoint scan phases and resume agent tasks"
```

---

### Task 8: Durable issues

**Files:**
- Create: `b_hunters/platform/db/issues.py`
- Modify: `b_hunters/platform/db/repositories.py` (`FindingRepository` links an issue)
- Modify: `b_hunters/platform/api/deps.py` (`services.issues`)
- Modify: `b_hunters/cli.py` (`b-hunters admin migrate-issues`)
- Test: `tests/integration/test_issues.py`

**Interfaces:**
- Consumes: `Database`, `ScanRepository` (for the target key of a scan).
- Produces: `b_hunters.platform.db.issues.IssueRepository` with
  - `upsert_for_finding(*, scan_id: str, fingerprint: str, title: str, severity: str, vuln_class: str) -> tuple[dict[str, Any], bool]`
  - `get(issue_id: str) -> dict[str, Any] | None`
  - `get_by_key(*, target_key: str, fingerprint: str) -> dict[str, Any] | None`
  - `set_triage(issue_id: str, *, status: str, assignee: str = "", tags: Sequence[str] = (), due_at: float | None = None) -> bool`
  - `list(*, triage_status: str = "", severity: str = "", limit: int = 100, offset: int = 0) -> list[dict[str, Any]]`
  - `history(issue_id: str) -> list[dict[str, Any]]`
  - `apply_scan_observations(*, scan_id: str, target_key: str, observed_fingerprints: Sequence[str], auto_close_misses: int = 2) -> dict[str, int]`

  The issue comments (`platform_issue_comments`) and the triage API endpoints are Phase 4 work; this task builds the durable issue and its state machine only.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_issues.py`:

```python
def test_a_finding_links_to_an_issue(services):
    scan = services.scans.create(
        {
            "name": "s",
            "status": "queued",
            "created_by": "test",
            "definition": {"targets": ["https://demo.test/"]},
            "scope": {"authorized_hosts": ["demo.test"]},
            "target_key": "demo.test",
        }
    )
    finding, _ = services.findings.upsert(
        scan_id=scan.scan_id, title="XSS", summary="s", vuln_class="xss", severity="high", host="demo.test", path="/x"
    )
    assert finding["issue_id"]
    issue = services.issues.get(finding["issue_id"])
    assert issue["fingerprint"] == finding["fingerprint"]
    assert issue["triage_status"] == "open"


def test_the_same_fingerprint_in_two_scans_shares_one_issue(services):
    for index in (1, 2):
        scan = services.scans.create(
            {
                "name": f"s{index}",
                "status": "queued",
                "created_by": "test",
                "definition": {"targets": ["https://demo.test/"]},
                "scope": {"authorized_hosts": ["demo.test"]},
                "target_key": "demo.test",
            }
        )
        services.findings.upsert(
            scan_id=scan.scan_id, title="XSS", summary="s", vuln_class="xss", severity="high", host="demo.test", path="/x"
        )
    issues = services.issues.list()
    assert len(issues) == 1
    assert len(services.issues.history(issues[0]["issue_id"])) == 2


def test_an_unobserved_issue_is_not_observed_and_then_auto_closed(services):
    issue, _ = services.issues.upsert_for_finding(
        scan_id=_scan_with_key(services).scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss"
    )
    counts = services.issues.apply_scan_observations(
        scan_id=_scan_with_key(services).scan_id, target_key="demo.test", observed_fingerprints=[]
    )
    assert counts["not_observed"] == 1
    assert services.issues.get(issue["issue_id"])["observation_status"] == "not_observed"
    services.issues.apply_scan_observations(
        scan_id=_scan_with_key(services).scan_id, target_key="demo.test", observed_fingerprints=[]
    )
    assert services.issues.get(issue["issue_id"])["observation_status"] == "auto_closed"


def test_a_manual_fixed_issue_is_not_auto_closed(services):
    issue, _ = services.issues.upsert_for_finding(
        scan_id=_scan_with_key(services).scan_id, fingerprint="fp", title="XSS", severity="high", vuln_class="xss"
    )
    services.issues.set_triage(issue["issue_id"], status="fixed")
    services.issues.apply_scan_observations(
        scan_id=_scan_with_key(services).scan_id, target_key="demo.test", observed_fingerprints=[]
    )
    assert services.issues.get(issue["issue_id"])["triage_status"] == "fixed"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_issues.py -q`

Expected: FAIL — `services.issues` does not exist.

- [ ] **Step 3: Implement the issue repository**

`b_hunters/platform/db/issues.py`:

- The issue document: `issue_id`, `target_key`, `fingerprint`, `title`, `severity`, `vuln_class`, `triage_status` (`open`), `assignee` (`""`), `tags` (`[]`), `due_at` (`None`), `observation_status` (`observed`), `consecutive_misses` (`0`), `first_seen_at`, `last_seen_at`, `last_seen_scan_id`, `created_at`, `updated_at`.
- `upsert_for_finding` resolves the target key from the scan document (`platform_scans.target_key`); when the scan has no target key it falls back to the scan id so that unkeyed scans never share an issue. On the first sighting it inserts the issue; later sightings update `last_seen_at`, `last_seen_scan_id`, `severity` and `title`, and append to `seen_scans` (a list of scan ids). It returns `(document, created)`.
- `history(issue_id)` returns the list of scan ids in `seen_scans` with their scan documents' `name`, `status` and `created_at`.
- `set_triage` validates the status against `open`, `in_progress`, `fixed`, `risk_accepted`, `false_positive`, `duplicate`, `auto_closed` and updates `triage_status`, `assignee`, `tags` and `due_at`.
- `apply_scan_observations` iterates the issues of the target key: when the fingerprint is in `observed_fingerprints` it sets `observation_status="observed"` and `consecutive_misses=0`; otherwise it increments `consecutive_misses`, sets `observation_status="not_observed"`, and when `consecutive_misses >= auto_close_misses` it sets `observation_status="auto_closed"` and `triage_status="auto_closed"` unless the triage status is `fixed`, `risk_accepted` or `false_positive`. It returns `{"observed": n, "not_observed": n, "auto_closed": n}`. The diff endpoint of Phase 3 is the caller; Phase 1 ships the method with its tests and no caller.

- [ ] **Step 4: Link the occurrences to the issue**

In `b_hunters/platform/db/repositories.py`, `FindingRepository.__init__` gains an optional `issues` argument (`issues: "IssueRepository | None" = None`, imported under `TYPE_CHECKING` to avoid a circular import). In `upsert`, after the document is written, when `self.issues` is not `None`:

```python
issue, _ = self.issues.upsert_for_finding(
    scan_id=scan_id,
    fingerprint=fingerprint,
    title=title,
    severity=document.get("severity", "info"),
    vuln_class=vuln_class,
)
self._col.update_one({"finding_id": document["finding_id"]}, {"$set": {"issue_id": issue["issue_id"], "not_observed": False}})
document["issue_id"] = issue["issue_id"]
```

- [ ] **Step 5: Wire the container and add the migration command**

In `b_hunters/platform/api/deps.py`: `self.issues = IssueRepository(self.db)` and `self.findings = FindingRepository(self.db, issues=self.issues)`.

In `b_hunters/cli.py` add `admin_sub.add_parser('migrate-issues', help="Link existing findings to durable issues")`. The command iterates `platform_findings` documents without an `issue_id`, calls `services.issues.upsert_for_finding(...)` for each, writes the `issue_id` back, and prints the number of findings linked.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_issues.py -q`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add b_hunters/platform/db/issues.py b_hunters/platform/db/repositories.py b_hunters/platform/api/deps.py b_hunters/cli.py tests/integration/test_issues.py
git commit -m "feat(platform): track findings as durable issues across scans"
```

---

### Task 9: Provider credentials encrypted at rest

**Files:**
- Modify: `b_hunters/platform/db/repositories.py` (`ProviderRepository`)
- Modify: `b_hunters/platform/api/deps.py` (pass the secret box)
- Modify: `b_hunters/platform/agents/factory.py` (decrypt at use)
- Modify: `b_hunters/cli.py` (`b-hunters admin migrate-secrets`)
- Test: `tests/integration/test_provider_secrets.py`

**Interfaces:**
- Consumes: `SecretBox` (Task 2).
- Produces:
  - `ProviderRepository(db, secret_box: SecretBox | None = None)` with `upsert`, `get`, `list`, `delete`, `public`, and `secret_for(name: str) -> str`.
  - `b-hunters admin migrate-secrets` — encrypts the plaintext provider keys.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_provider_secrets.py`:

```python
def test_a_provider_key_is_stored_encrypted(services, settings):
    services.providers.upsert({"name": "p1", "base_url": "https://x", "model": "m", "api_key": "sk-secret"})
    document = services.providers.get("p1")
    assert document.get("api_key") in (None, "")
    assert document["api_key_ciphertext"].startswith("bh1.")
    assert services.providers.secret_for("p1") == "sk-secret"


def test_the_api_never_returns_the_provider_key(client, csrf, services):
    services.providers.upsert({"name": "p1", "base_url": "https://x", "model": "m", "api_key": "sk-secret"})
    response = client.get("/api/v1/admin/providers", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert "sk-secret" not in response.text


def test_migrate_secrets_encrypts_an_existing_provider(services):
    services.db.collection("platform_providers").insert_one(
        {"name": "legacy", "base_url": "https://x", "model": "m", "api_key": "sk-legacy"}
    )
    migrated = migrate_provider_secrets(services)
    assert migrated == 1
    document = services.providers.get("legacy")
    assert document.get("api_key") in (None, "")
    assert services.providers.secret_for("legacy") == "sk-legacy"
```

`migrate_provider_secrets(services) -> int` is a function in `b_hunters/platform/db/repositories.py`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_provider_secrets.py -q`

Expected: FAIL — the key is stored in plain text.

- [ ] **Step 3: Encrypt the provider key**

In `b_hunters/platform/db/repositories.py`:

- `ProviderRepository.__init__(self, db, secret_box: SecretBox | None = None)`.
- `upsert(provider)`: when `self.secret_box` is not `None` and the document carries a plain `api_key`, encrypt it into `api_key_ciphertext` and remove `api_key` from the stored document. When there is no secret box, store the plain key as before (the deployment has not configured a key yet).
- `secret_for(name)`: returns the decrypted key — from `api_key_ciphertext` when present, otherwise from a plain `api_key`.
- `public(provider)`: masks `api_key`, `api_key_ciphertext` and `secret` (it already masks the first and the third; add `api_key_ciphertext`).
- `migrate_provider_secrets(services) -> int`: for every provider document with a plain `api_key`, encrypt it and unset the plain value; returns the number of providers migrated. It raises `RuntimeError` when `services.secret_box` is `None`.

In `b_hunters/platform/api/deps.py`: `self.providers = ProviderRepository(self.db, secret_box=self.secret_box)` — `self.secret_box` must be created before it.

In `b_hunters/platform/agents/factory.py`: `provider_config_for` uses `services.providers.secret_for(provider_name)` instead of `document.get("api_key", "")`.

- [ ] **Step 4: Add the migration command**

In `b_hunters/cli.py`: `admin_sub.add_parser('migrate-secrets', help="Encrypt the stored credentials with BHUNTERS_SECRET_KEY")`. The command calls `migrate_provider_secrets(services)` and prints the count.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_provider_secrets.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add b_hunters/platform/db/repositories.py b_hunters/platform/api/deps.py b_hunters/platform/agents/factory.py b_hunters/cli.py tests/integration/test_provider_secrets.py
git commit -m "feat(platform): encrypt the stored provider credentials"
```

---

### Task 10: Deploy the runner

**Files:**
- Modify: `docker-compose.platform.yml`
- Create: `docs/runner.md`

**Interfaces:**
- Consumes: `b-hunters runner` (Task 4), `BHUNTERS_SECRET_KEY` (Task 2).
- Produces: a `runner` service in the stack that runs the queue, and a health check that reports a stale runner.

- [ ] **Step 1: Add the runner service**

In `docker-compose.platform.yml`, next to the `platform` service:

```yaml
  runner:
    build:
      context: .
      dockerfile: Dockerfile
    image: b-hunters-platform:1.2.0
    container_name: bhunter_runner
    restart: unless-stopped
    depends_on:
      - mongo
      - redis
    environment:
      - BHUNTERS_MONGO_URI=mongodb://bhunter:bhunter_dev_pw@mongo:27017/?authSource=admin
      - BHUNTERS_MONGO_DB=b-hunters
      - BHUNTERS_KARTON_CONFIG_PATH=/etc/b-hunters/b-hunters.ini
      - BHUNTERS_AGENT_WORKSPACE_ROOT=/var/lib/b-hunters/workspaces
      - BHUNTERS_SECRET_KEY=${BHUNTERS_SECRET_KEY:?set BHUNTERS_SECRET_KEY in the environment file}
      - BHUNTERS_RUNNER_CONCURRENCY=${BHUNTERS_RUNNER_CONCURRENCY:-1}
      - BHUNTERS_RUNNER_LEASE_SECONDS=${BHUNTERS_RUNNER_LEASE_SECONDS:-60}
      - BHUNTERS_LLM_NAME=${MINIMAX_NAME:-minimax}
      - BHUNTERS_LLM_BASE_URL=${MINIMAX_HOST}
      - BHUNTERS_LLM_API_KEY=${MINIMAX_KEY}
      - BHUNTERS_LLM_MODEL=${MINIMAX_MODEL:-MINIMAX-M3.1-flash}
    command: ["b-hunters", "runner"]
    volumes:
      - ./deploy/platform.ini:/etc/b-hunters/b-hunters.ini:ro
      - workspaces:/var/lib/b-hunters
    healthcheck:
      test: ["CMD-SHELL", "b-hunters runner status || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
```

The runner shares the `workspaces` volume with the platform so that the agent workspaces survive a restart.

- [ ] **Step 2: Validate the compose file**

Run: `docker compose --env-file ../.env -f docker-compose.platform.yml config >/dev/null`

Expected: exit code 0. When `BHUNTERS_SECRET_KEY` is missing from the environment file the command fails with the `:?` message — that is the intended behaviour; add the key to the environment file (`openssl rand -base64 32`) before deploying.

- [ ] **Step 3: Write the runner documentation**

`docs/runner.md` describes: what the runner does, how a job moves from queued to succeeded, the lease and the heartbeat, what happens when the runner dies (the lease expires and the job is reclaimed), how to inspect the queue (`b-hunters runner status`, the `platform_jobs` collection), how to recover a stuck scan (cancel the job, set the scan status back to `queued`, start it again), and the setting reference (`BHUNTERS_RUNNER_CONCURRENCY`, `BHUNTERS_RUNNER_LEASE_SECONDS`, `BHUNTERS_RUNNER_HEARTBEAT_SECONDS`, `BHUNTERS_RUNNER_POLL_SECONDS`, `BHUNTERS_JOB_MAX_ATTEMPTS`, `BHUNTERS_SECRET_KEY`).

- [ ] **Step 4: Commit**

```bash
git add docker-compose.platform.yml docs/runner.md
git commit -m "feat(deploy): run the job runner as its own service"
```

---

### Task 11: Verify the recovery end to end and update the status documents

**Files:**
- Modify: `/home/sniper/pentest/STATUS.md`
- Modify: `docs/implementation-report.md`
- Modify: `docs/architecture-audit.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the measured evidence that the phase works, recorded in the status documents.

- [ ] **Step 1: Run the whole suite and the linters**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests -q`

Expected: every test passes; the count is higher than 414 and the summary line states the exact number.

Run: `/home/sniper/pentest/.venv/bin/python -m ruff check b_hunters tests && /home/sniper/pentest/.venv/bin/python -m ruff format --check b_hunters tests`

Expected: clean.

Run: `/home/sniper/pentest/.venv/bin/python -m mypy b_hunters/platform/runner.py b_hunters/platform/db/jobs.py b_hunters/platform/db/issues.py b_hunters/platform/security/secrets.py b_hunters/platform/scan_keys.py b_hunters/platform/agents/factory.py --ignore-missing-imports --no-strict-optional`

Expected: `Success: no issues found`.

- [ ] **Step 2: Prove the restart behaviour against the live stack**

```bash
docker compose --env-file ../.env -f docker-compose.platform.yml up -d runner
docker compose --env-file ../.env -f docker-compose.platform.yml exec runner b-hunters runner status
```

Expected: the runner reports itself with a fresh heartbeat and exits 0.

Create a scan through the API, start it, and confirm that it is claimed by the runner and that restarting the API does not stop it:

```bash
docker compose --env-file ../.env -f docker-compose.platform.yml restart platform
docker compose --env-file ../.env -f docker-compose.platform.yml exec runner b-hunters runner status
```

Expected: the scan reaches `completed` while the API was restarting. Record the scan id, the job id and the final status in the status documents.

- [ ] **Step 3: Update the status documents**

In `/home/sniper/pentest/STATUS.md`, `docs/implementation-report.md` and `docs/architecture-audit.md`, record: the phase that just landed, the exact test count from Step 1, the recovery evidence from Step 2 (scan id, job id, statuses, and the command output), the new settings, and the fact that `mypy` is still not clean for the pre-existing 36 errors (Phase 6).

Every number must come from a command you ran. Do not write a claim you have not measured.

- [ ] **Step 4: Commit**

```bash
git add docs/implementation-report.md docs/architecture-audit.md
git commit -m "docs: record the durable-foundation results"
```

`/home/sniper/pentest/STATUS.md` is outside the repository and is not part of this commit.
