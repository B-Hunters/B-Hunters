# Worker Authentication Pass-through Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the seventeen Karton scanner workers run against an authenticated surface, by giving the shared worker base class an authentication helper and passing the identity's headers and cookies through the task payload.

**Architecture:** The framework's `b_hunters/bhunter.py` gains an `auth_headers(task)` helper that reads an `auth` payload from the Karton task and returns the headers and cookies to add to the tool's own invocation. The platform's Karton bridge puts the identity's `auth` payload into the task it publishes. The workers that support custom headers or cookies — nuclei, sqlmap, dalfox, wapiti, katana, gospider, dirsearch, xray — pass them to their tools; the rest ignore the payload and are unaffected. The shared base class is released as `b-hunters==1.3.0` and each worker repository bumps its pin.

**Tech Stack:** Python 3.10+ (the shared base class), the workers' own tool invocations, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-29-single-operator-platform-design.md` — §5.3 (worker pass-through) and §3.1 item 6.

**Preconditions.** The authenticated platform (`docs/superpowers/plans/2026-10-29-authenticated-platform.md`) must be in place: the identity vault, the login recorder and the identity injection into the native adapters. The workers are released from PyPI, so the platform must be able to install a specific version of the shared class.

## Global Constraints

- The seventeen worker repositories are separate repositories. Every change in one of them is its own commit with its own message.
- A worker that does not support authentication must keep working exactly as it does now: the `auth` payload is optional and ignored when absent.
- No credential ever enters a worker's log output, a result document or the platform's database. The `auth` payload carries the values, so the bridge must never write it into the report.
- The shared base class's tests run in the framework repository; each worker repository runs its own tests.
- One worker is changed and verified at a time, with `dev/check_workers_one_by_one.py`, so a broken worker cannot be masked by a working one.

---

### Task 1: The shared base class

**Files:** Modify `b_hunters/bhunter.py` in `repos/B-Hunters`; add its tests; test `tests/unit/test_worker_auth.py`.

**Interfaces:**
- `BHunters.auth_headers(task) -> dict[str, str]` — reads `task.payload.get("auth", {})` and returns a header mapping: the `cookies` value becomes a `Cookie` header, the `headers` mapping is merged, and `extra` is merged last so it wins. An absent or empty payload returns `{}`.
- `BHunters.auth_cookies(task) -> dict[str, str]` — the cookie mapping alone, for the tools that take a cookie jar.
- The class keeps a `self.auth_headers` attribute the subclass may read, so a worker does not have to call the helper itself.

- [ ] **Step 1: Write the failing test**

```python
def test_an_absent_auth_payload_yields_no_headers():
    worker = _worker()
    assert worker.auth_headers(_task(payload={})) == {}


def test_the_auth_payload_becomes_headers():
    worker = _worker()
    headers = worker.auth_headers(_task(payload={"auth": {"cookies": {"JSESSIONID": "abc"}, "headers": {"X-Test": "1"}}}))
    assert headers["Cookie"] == "JSESSIONID=abc"
    assert headers["X-Test"] == "1"


def test_extra_headers_win():
    worker = _worker()
    headers = worker.auth_headers(_task(payload={"auth": {"headers": {"X-Test": "1"}, "extra": {"X-Test": "2"}}}))
    assert headers["X-Test"] == "2"
```

- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement in `b_hunters/bhunter.py`. The helper must not log the values.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(workers): accept an authentication payload"`.

---

### Task 2: The platform publishes the auth payload

**Files:** Modify `b_hunters/platform/scanners/karton_bridge.py`; test `tests/integration/test_worker_auth_payload.py`.

**Interfaces:** when a scan names an identity, the Karton task the bridge publishes carries `payload["auth"] = {"cookies": {...}, "headers": {...}}`; without an identity it carries nothing. The report document the bridge writes must never contain the `auth` payload.

- [ ] **Step 1:** write the failing tests (the published task carries the auth; the report does not).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run — expect PASS.
- [ ] **Step 5:** commit — `git commit -m "feat(platform): give the workers the target's session"`.

---

### Task 3: One worker at a time

**Files:** In each of `repos/B-Hunters-Nuclei`, `repos/B-Hunters-Sqlmap`, `repos/B-Hunters-DalFox`, `repos/B-Hunters-Wapiti`, `repos/B-Hunters-Katana`, `repos/B-Hunters-GoSpider`, `repos/B-Hunters-Dirsearch`, `repos/B-Hunters-xray`: the worker source and its Dockerfile.

**Interfaces:** each worker passes `self.auth_headers(task)` (or `self.auth_cookies(task)`) to its tool as the custom-header or cookie option the tool already supports. A worker whose tool has no such option ignores the payload and logs nothing about it.

- [ ] **Step 1:** for one worker — nuclei first — write the failing test (the task it builds carries the header argument when the payload has one).
- [ ] **Step 2:** run it — expect FAIL.
- [ ] **Step 3:** implement, and bump the worker's `b-hunters` pin to `1.3.0`.
- [ ] **Step 4:** run the worker's tests and `python /home/sniper/pentest/dev/check_workers_one_by_one.py --worker <name>` — expect PASS.
- [ ] **Step 5:** commit in that repository — `git commit -m "feat: send the session headers to the scanner"`.
- [ ] **Step 6:** repeat steps 1–5 for the remaining seven workers, one repository at a time, verifying each before moving to the next.

---

### Task 4: The release and the deployment

**Files:** `repos/B-Hunters/setup.py` (the version), `repos/B-Hunters/docs/` (the release note), the worker Dockerfiles.

**Interfaces:** `b-hunters==1.3.0` is published, and every worker image that uses the shared class pins it. The platform's compose file pins the images it builds.

- [ ] **Step 1:** bump the version, tag `v1.3.0` and build the release artefact.
- [ ] **Step 2:** update the eight worker repositories' pins and rebuild their images.
- [ ] **Step 3:** rebuild the platform image and redeploy the stack; confirm every worker registers on the Karton backend.
- [ ] **Step 4:** run a scan of a lab with an identity and confirm the authenticated workers report findings the unauthenticated scan did not.
- [ ] **Step 5:** document the change in `docs/authenticated-scanning.md`.
