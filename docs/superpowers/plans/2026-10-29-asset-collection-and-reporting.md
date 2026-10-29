# Asset Collection and Complete Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect every URL the platform can see — including JavaScript and image URLs that nothing collects today — into one inventory, record what each tool and each agent actually did, and show all of it in the console and the report.

**Architecture:** A new `platform_assets` collection holds one row per URL with its kind, scope, status, size and the tools that saw it. A new native `asset_crawl` adapter discovers URLs; a merge step at the end of the worker phase folds the workers' output and the fingerprinted URLs into the same rows, deduplicated by normalised URL. The worker phase begins by snapshotting which workers are online and ends by persisting per-worker task and crash counts, so the participation table can say *why* a tool did not report. The scan's time cap becomes an enforced deadline, so a role that was cut off is recorded as cut off. A new error ledger classifies every failure, so the verification can assert that nothing failed without an explanation.

**Tech Stack:** Python 3.10+, FastAPI, pymongo against MongoDB 7, pytest + pytest-asyncio, zero-build ES modules for the console.

**Spec:** `docs/superpowers/specs/2026-10-29-asset-collection-and-reporting-design.md` — this plan implements §3, §3.1, §5, §6, §7, §8, §11, §12, §13. The durable job runner this workstream depends on is in `docs/superpowers/plans/2026-10-29-durable-foundation.md`; execute that plan first.

## Global Constraints

- Every new module starts with `from __future__ import annotations` and a module docstring.
- Python 3.10-compatible syntax; `ruff check b_hunters tests` and `ruff format --check b_hunters tests` must pass before every commit.
- mypy must not gain new errors: `mypy <the files this task touches> --ignore-missing-imports --no-strict-optional` must report none. The repository has 36 pre-existing errors elsewhere; do not fix them here.
- Scope enforcement stays mandatory. Every outbound request goes through `ScopeEnforcer`; a new request path that bypasses it is a defect.
- Secrets never enter Mongo, an API response, an event payload or a report. Use `b_hunters/platform/security/redact.py`.
- No native adapter may store a response body or an image byte. The inventory is metadata only.
- A stored tool output is bounded at 512 KB (`ToolPermissions.max_output_bytes`). Never store more than the model saw.
- The legacy collections (`scans`, `domains`, `reports`, `js`) are read-only. Every new collection is `platform_*` and registered in `PLATFORM_COLLECTIONS` and `INDEXES` in `b_hunters/platform/db/client.py`.
- Test commands (run from `/home/sniper/pentest/repos/B-Hunters`):
  - unit: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit -q`
  - full: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests -q`
- Integration tests skip when MongoDB is unreachable; a skipped test is not a pass — read the summary line.

## Review Focus

The failure modes the spec implies that no task's tests obviously cover. Each is pinned to a test in the owning task.

1. **A tool output that cannot be stored must be visible, not missing** — a failed insert emits `tool.record_failed` rather than disappearing — pinned in Task 11 (`test_a_failed_tool_call_insert_is_reported`).
2. **A third-party reference must never be fetched** — pinned in Task 3 (`test_an_external_reference_is_recorded_but_never_fetched`).
3. **A worker that consumed a task and crashed must be distinguishable from one that found nothing** — pinned in Task 7 (`test_a_crashed_worker_is_reported_as_errored`).
4. **A role that never started because the deadline passed must not be reported as succeeded** — pinned in Task 9 (`test_a_role_that_never_started_is_recorded_as_wall_clock`).
5. **The same URL seen by the crawler and by katana must be one row listing both sources** — pinned in Task 5 (`test_one_url_seen_by_two_tools_is_one_row`).

---

### Task 1: The asset repository

**Files:**
- Create: `b_hunters/platform/db/assets.py`
- Modify: `b_hunters/platform/db/client.py`
- Test: `tests/integration/test_asset_repository.py`

**Interfaces:**
- Consumes: `Database`.
- Produces: `b_hunters.platform.db.assets.AssetRepository` with
  - `upsert(*, scan_id: str, url: str, kind: str, scope: str = "first_party", host: str = "", path: str = "", status_code: int = 0, content_type: str = "", size_bytes: int = 0, depth: int = 0, source: str = "", discovered_from: str = "", extension: str = "") -> tuple[dict[str, Any], bool]`
  - `get(asset_id: str) -> dict[str, Any] | None`
  - `list_for_scan(scan_id: str, *, kind: str = "", scope: str = "", limit: int = 500, offset: int = 0) -> list[dict[str, Any]]`
  - `counts_for_scan(scan_id: str) -> dict[str, int]` — the count per kind
  - `count(scan_id: str = "") -> int`

- [ ] **Step 1: Write the failing test**

`tests/integration/test_asset_repository.py`:

```python
def test_an_asset_is_upserted_by_its_url(database):
    repo = AssetRepository(database)
    document, created = repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl")
    assert created is True
    assert document["kind"] == "js"
    assert repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="katana")[1] is False


def test_a_second_source_is_added_to_the_same_row(database):
    repo = AssetRepository(database)
    repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl")
    document, _ = repo.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="katana")
    assert sorted(document["sources"]) == ["asset_crawl", "katana"]


def test_assets_are_counted_by_kind(database):
    repo = AssetRepository(database)
    repo.upsert(scan_id="s1", url="https://demo.test/", kind="page")
    repo.upsert(scan_id="s1", url="https://demo.test/a.js", kind="js")
    repo.upsert(scan_id="s1", url="https://demo.test/a.js", kind="js")
    counts = repo.counts_for_scan("s1")
    assert counts["page"] == 1
    assert counts["js"] == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_asset_repository.py -q`

Expected: FAIL — `ImportError: cannot import name 'AssetRepository'`.

- [ ] **Step 3: Implement the repository**

`b_hunters/platform/db/assets.py`:

- The document: `asset_id`, `scan_id`, `url`, `host`, `path`, `kind`, `scope`, `status_code`, `content_type`, `size_bytes`, `depth`, `sources` (list), `source`, `discovered_from`, `extension`, `first_seen_at`, `last_seen_at`.
- `upsert` finds the row by `(scan_id, url)`. On a new row it inserts with `sources=[source]`. On an existing row it adds the source when it is new, updates `last_seen_at`, and fills in `status_code`, `content_type` and `size_bytes` when they are still empty. It returns `(document, created)`.
- `list_for_scan` filters by `kind` and `scope` when given, sorts by `url`, and caps the page at 2000.
- `counts_for_scan` aggregates by kind and returns a zero for every kind in `page, js, image, css, api, other`.

In `b_hunters/platform/db/client.py`: add `"platform_assets"` and `"platform_worker_runs"` to `PLATFORM_COLLECTIONS`, and to `INDEXES`:

- `platform_assets`: `("scan_id", ASCENDING), ("url", ASCENDING)` unique; `("scan_id", ASCENDING), ("kind", ASCENDING)`; `("host", ASCENDING)`; `("kind", ASCENDING), ("last_seen_at", DESCENDING)`.
- `platform_worker_runs`: `("scan_id", ASCENDING), ("worker", ASCENDING)` unique; `("scan_id", ASCENDING), ("crashed_tasks", DESCENDING)`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_asset_repository.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/db/assets.py b_hunters/platform/db/client.py tests/integration/test_asset_repository.py
git commit -m "feat(platform): store the asset inventory"
```

---

### Task 2: URL normalisation and classification

**Files:**
- Create: `b_hunters/platform/assets.py`
- Test: `tests/unit/test_assets.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `b_hunters.platform.assets.ASSET_KINDS = ("page", "js", "image", "css", "api", "other")`
  - `normalise_url(url: str) -> str` — lowercase scheme and host, drop the default port, normalise the path, drop the fragment, sort the query, redact credential-shaped query parameters.
  - `redact_query(query: str) -> str` — replaces the values of credential-shaped parameters with `[REDACTED]`.
  - `classify(*, content_type: str = "", url: str = "", path: str = "") -> str` — one of `ASSET_KINDS`, applying the rules in the design §5.3 in order: content type, then extension, then path.
  - `extension_of(url: str) -> str` — the lower-cased file extension without the dot, `""` when there is none.
  - `is_external(url: str, authorized_hosts: Sequence[str]) -> bool` — `True` when the host is not covered by the authorised list.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_assets.py`:

```python
def test_a_url_is_normalised():
    assert normalise_url("HTTPS://Demo.test:443/app.js?b=2&a=1#frag") == "https://demo.test/app.js?a=1&b=2"


def test_a_credential_in_the_query_is_redacted():
    assert normalise_url("https://demo.test/x?token=abcdef123456&page=2") == "https://demo.test/x?page=2&token=[REDACTED]"


def test_a_javascript_file_is_classified_by_extension():
    assert classify(url="https://demo.test/app.js") == "js"


def test_a_content_type_wins_over_the_extension():
    assert classify(content_type="text/html", url="https://demo.test/app.js") == "page"


def test_an_image_is_classified():
    assert classify(content_type="image/png", url="https://demo.test/logo.png") == "image"


def test_an_api_path_is_classified():
    assert classify(path="/api/v1/users") == "api"


def test_a_third_party_host_is_external():
    assert is_external("https://cdn.example.com/app.js", ["demo.test"]) is True
    assert is_external("https://demo.test/app.js", ["demo.test"]) is False
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_assets.py -q`

Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement the module**

`b_hunters/platform/assets.py`:

- `normalise_url` uses `urllib.parse.urlsplit`, `urlunsplit` and `parse_qsl`/`urlencode`. It drops the fragment, lowercases the scheme and host, removes `:80` for `http` and `:443` for `https`, normalises an empty path to `/`, and sorts the query parameters by name.
- `redact_query` redacts the values of any parameter whose name matches `(?i)(token|key|secret|password|passwd|pwd|auth|session|signature|sig|access_token|api_key)`, replacing the value with `[REDACTED]` and keeping the name.
- `classify` applies the content-type rules first, then the extension rules, then the path rules; anything unmatched is `other`. The content types are matched case-insensitively and ignore any `; charset=…` suffix.
- `extension_of` takes the last path segment and returns the part after the final dot, lower-cased, when that part is 1–10 characters of letters and digits.
- `is_external` compares the URL's host against the authorised hosts, honouring a leading `*.` wildcard the same way `ScopePolicy.matches_host` does — import `ScopePolicy` and use its matching rather than writing a second rule.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_assets.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/assets.py tests/unit/test_assets.py
git commit -m "feat(platform): normalise and classify discovered URLs"
```

---

### Task 3: The `asset_crawl` adapter

**Files:**
- Modify: `b_hunters/platform/scanners/native.py`
- Modify: `b_hunters/platform/scanners/registry.py`
- Test: `tests/unit/test_asset_crawl.py`

**Interfaces:**
- Consumes: `ScanRequest`/`ScanResult` (`b_hunters/platform/scanners/base.py`), `ScopeEnforcer`, `normalise_url`, `classify`.
- Produces: `b_hunters.platform.scanners.native.asset_crawl_executor(request: ScanRequest) -> ScanResult` — a native adapter registered under the name `asset_crawl`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_asset_crawl.py` — build a fake `ScopeEnforcer` that records the URLs it was asked to fetch:

```python
class RecordingScope:
    def __init__(self, pages):
        self.pages = pages
        self.requested = []
        self.policy = None

    def evaluate_url(self, url, resolve=True):
        from b_hunters.platform.security.scope import ScopeDecision
        self.requested.append(url)
        return ScopeDecision(allowed=url in self.pages, reason="test", url=url, host="")

    def violation_count(self):
        return 0


def test_the_crawl_follows_same_origin_links():
    pages = {
        "https://demo.test/": '<a href="/app.js">js</a><img src="/logo.png">',
        "https://demo.test/app.js": "var a = 1;",
    }
    scope = RecordingScope(pages)
    request = _request(scope, targets=["https://demo.test/"])
    result = asset_crawl_executor(request)
    urls = {item["value"] for item in result.items}
    assert "https://demo.test/app.js" in urls
    assert "https://demo.test/logo.png" in urls
```

The test file provides a `_request(scope, targets)` helper that builds a `ScanRequest` with the recording scope.

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_asset_crawl.py -q`

Expected: FAIL — `ImportError: cannot import name 'asset_crawl_executor'`.

- [ ] **Step 3: Implement the adapter**

In `b_hunters/platform/scanners/native.py`:

- `asset_crawl_executor(request)`:
  - The seeds are `request.targets` plus any URLs in `request.seeds` that are in scope.
  - A queue of `(url, depth)`; the seeds start at depth 0. The maximum depth is 3 and the maximum number of assets is 2000.
  - For each URL it fetches, it uses the same HTTP helper the other native adapters use — check how `security_headers_executor` and `openapi_discovery_executor` perform their request, and use that helper, so the scope policy and the rate limit are enforced by the same path.
  - It records the URL with `kind` from `classify(content_type=..., url=...)`, `scope` from `is_external(url, request.scope.policy.authorized_hosts)`, `status_code`, `content_type`, `size_bytes` (the length of the body read, capped at the 256 KB read limit) and `discovered_from`.
  - It extracts links from the body: `href` and `src` attributes, absolute or relative, resolved against the page URL. A reference whose host is not authorised is recorded as an external reference and never fetched. `fetch`/`XMLHttpRequest` targets inside inline scripts are recorded too, resolved against the page URL, and fetched only when they are same-origin.
  - It never writes the body into the result; only the metadata.
- Register it in `b_hunters/platform/scanners/registry.py` under the name `asset_crawl`, with a description, a version, and `kind="native"`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_asset_crawl.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/scanners/native.py b_hunters/platform/scanners/registry.py tests/unit/test_asset_crawl.py
git commit -m "feat(platform): crawl the target for every URL it serves"
```

---

### Task 4: The two-wave native dispatch and the worker phase share

**Files:**
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Modify: `b_hunters/platform/settings.py`
- Test: `tests/integration/test_native_waves.py`

**Interfaces:**
- Consumes: `ScanProfile`, `Settings`.
- Produces:
  - `Settings.worker_phase_share: float = 0.7` — the share of the scan duration the worker phase may use.
  - The orchestrator dispatches the native adapters in two waves: every adapter except `asset_crawl` first, then `asset_crawl`.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_native_waves.py`:

```python
def test_the_asset_crawl_runs_after_the_fingerprinters(services):
    order = []

    class Recorder:
        def __init__(self, name):
            self.name = name
            self.kind = "native"

        async def execute(self, request):
            order.append(self.name)
            from b_hunters.platform.scanners.base import ScanResult
            return ScanResult(scanner=self.name, items=[], findings=[], error="")

    registry = build_default_registry({"asset_crawl": Recorder("asset_crawl").execute, "service_fingerprint": Recorder("service_fingerprint").execute})
    ...
```

The test builds an orchestrator with a registry whose two adapters record the order they run in, runs it against a scan, and asserts the order is `["service_fingerprint", "asset_crawl"]`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_native_waves.py -q`

Expected: FAIL — the adapters currently run in one concurrent gather, so the order is not guaranteed and `asset_crawl` may run first.

- [ ] **Step 3: Implement the two waves**

In `b_hunters/platform/agents/orchestrator.py`, `_dispatch_scanners`:

- Split `native_names` into `first_wave` (every adapter except `asset_crawl`) and `second_wave` (`["asset_crawl"]`).
- Run the first wave with the existing `asyncio.gather`, then the second wave with the same helper.
- The reason is in a comment: the crawler seeds itself from the URLs the fingerprinters recorded, so it must run after them.

In `b_hunters/platform/settings.py`:

- Add `worker_phase_share: float = 0.7` and add the name to the float list in `load_settings`.
- In the orchestrator, replace the module constants `WORKER_PHASE_SHARE` and `AGENT_PHASE_SHARE` with the setting: the worker phase gets `settings.worker_phase_share` and the agent phase gets `1 - worker_phase_share`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_native_waves.py tests/integration/test_scan_lifecycle.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/agents/orchestrator.py b_hunters/platform/settings.py tests/integration/test_native_waves.py
git commit -m "feat(platform): run the crawler after the fingerprinters"
```

---

### Task 5: The merge

**Files:**
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Test: `tests/integration/test_asset_merge.py`

**Interfaces:**
- Consumes: `AssetRepository`, `WorkerOutputRepository`, `ServiceRepository`, `normalise_url`, `classify`.
- Produces: `b_hunters.platform.agents.orchestrator.ScanOrchestrator._merge_assets(context, primary_target: str) -> dict[str, int]` — returns `{"assets": n, "from_workers": n, "from_services": n}`.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_asset_merge.py`:

```python
def test_one_url_seen_by_two_tools_is_one_row(services):
    scan = _scan(services)
    services.worker_output.replace_for_scan(
        scan.scan_id,
        [{"worker": "B-Hunters-Katana", "kind": "url", "value": "https://demo.test/app.js"}],
    )
    services.assets.upsert(scan_id=scan.scan_id, url="https://demo.test/app.js", kind="js", source="asset_crawl")
    orchestrator = _orchestrator(services)
    orchestrator._merge_assets(_context(services, scan_id=scan.scan_id), "https://demo.test/")
    rows = services.assets.list_for_scan(scan.scan_id)
    assert len(rows) == 1
    assert sorted(rows[0]["sources"]) == ["B-Hunters-Katana", "asset_crawl"]


def test_a_worker_path_is_resolved_against_the_target(services):
    scan = _scan(services)
    services.worker_output.replace_for_scan(
        scan.scan_id,
        [{"worker": "B-Hunters-dirsearch", "kind": "path", "value": "/admin"}],
    )
    orchestrator = _orchestrator(services)
    orchestrator._merge_assets(_context(services, scan_id=scan.scan_id), "https://demo.test/")
    rows = services.assets.list_for_scan(scan.scan_id)
    assert rows[0]["url"] == "https://demo.test/admin"
    assert rows[0]["status_code"] == 0


def test_a_javascript_file_from_the_jsscanner_is_classified_as_js(services):
    scan = _scan(services)
    services.worker_output.replace_for_scan(
        scan.scan_id,
        [{"worker": "B-Hunters-jsscanner", "kind": "item", "value": "https://demo.test/vendor/lib.js"}],
    )
    orchestrator = _orchestrator(services)
    orchestrator._merge_assets(_context(services, scan_id=scan.scan_id), "https://demo.test/")
    rows = services.assets.list_for_scan(scan.scan_id)
    assert rows[0]["kind"] == "js"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_asset_merge.py -q`

Expected: FAIL — `_merge_assets` does not exist.

- [ ] **Step 3: Implement the merge**

In `b_hunters/platform/agents/orchestrator.py`:

- `ScanOrchestrator.__init__` gains `self.assets = AssetRepository(database)`.
- `_merge_assets(context, primary_target)`:
  - Reads `self.worker_output.list_for_scan(context.scan_id, limit=5000)`.
  - For each item whose kind is `url` or `item`, the value is a URL candidate: normalise it; when it has no scheme, resolve it against `primary_target`.
  - For each item whose kind is `path`, resolve it against `primary_target`'s scheme and host; the result carries `status_code=0`.
  - The kind comes from `classify(url=...)` unless the item's worker is the jsscanner, in which case it is `js`.
  - It reads `self.services.list_for_scan(context.scan_id)` and adds each fingerprinted URL with the source `service_fingerprint`.
  - It upserts every row through `self.assets.upsert(...)` with `source` set to the item's worker.
  - It returns the counts.
- `_dispatch_workers` calls `_merge_assets` at the end, and the orchestrator emits the event `assets.merged` with the counts.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_asset_merge.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/agents/orchestrator.py tests/integration/test_asset_merge.py
git commit -m "feat(platform): merge the worker output into the asset inventory"
```

---

### Task 6: `list_assets` returns the real inventory

**Files:**
- Modify: `b_hunters/platform/tools/builtin/scan.py`
- Modify: `b_hunters/platform/agents/orchestrator.py` (the tool context metadata)
- Test: `tests/unit/test_list_assets_tool.py`

**Interfaces:**
- Consumes: `AssetRepository`.
- Produces: `list_assets(kind: str = "", limit: int = 100, *, context: ToolContext) -> dict[str, Any]` — reads the repository; its `kind` parameter accepts the old names (`url`, `route`, `host`, `technology`, `javascript`) and the new ones (`page`, `js`, `image`, `css`, `api`, `other`); `javascript` is an alias for `js`. The result is `{"kind", "count", "by_kind", "assets"}`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_list_assets_tool.py`:

```python
def test_the_tool_lists_the_real_assets(services):
    services.assets.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl")
    context = _context(services, scan_id="s1")
    result = list_assets("js", 100, context=context)
    assert result["count"] == 1
    assert result["assets"][0]["url"] == "https://demo.test/app.js"
    assert result["by_kind"]["js"] == 1


def test_javascript_is_an_alias_for_js(services):
    services.assets.upsert(scan_id="s1", url="https://demo.test/app.js", kind="js", source="asset_crawl")
    context = _context(services, scan_id="s1")
    assert list_assets("javascript", 100, context=context)["count"] == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_list_assets_tool.py -q`

Expected: FAIL — the tool still reads the empty metadata dictionary and returns zero.

- [ ] **Step 3: Implement the tool**

In `b_hunters/platform/tools/builtin/scan.py`:

- `list_assets` reads `context.metadata["asset_repository"]` and `context.metadata["scan_id"]`; when the repository is missing it returns the empty result it returns today rather than raising.
- The `kind` argument is mapped through an alias table (`javascript` → `js`, `url` → `""`, `route` → `""`, `host` → `""`, `technology` → `""`).
- The result carries `by_kind`, the counts per kind for the scan.

In `b_hunters/platform/agents/orchestrator.py`, `_make_tool_context` puts `asset_repository` and `scan_id` into the tool context metadata.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_list_assets_tool.py tests/unit/test_framework_tools.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/tools/builtin/scan.py b_hunters/platform/agents/orchestrator.py tests/unit/test_list_assets_tool.py
git commit -m "feat(platform): let the agents list the assets they found"
```

---

### Task 7: The facts behind the participation table

**Files:**
- Modify: `b_hunters/platform/scanners/karton_bridge.py`
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Modify: `b_hunters/platform/db/assets.py` (the `WorkerRunRepository`)
- Test: `tests/integration/test_worker_runs.py`

**Interfaces:**
- Consumes: the Karton producer's online consumers and the analysis of the dispatched tasks.
- Produces:
  - `b_hunters.platform.db.assets.WorkerRunRepository` with `record(*, scan_id: str, worker: str, tasks: int = 0, findings: int = 0, crashed_tasks: int = 0, connected: bool = False, expected_version: str = "") -> dict[str, Any]`, `list_for_scan(scan_id: str) -> list[dict[str, Any]]` and `snapshot_connection(scan_id: str, identities: Sequence[str]) -> None`.
  - `KartonWorkerBridge.online_identities() -> list[str]` — the identity of every consumer currently online.
  - `KartonWorkerBridge.worker_outcomes(scan_id: str) -> list[dict[str, Any]]` — per worker: the tasks it consumed, the findings it produced and the tasks that crashed.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_worker_runs.py`:

```python
def test_a_crashed_worker_is_reported_as_errored(services):
    repo = services.worker_runs
    repo.record(scan_id="s1", worker="B-Hunters-Nuclei", tasks=2, findings=1, crashed_tasks=1, connected=True)
    rows = repo.list_for_scan("s1")
    assert rows[0]["crashed_tasks"] == 1


def test_a_worker_is_recorded_once_per_scan(services):
    repo = services.worker_runs
    repo.record(scan_id="s1", worker="B-Hunters-Nuclei", tasks=1)
    repo.record(scan_id="s1", worker="B-Hunters-Nuclei", tasks=3)
    rows = repo.list_for_scan("s1")
    assert len(rows) == 1
    assert rows[0]["tasks"] == 3
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_worker_runs.py -q`

Expected: FAIL — `WorkerRunRepository` does not exist.

- [ ] **Step 3: Implement the repository and the bridge**

In `b_hunters/platform/db/assets.py`:

- `WorkerRunRepository.record` upserts on `(scan_id, worker)`, keeping the highest `tasks` count and adding the `crashed_tasks`, and setting `connected` when it is true.
- `snapshot_connection(scan_id, identities)` records one row per identity with `connected=True` and no tasks, so a worker that was online but never dispatched is distinguishable from one that was not online.

In `b_hunters/platform/scanners/karton_bridge.py`:

- `online_identities()` calls `producer.backend.get_online_consumers()` and returns the sorted identity names. When the backend is unreachable it returns `[]` and the caller records nothing rather than recording "not connected" — an unreachable backend is not evidence that a worker is absent.
- `worker_outcomes(scan_id)` returns the per-worker task counts (from the same counters the bridge already keeps), the finding counts (from the findings it persisted) and the crashed-task counts (from the Karton analysis, which the bridge currently discards — it must keep the analysis root uid per target so the crashed tasks can be counted afterwards).

In `b_hunters/platform/agents/orchestrator.py`:

- Before `_dispatch_workers`, the orchestrator snapshots the online identities into `platform_worker_runs`.
- After `_dispatch_workers`, it records each worker's outcome.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_worker_runs.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/db/assets.py b_hunters/platform/scanners/karton_bridge.py b_hunters/platform/agents/orchestrator.py tests/integration/test_worker_runs.py
git commit -m "feat(platform): record what every worker did in every scan"
```

---

### Task 8: The participation endpoint

**Files:**
- Create: `b_hunters/platform/api/routers/assets.py`
- Modify: `b_hunters/platform/api/app.py`
- Test: `tests/integration/test_participation.py`

**Interfaces:**
- Consumes: `WorkerRunRepository`, the scanner registry, the worker output.
- Produces: `GET /api/v1/scans/{scan_id}/participation` →
  `{"workers": [...], "native_adapters": [...], "coverage": {"workers": {...}, "native_adapters": {...}}, "health": {...}}`.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_participation.py`:

```python
def test_the_participation_table_accounts_for_every_worker(client, csrf, services):
    scan_id = _scan(client, csrf)
    response = client.get(f"/api/v1/scans/{scan_id}/participation", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["workers"]) == 17
    assert payload["coverage"]["workers"]["total"] == 17
    assert payload["native_adapters"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_participation.py -q`

Expected: FAIL — the endpoint does not exist (404).

- [ ] **Step 3: Implement the router**

`b_hunters/platform/api/routers/assets.py`:

- `GET /{scan_id}/participation` — builds the worker rows from `platform_worker_runs`, defaulting to "not connected" for a worker with no row, and the reason per the design §6.1 table. The native adapter rows come from the scanner registry specs and the scan's recorded adapter outcomes.
- The coverage line counts both sections.
- The health line carries the online identities and each worker's expected version.

Register the router in `b_hunters/platform/api/app.py` with the prefix `settings.api_prefix`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_participation.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/api/routers/assets.py b_hunters/platform/api/app.py tests/integration/test_participation.py
git commit -m "feat(platform): report which tools took part in a scan"
```

---

### Task 9: Stop reasons and the enforced deadline

**Files:**
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Modify: `b_hunters/platform/agents/runtime.py`
- Test: `tests/integration/test_stop_reasons.py`

**Interfaces:**
- Consumes: the existing task status and the scan's duration.
- Produces:
  - Every task result carries a `stop_reason`: `completed`, `budget_exhausted`, `wall_clock`, `cancelled` or `failed`.
  - The runtime sets `run.status = "wall_clock"` when the per-task wall clock expires (today it becomes `failed` with an empty error).
  - The orchestrator enforces the scan deadline: tasks that have not started when the deadline passes are marked `wall_clock` and never run; in-flight tasks are cancelled and marked `wall_clock`.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_stop_reasons.py`:

```python
def test_a_role_that_never_started_is_recorded_as_wall_clock(services, orchestrator_parts):
    orchestrator, provider, services = orchestrator_parts
    scan = services.scans.create({...})
    provider.script = [_conclusion("done")]
    context = _context(services, scan_id=scan.scan_id)
    context.profile.agent_roles = ["recon", "api"]
    context.max_duration_seconds = 30
    # Make the deadline already past.
    services.scans.update(scan.scan_id, {"deadline_at": time.time() - 1})
    await orchestrator.run(context)
    tasks = {t["task_id"]: t for t in services.tasks.list_for_scan(scan.scan_id)}
    for task in tasks.values():
        assert task["status"] == "wall_clock"
        assert task["result"]["stop_reason"] == "wall_clock"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_stop_reasons.py -q`

Expected: FAIL — there is no deadline and no `stop_reason`.

- [ ] **Step 3: Implement the deadline and the stop reason**

In `b_hunters/platform/agents/runtime.py`:

- The wall-clock timeout sets `run.status = "wall_clock"` and `run.error = "the task ran out of its wall clock"`.
- `AgentRun.to_dict()` gains a `stop_reason` field, derived from the status: `succeeded` → `completed`, `budget_exhausted` → `budget_exhausted`, `wall_clock` → `wall_clock`, `cancelled` → `cancelled`, `failed` → `failed`.

In `b_hunters/platform/agents/orchestrator.py`:

- `run()` computes `deadline = time.monotonic() + context.max_duration_seconds` and stores it on the scan as `deadline_at` (an epoch timestamp) when the scan starts, so a resume can see it.
- `_run_agent_tasks` checks the deadline before each batch. When it has passed, every task that has not started is marked `wall_clock` with the result `{"stop_reason": "wall_clock"}`, and the loop ends.
- A task that is cancelled mid-flight is marked `wall_clock` when the deadline caused it.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_stop_reasons.py tests/integration/test_scan_lifecycle.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/agents/orchestrator.py b_hunters/platform/agents/runtime.py tests/integration/test_stop_reasons.py
git commit -m "feat(platform): record why an agent stopped"
```

---

### Task 10: The per-role agent report

**Files:**
- Modify: `b_hunters/platform/api/routers/assets.py`
- Test: `tests/integration/test_agent_report.py`

**Interfaces:**
- Consumes: the task documents and their results.
- Produces: `GET /api/v1/scans/{scan_id}/agents/report` → `{"roles": [{"role", "tasks", "status", "stop_reason", "rounds", "tool_calls", "tokens", "findings_raised", "findings_confirmed", "conclusion"}], "stop_reasons": {"completed": n, ...}, "built_in_roles": 13, "planned_roles": n}`.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_agent_report.py`:

```python
def test_the_agent_report_names_every_planned_role(client, csrf, services):
    scan_id = _scan(client, csrf)
    response = client.get(f"/api/v1/scans/{scan_id}/agents/report", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    payload = response.json()
    assert payload["built_in_roles"] == 13
    assert payload["roles"]
    assert "stop_reasons" in payload
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_agent_report.py -q`

Expected: FAIL — the endpoint does not exist.

- [ ] **Step 3: Implement the endpoint**

`GET /{scan_id}/agents/report` in `b_hunters/platform/api/routers/assets.py`:

- Reads the scan's task documents of kind `agent`, groups them by `agent_role`, and builds one row per role from the task result: `status`, `stop_reason`, `rounds`, `tool_calls`, `tokens`, the findings it raised (counted from `platform_findings` with that role in `detected_by`) and the findings that were confirmed.
- `conclusion` is the role's conclusion from the task result, truncated to 400 characters.
- `built_in_roles` is the number of roles in `builtin_roles()`; `planned_roles` is the number of rows.
- `stop_reasons` counts the rows by stop reason.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_agent_report.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/api/routers/assets.py tests/integration/test_agent_report.py
git commit -m "feat(platform): report the outcome of every agent role"
```

---

### Task 11: The full tool output and the transcript endpoint

**Files:**
- Modify: `b_hunters/platform/tools/gateway.py`
- Modify: `b_hunters/platform/db/repositories.py` (`ToolCallRepository.record`)
- Modify: `b_hunters/platform/api/routers/assets.py`
- Test: `tests/integration/test_transcript.py`

**Interfaces:**
- Consumes: the rendered tool output; the messages and the tool calls.
- Produces:
  - `platform_tool_calls` gains `output` (the full rendered text, at most 512 KB), `output_truncated` (bool) and `output_bytes` (int). The 2000-character `output_summary` is kept.
  - `GET /api/v1/scans/{scan_id}/transcript?role=&task_id=&cursor=&limit=` → `{"messages": [...], "tool_calls": [...], "next_cursor": str, "truncated": bool}` — chronological, at most 200 items and 2 MB per page.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_transcript.py`:

```python
def test_the_transcript_is_chronological_and_paginated(client, csrf, services):
    scan_id = _scan(client, csrf)
    _messages(services, scan_id, count=5)
    _tool_calls(services, scan_id, count=5)
    response = client.get(f"/api/v1/scans/{scan_id}/transcript?limit=3", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["messages"]) + len(payload["tool_calls"]) == 3
    assert payload["next_cursor"]


def test_a_failed_tool_call_insert_is_reported(services):
    class BrokenCollection:
        def insert_one(self, document):
            raise RuntimeError("document too large")

    services.db.collection = lambda name: BrokenCollection()
    services.tool_calls.record({"scan_id": "s1", "tool": "http_request"})
    # The failure must be visible, not silent.
```

The second test asserts that a failed insert returns `False` rather than raising into the audit hook, and that the orchestrator emits a `tool.record_failed` event.

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_transcript.py -q`

Expected: FAIL — the endpoint does not exist and `record` returns nothing.

- [ ] **Step 3: Implement the storage and the endpoint**

In `b_hunters/platform/tools/gateway.py`:

- The record gains `output` (the rendered output, cut at 512 KB), `output_truncated` and `output_bytes`. The 2000-character `output_summary` is unchanged.

In `b_hunters/platform/db/repositories.py`:

- `ToolCallRepository.record` returns `bool` — `True` when the document was written, `False` when the write failed. The insert is wrapped in a `try` that catches `PyMongoError` and returns `False`.

In `b_hunters/platform/agents/orchestrator.py`:

- `_audit_tool_call` checks the return value; when the write failed it emits the scan event `tool.record_failed` with the tool name and the error, so a tool that could not record itself is visible.

In `b_hunters/platform/api/routers/assets.py`:

- `GET /{scan_id}/transcript` merges the messages and the tool calls of the scan — or of one role or task — into one chronological stream, page by page, with a cursor. The tool calls are sorted ascending by `at` (the repository sorts them descending today, so the endpoint must reverse them), and the row limits are raised above 1000.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_transcript.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/tools/gateway.py b_hunters/platform/db/repositories.py b_hunters/platform/agents/orchestrator.py b_hunters/platform/api/routers/assets.py tests/integration/test_transcript.py
git commit -m "feat(platform): keep the full tool output and serve the transcript"
```

---

### Task 12: The error ledger and the integrity verdict

**Files:**
- Create: `b_hunters/platform/errors.py`
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Modify: `b_hunters/platform/api/routers/assets.py`
- Test: `tests/unit/test_error_ledger.py`, `tests/integration/test_integrity.py`

**Interfaces:**
- Consumes: the tool call records, the scan events and the task results.
- Produces:
  - `b_hunters.platform.errors.classify_error(text: str, status: str = "") -> str` — one of `http_status`, `connection`, `timeout`, `dns`, `scope`, `permission`, `unknown_tool`, `budget`, `crash`, `unexplained`.
  - `b_hunters.platform.errors.ErrorLedger` with `add(source: str, detail: str, status: str = "") -> None`, `counts() -> dict[str, int]` and `verdict() -> dict[str, Any]` — `{"unexplained": n, "by_class": {...}, "verdict": "pass" | "fail"}`.
  - `GET /api/v1/scans/{scan_id}/integrity` → the ledger and the verdict.
  - The scan record gains `integrity` at completion.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_error_ledger.py`:

```python
def test_an_expected_failure_is_explained():
    assert classify_error("HTTP 404 Not Found", status="error") == "http_status"
    assert classify_error("Connection refused") == "connection"
    assert classify_error("the request timed out") == "timeout"
    assert classify_error("the host could not be resolved") == "dns"


def test_an_unhandled_exception_is_unexplained():
    assert classify_error("RuntimeError: object has no attribute 'x'") == "unexplained"


def test_the_verdict_fails_only_on_an_unexplained_error():
    ledger = ErrorLedger()
    ledger.add("tool_call", "HTTP 404 Not Found")
    assert ledger.verdict()["verdict"] == "pass"
    ledger.add("tool_call", "RuntimeError: object has no attribute 'x'")
    assert ledger.verdict()["verdict"] == "fail"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_error_ledger.py -q`

Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Implement the ledger**

`b_hunters/platform/errors.py`:

- `classify_error(text, status)` matches, in order: a 404/500-shaped HTTP status → `http_status`; "connection refused", "connection reset" → `connection`; "timed out", "timeout" → `timeout`; "could not be resolved", "name or service not known" → `dns`; "out of scope", "not authorised", "scope" → `scope`; "permission" → `permission`; "unknown tool" → `unknown_tool`; "budget", "exhausted" → `budget`; a traceback or an exception class name → `crash`; an empty or unrecognised text → `unexplained`.
- `ErrorLedger` keeps a list of `(source, detail, class)` and computes the verdict: `pass` when no entry is `unexplained` or `crash`.

In `b_hunters/platform/agents/orchestrator.py`:

- The orchestrator feeds every tool call error and every task failure into a ledger, and at the end of the scan writes `integrity` onto the scan record.

In `b_hunters/platform/api/routers/assets.py`:

- `GET /{scan_id}/integrity` recomputes the ledger from the stored records and returns it, so the verdict can be read after the scan and re-checked later.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_error_ledger.py -q` and `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_integrity.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/errors.py b_hunters/platform/agents/orchestrator.py b_hunters/platform/api/routers/assets.py tests/unit/test_error_ledger.py tests/integration/test_integrity.py
git commit -m "feat(platform): tell an explained failure from an unexplained one"
```

---

### Task 13: The extended report

**Files:**
- Modify: `b_hunters/platform/api/routers/findings.py`
- Test: `tests/integration/test_report.py`

**Interfaces:**
- Consumes: the asset inventory, the participation rows, the agent report and the integrity verdict.
- Produces: the existing `GET /api/v1/scans/{scan_id}/report?format=json|html|sarif` gains the asset table, the participation table, the per-role table and the transcript appendix in HTML and JSON. SARIF is unchanged.

- [ ] **Step 1: Write the failing test**

`tests/integration/test_report.py`:

```python
def test_the_html_report_carries_the_assets_and_the_participation(client, csrf, services):
    scan_id = _scan(client, csrf)
    services.assets.upsert(scan_id=scan_id, url="https://demo.test/app.js", kind="js", source="asset_crawl")
    response = client.get(f"/api/v1/scans/{scan_id}/report?format=html", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert "app.js" in response.text
    assert "participation" in response.text.lower()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_report.py -q`

Expected: FAIL — the report has no asset table.

- [ ] **Step 3: Extend the report**

In `b_hunters/platform/api/routers/findings.py`:

- `_to_html` gains four sections: the asset table, the participation table, the per-role table with the stop reasons, and the transcript appendix.
- The transcript appendix embeds up to 2 MB of transcript text per scan and states how much was omitted, with the transcript endpoint named.
- The JSON export gains `assets`, `participation`, `agents` and `integrity`.
- `_to_sarif` is unchanged.

- [ ] **Step 4: Run the test to verify it passes**

Run: `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" /home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_report.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/api/routers/findings.py tests/integration/test_report.py
git commit -m "feat(platform): report the assets, the tools and the agents"
```

---

### Task 14: The three asset tabs in the console

**Files:**
- Create: `b_hunters/web/js/views/assets.js`
- Modify: `b_hunters/web/app.js`
- Modify: `b_hunters/web/index.html` (only if the tab markup lives there)

**Interfaces:**
- Consumes: `GET /api/v1/scans/{scan_id}/assets`.
- Produces: three scan tabs — **URLs**, **JS**, **Images** — rendering one table: kind, scope, URL, status, content type, size, sources, depth, discovered from. The URLs tab has a type filter and a first-party/external toggle; the JS tab filters to `js` and defaults to first-party only; the Images tab filters to `image`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_console_assets.py` — the console has no test harness yet; add a Node test for the pure rendering function:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderAssetTable, filterAssets } from '../../b_hunters/web/js/views/assets.js';

test('the asset table shows every column', () => {
  const html = renderAssetTable([{ kind: 'js', scope: 'first_party', url: 'https://demo.test/app.js', status_code: 200, content_type: 'application/javascript', size_bytes: 12, sources: ['asset_crawl'], depth: 1, discovered_from: 'https://demo.test/' }]);
  assert.match(html, /app\.js/);
  assert.match(html, /first_party/);
  assert.match(html, /application\/javascript/);
});

test('the javascript view keeps only the javascript assets', () => {
  const assets = [{ kind: 'js', url: 'a' }, { kind: 'image', url: 'b' }];
  assert.equal(filterAssets(assets, { kind: 'js' }).length, 1);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test tests/unit/test_console_assets.test.js`

Expected: FAIL — the module does not exist.

- [ ] **Step 3: Implement the view**

`b_hunters/web/js/views/assets.js`:

- `filterAssets(assets, { kind, scope })` — pure.
- `renderAssetTable(assets)` — pure, returns HTML; it escapes every value with the console's `escape` helper (import it from `../../format.js`, or move `escape` into `b_hunters/web/js/format.js` if it does not exist there yet — the console is one file today, so create `js/format.js` with `escape` and `fmtTime` and have `app.js` import them).
- The module exports a `renderAssetsTab(tab, scanId)` that fetches `/api/v1/scans/{id}/assets?limit=2000` and renders the table with the filters.

In `b_hunters/web/app.js`: add the three tabs to the tab markup, add the three cases to `renderScanTab`, and import the module.

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test tests/unit/test_console_assets.test.js`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/web/js/views/assets.js b_hunters/web/app.js b_hunters/web/index.html tests/unit/test_console_assets.test.js
git commit -m "feat(console): show the URLs, the JavaScript and the images"
```

---

### Task 15: Participation, per-role outcomes and the transcript pane

**Files:**
- Create: `b_hunters/web/js/views/participation.js`
- Create: `b_hunters/web/js/views/transcript.js`
- Modify: `b_hunters/web/app.js`
- Test: `tests/unit/test_console_participation.test.js`

**Interfaces:**
- Consumes: `GET /api/v1/scans/{scan_id}/participation`, `GET /api/v1/scans/{scan_id}/agents/report`, `GET /api/v1/scans/{scan_id}/transcript`.
- Produces: the Scanners tab gains the participation table and the coverage line; the Agents tab gains the per-role table with the stop reason and a transcript button that opens a pane fetching the transcript page by page; the Findings tab gains a detected-by filter.

- [ ] **Step 1: Write the failing test**

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderParticipation, renderRoleTable } from '../../b_hunters/web/js/views/participation.js';

test('the participation table names the reason a tool did not report', () => {
  const html = renderParticipation({ workers: [{ worker: 'B-Hunters-Nuclei', participated: false, reason: 'never dispatched', tasks: 0, findings: 0 }] });
  assert.match(html, /never dispatched/);
});

test('the role table shows the stop reason', () => {
  const html = renderRoleTable([{ role: 'recon', status: 'wall_clock', stop_reason: 'wall_clock', tokens: 1200 }]);
  assert.match(html, /wall_clock/);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test tests/unit/test_console_participation.test.js`

Expected: FAIL — the module does not exist.

- [ ] **Step 3: Implement the views**

`b_hunters/web/js/views/participation.js` exports the two pure renderers; `b_hunters/web/js/views/transcript.js` exports `renderTranscript(messages, toolCalls)` and `renderTranscriptPane(scanId, role)` which fetches the transcript page by page and appends it.

In `b_hunters/web/app.js`: the Scanners tab renders the participation table above the existing worker output; the Agents tab renders the role table with a transcript button per role; the Findings tab gets a detected-by filter that adds `detected_by` to the findings query.

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test tests/unit/test_console_participation.test.js`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/web/js/views/participation.js b_hunters/web/js/views/transcript.js b_hunters/web/app.js tests/unit/test_console_participation.test.js
git commit -m "feat(console): show the participation, the stop reasons and the transcripts"
```

---

### Task 16: The verification run

**Files:**
- Create: `docs/verification.md`
- Modify: `/home/sniper/pentest/STATUS.md`

**Interfaces:**
- Consumes: the platform, the runner and the three labs.
- Produces: the measured evidence in `docs/verification.md`.

- [ ] **Step 1: Run the three scans**

For each of DVGA, Juice Shop and WebGoat, create a scan through the API with `max_duration_seconds: 900`, the standard scanner list plus `asset_crawl`, every planned agent role, and the independent verifier enabled. Start it and let the runner execute it.

```bash
curl -sS -X POST http://bhunter/api/v1/scans -H 'Content-Type: application/json' -b cookies.txt -H "X-CSRF-Token: $CSRF" -d '{...}'
curl -sS -X POST http://bhunter/api/v1/scans/$SCAN_ID/start -b cookies.txt -H "X-CSRF-Token: $CSRF"
```

- [ ] **Step 2: Check the pass criteria**

For each scan, read `GET /api/v1/scans/{id}/participation`, `GET /api/v1/scans/{id}/agents/report` and `GET /api/v1/scans/{id}/integrity` and confirm:

* every one of the seventeen workers appears with a reason when it did not take part;
* every native adapter appears;
* every planned role appears with a status and a stop reason;
* the integrity verdict reports no unexplained error.

Record the actual result, including anything that failed, in `docs/verification.md`.

- [ ] **Step 3: Write the verification document**

`docs/verification.md` records, per lab: the scan id, the duration, the assets by kind, the findings by severity and by detector, the participation table, the stop-reason counts, the integrity verdict, and the pass criteria outcome. Every number is the output of a command or an API call you ran.

- [ ] **Step 4: Commit**

```bash
git add docs/verification.md
git commit -m "docs: record the verification run"
```

---

### Task 17: The documentation set

**Files:**
- Create: `docs/assets.md`, `docs/console.md`
- Modify: `README.md`, `docs/implementation-report.md`, `docs/architecture-audit.md`, `/home/sniper/pentest/STATUS.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the documentation the operator asked to be saved.

- [ ] **Step 1: Write `docs/assets.md`**

How the inventory is built: the adapter, the merge, the three sources, the classification rules, the limits, the collection and its indexes, the API, and how an agent lists the assets.

- [ ] **Step 2: Write `docs/console.md`**

The tab structure of a scan, what each tab shows, the filters, the participation reasons and the stop reasons.

- [ ] **Step 3: Update the status documents**

In `README.md`, `docs/implementation-report.md`, `docs/architecture-audit.md` and `/home/sniper/pentest/STATUS.md`: record what landed, the measured test count, the verification results, and the new API and settings. Every number is a command output.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/implementation-report.md docs/architecture-audit.md docs/assets.md docs/console.md
git commit -m "docs: describe the asset inventory and the console"
```
