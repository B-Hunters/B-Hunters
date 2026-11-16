# Scanner handoff integrity — design

**Date:** 2026-11-16
**Status:** ready to implement
**Covers:** A1–A4 of `2026-11-16-rebaseline-design.md`
**Plan:** `../plans/2026-11-16-scanner-handoff-integrity.md`

---

## 1. The problem

The platform's benchmark scores it against known-vulnerable applications.
Four cases are genuinely missed, and they share two causes.

### A1 — the three path scanners have produced nothing since mid-October

`sqlmap`, `dalfox` and `ssti` consume the `paths`/`scan` task and download the
URL list from the object store. The list is written as a **raw S3 object**:

```python
# B-Hunters-Katana/katanam/katanam.py:101
self.backend.upload_object("bhunters", "katana_" + scan_id + "_" + encoded, body)
```

The Karton router's garbage collector deletes every object in that bucket that
no registered task references, every three minutes:

```python
# Karton v5.5.0, karton/system/system.py
def gc_collect_resources(self) -> None:
    karton_bucket = self.backend.default_bucket_name
    resources_to_remove = set(self.backend.list_objects(karton_bucket))
    for task in self.backend.iter_all_tasks():
        for resource in task.iterate_resources():
            if resource.bucket == karton_bucket and resource.uid in resources_to_remove:
                resources_to_remove.remove(resource.uid)
    if resources_to_remove:
        self.backend.remove_objects(karton_bucket, resources_to_remove)
```

A raw write is referenced by nobody, so the collector takes it. Verified
against the running stack: the `bhunters` bucket holds **0 objects**.

The two workers that still report — `nuclei` and `wapiti` — scan the target
directly and never read the list. `ffuf` builds its own inventory and does
not read it either. Everything that depends on the list produces nothing.

### A2 — a single-page application's API is never tested

The crawler follows links. A SPA's REST routes are not links: they are in the
JavaScript bundle. The crawler's list for the laboratory holds 67 links, and
the scanners' own filter reduces it to **one** URL:

```
http://172.25.0.13:3000/socket.io/?EIO=FUZZ&sid=FUZZ&t=FUZZ&transport=FUZZ
```

The `GET /rest/products/search?q=` endpoint — the one with the SQL injection —
is in the bundle, and nothing hands the bundle's routes to the scanners.

### A3 — the bundle's API surface is never a finding

The `javascript` role runs, reads the bundle, and raises a *note* about
Angular template interpolation. The API routes it recovered are never
converted into a finding of class `api_discovery` or `javascript_analysis`.

### A4 — two classes of evidence never become findings

* `information_disclosure` **is** produced — "Additional unauthenticated
  static/served paths" — but the finding does not carry the evidence the
  benchmark looks for (the names in the challenge catalogue).
* `route_discovery` is **never** produced, although the class exists in
  `vuln_classes.py` and the inventory holds the routes.

---

## 2. What is not changed

* **The collector stays on.** Disabling it, or raising its interval, would
  trade a systematic failure for a timing race and leak the bucket.
* **The workers are not rewritten.** `STATUS.md` §10: *"Extend the Karton
  workers; do not rewrite them."* The fix lives in the shared base class and
  in the platform.
* **The phase order stays.** `("workers", "agents", "verifying", "reporting",
  "completed")` — a phase that runs the scanners before the agents is correct;
  it is the *content* of the list that is wrong.
* **The finding taxonomy is unchanged.** `route_discovery`, `api_discovery`,
  `javascript_analysis` and `information_disclosure` all exist already.

---

## 3. The design

### 3.1 A1 — the artefact becomes a tracked Karton resource

Karton keeps an object alive for exactly as long as a registered task
references it, and removes it when the last such task finishes. The
collector's own code says so: it keeps every `resource.uid` that appears in
`task.iterate_resources()`.

So the path list must be **a resource of the task that publishes it**, not a
raw object.

**New helper in the shared base class** — `b_hunters/bhunter.py`:

```python
def publish_task_with_artifact(self, task, bucket, key, body):
    """Publish a task that carries the artefact its consumers will read.

    A raw write to the object store is referenced by no task, and the
    Karton collector removes every such object.  A task that carries the
    artefact as a resource keeps it alive for the life of the task and
    releases it when the last consumer is done.
    """
    self.backend.upload_object(bucket, key, body)
    resource = RemoteResource(name=key, bucket=bucket, uid=key)
    task.add_resource("artifact", resource, persistent=True)
    self.send_task(task)
```

`RemoteResource(name, bucket, uid)` is the constructor in Karton v5.5.0
(`karton/core/resource.py:364`). `uid` is the S3 key, so the collector
recognises the object by the key it already uses, and the workers keep
downloading by the same key — no worker-side change to the download path.

`persistent=True` puts the resource in the task's persistent payload, so it
is inherited by every task in the subtree and survives the fork the router
makes for each consumer.

**Two call sites change:**

| Where | Change |
|------|--------|
| `B-Hunters-Katana/katanam/katanam.py` | the `paths`/`scan` task is published through the helper, with the list it just uploaded |
| `b_hunters/platform/bench/workers.py` | `_upload_paths` publishes through the helper instead of writing with a bare boto3 client |

**Why the workers that read the list need no change.** They download by raw
key (`sqlmapm.py:145`, `dalfox`, `sstichecker`). The key is unchanged; only
the *lifetime* of the object changes. The download keeps working — it simply
finds an object that is still there.

**The lifecycle becomes correct:**

```
upload ──▶ task published ──▶ router forks it to 4 consumers
                                  │
                    each consumer's task holds the resource
                                  │
                  collector sees the reference, keeps the object
                                  │
             last consumer finishes ──▶ task deleted ──▶ object deleted
```

### 3.2 A2 — the platform publishes the list the scanners should use

The crawler publishes a `paths`/`scan` task with the links *it* found. That
list is incomplete by construction.

The platform already reads the crawler's output — it writes `links` documents
keyed by `report_id` and `source` — and it already collects a merged asset
inventory. So the platform can compose the list the scanners ought to have:

```
final list = crawled links
           ∪ routes extracted from the JavaScript bundles
           ∪ routes recovered by the javascript and api roles
```

and publish its own `paths`/`scan` task with it, under `source="platform"`.

The key convention is fixed by the workers: they compute
`f"{source}_{scan_id}_{encode_filename(url)}"`. The platform uses the same
convention, so the scanners find the object without knowing who wrote it.

**Two publications, because the routes arrive at two different times:**

| Publication | When | List |
|-------------|------|------|
| **P1 — worker phase** | after the crawler finishes, before the agents | crawled links ∪ routes extracted from the bundles by the asset crawl |
| **P2 — agents phase** | after the `javascript` and `api` roles finish | P1's list ∪ the routes the roles recovered |

P2 is the one that closes the Juice Shop miss, because the SQL injection is
in a route only the JavaScript bundle names.

**The routes must carry their parameters.** The scanners filter the list with
`grep "=" | uro --filter hasparams | qsreplace FUZZ`. A route without a
parameter is dropped by `uro`. So the platform must write the route **with
its query parameters** — `GET /rest/products/search?q=` — not just its path.
The `javascript` role recovers parameter names, and the static extractor
recovers them from the bundle.

### 3.3 A3 — the recovered routes become findings

The `javascript` role already returns routes. Today they die in the
transcript. The platform needs to lift them into findings:

* a route recovered from a bundle becomes a finding of class
  `api_discovery`, with the bundle it came from as the evidence;
* the bundle's own findings keep class `javascript_analysis`.

The agent finding schema already carries `vuln_class`, `title`, `summary`,
`host` and `path`. The lift is a matter of reading the role's findings —
they are already stored — and adding the *routes* the role reported as
`api_discovery` findings with the route as the path.

### 3.4 A4 — the two missing finding classes

| Class | What must produce it | Evidence it carries |
|-------|---------------------|---------------------|
| `route_discovery` | every route in the merged inventory | the route, the method if known, and the host |
| `information_disclosure` | a body whose content is sensitive | **the matched content**, redacted |

The second is the sharper one. The platform already reports "Additional
unauthenticated static/served paths" as an information disclosure, and the
benchmark cannot see the challenge names because the finding does not carry
them. The rule becomes: *an information-disclosure finding that names
content in its body must quote that content in its evidence.*

The redaction rule already exists — `platform/security/redact.py` — and
applies before the content is stored.

---

## 4. Interfaces

New and changed, in the order a task depends on them:

| Symbol | Where | Signature |
|--------|-------|-----------|
| `BHunters.publish_task_with_artifact` | `b_hunters/bhunter.py` | `(self, task: Task, bucket: str, key: str, body: bytes) -> None` |
| `BHunters.artifact_key` | `b_hunters/bhunter.py` | `(self, source: str, scan_id: str, target: str) -> str` — the key the workers compute |
| `PlatformPathList` | `b_hunters/platform/scanners/path_list.py` (new) | `compose(links, routes) -> list[str]`; `publish(producer, scan_id, target, urls) -> None` |
| `RouteExtractor` | `b_hunters/platform/scanners/routes.py` (new) | `extract(bundle_text: str) -> list[Route]` |
| `Route` | same module | `path: str`, `method: str | None`, `parameters: tuple[str, ...]` |
| `FindingRepository.upsert` (existing) | `platform/db/repositories.py` | unchanged — reused |

`artifact_key` must reproduce exactly what the workers compute:

```python
# what the worker does
key = f"{source}_{scan_id}_{re.sub(r'[<>:\"/\\\\|?*]', '_', url)}"
```

The workers use `self.encode_filename(url)` where `url` has had its scheme
and trailing slash removed. The platform must apply the same normalisation,
or the object will be written under a key the workers do not look for.

---

## 5. Acceptance criteria

| # | Criterion | How it is checked |
|---|-----------|-------------------|
| 1 | The path list survives the collector for the life of the scan | A test reproduces the collector's own logic against a published task and asserts the object is kept; a second test asserts it is removed once the task is gone |
| 2 | The scanners find the list | The key the platform writes equals the key the scanners compute — asserted against the workers' own source |
| 3 | A route recovered from a bundle reaches a scanner | An end-to-end test publishes the task and asserts the list contains `…/rest/products/search?q=` |
| 4 | The bundle's API surface becomes a finding | A test asserts an `api_discovery` finding exists with the route as its path |
| 5 | Every route in the inventory becomes a `route_discovery` finding | A test asserts the count matches the inventory |
| 6 | An information disclosure carries its evidence | A test asserts the finding's evidence contains the matched content, redacted |
| 7 | Nothing regresses | The full suite stays green; `tests/integration/test_worker_contracts.py` still passes |

---

## 6. Risks

| Risk | Mitigation |
|------|-----------|
| The platform publishes a second `paths`/`scan` task and the scanners run twice | The scanners are idempotent — they upsert by `report_id` and URL. The benchmark already shows duplicated findings are a separate concern (fixed by the class normalisation). The cost is scan time, which the phase budget bounds. |
| The key normalisation drifts from the workers' | `artifact_key` is tested against the workers' own source text, and the contract test reads the worker repositories — so a drift in the worker fails the suite rather than the scan |
| The object is now kept alive for a long scan | The object is a list of URLs, measured in kilobytes; and it is released when the last consumer finishes |
| The collector deletes the object between the platform's upload and the router's fork | The resource is attached to the task *before* `send_task`, and `send_task` registers the task before the object is visible to the collector — the same ordering Karton itself relies on |

---

## 7. What this does not do

* It does not make the two unmeasured applications measurable — that is an
  image-availability problem (D2).
* It does not change the finding taxonomy, the phase order, or the worker's
  download convention.
* It does not retire the crawler's own `paths`/`scan` publication. The
  crawler's list is still uploaded and still consumed; the platform's
  publications add to it.
