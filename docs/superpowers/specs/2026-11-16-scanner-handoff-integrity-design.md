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

`sqlmap`, `dalfox` and `ssti` consume the `paths`/`scan` task and filter the
crawler's list down to the URLs that carry a parameter:

```python
# B-Hunters-DalFox/dalfox/dalfox.py:41-57
p3 = subprocess.Popen(["grep", "-v", "png|jpg|css|js|gif|txt"], ...)
p4 = subprocess.Popen(["grep", "="], ...)
p5 = subprocess.Popen(["uro", "--filter", "hasparams"], ...)
p6 = subprocess.Popen(["qsreplace", "FUZZ"], ...)
newlinks = self.checklinksexist(self.subdomain, [...])
if newlinks == []:
    return [], []          # ← nothing to test: the scanner exits, successfully
```

For the laboratory the filter leaves **nothing**. The crawler's haul is
fifteen URLs, and not one of them carries a parameter:

```
172.25.0.14:8080/WebGoat    crawled=15   with_params=0
```

The seven links in the `links` document are four style sheets and three
paths — `/WebGoat/registration`, `/WebGoat/login`, `/WebGoat/start.mvc` —
and none of them contains a `=`.

The scanner therefore exits in eighty-three milliseconds, **successfully**:

```
[2026-11-02 03:54:17,426] Starting processing new url
[2026-11-02 03:54:17,426] [WARNING] katana 172.25.0.13:3000
[2026-11-02 03:54:17,509] Task done
```

And the platform reports it as *"ran, found nothing"* — a false clean bill
of health for work that never happened.

### A1a — the garbage collector is not the cause

This was the first hypothesis and it is wrong, so it is recorded here to
save the next reader the detour.

* The crawler already publishes the list as a Karton `LocalResource`
  (`katanam.py:144`), so the collector keeps it for the life of the scan.
* All three scanners already fall back to the database when the object
  store copy has gone (`sqlmapm.py:166`, `dalfox.py:103`,
  `sstichecker.py:63`).
* An empty bucket after a scan has finished is the **correct** steady
  state.

The bucket that was observed empty was the **older** `bh-*` stack's: the
current platform's object store publishes no host port and is reachable
only on the `bhunter` network.

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

### 3.1 A1 — the platform must say a scanner had nothing to test

The platform already knows the answer and does not use it.
`candidates()` counts the crawler's URLs that carry a parameter, and every
worker row in the participation table carries that count:

```python
# b_hunters/platform/scanners/worker_output.py:334
counts = candidates(database, report) if report else {...}
...
"candidates": counts["urls_with_parameters"],
```

What was missing is a reason that says what the count means. The table
has five reasons, and a path scanner that was handed nothing lands on
*"ran, found nothing"* — a false clean bill of health for work that never
happened.

**The fix is a sixth reason and the record that supports it.**

| Where | Change |
|------|--------|
| `platform/scanners/worker_output.py` | `PATH_SCANNERS` — the workers that test the candidate list; `_status()` takes the candidate count and the worker identity |
| `platform/db/assets.py` | `WorkerRunRepository.record()` takes `candidates` and stores it |
| `platform/agents/orchestrator.py` | `_record_worker_outcomes()` computes the count once and records it with every worker's outcome |
| `platform/api/routers/assets.py` | `_reason_for()` consults the count; the docstring documents the reason |

The reason is decided by the facts of the scan, not guessed when the table
is read — which is the rule the participation table already follows for
the other four reasons.

This is the same principle the platform already applies to the agent
roles: *"A role that was cut off looks like a role that found nothing"*
(`STATUS.md` §7 #15) was fixed by recording the stop reason. The
scanners had the same defect and the same remedy.

### 3.1b The platform's own path list is still an untracked write

The workers publish their list as a Karton `LocalResource`, which the
collector keeps for the life of the scan. The platform's benchmark harness
does not: it writes with a bare boto3 client.

```python
# b_hunters/platform/bench/workers.py:518
client.put_object(Bucket=self.s3_bucket, Key=key, Body=body)
```

That object is referenced by no task, so the collector removes it. It is
not the cause of A1 — the scanners fall back to the database — but it is
the same mistake in one place, and the benchmark harness is the place
where a *new* scanner is exercised first.

**The fix** is a shared mechanism, `b_hunters/artifacts.py`, with the key
convention and the attachment in one place, and a base-class method that
uses it. `b_hunters/artifacts.py` reproduces the worker's `encode_filename`
exactly — including the shortening of a very long name — and a test
asserts the two agree, because a producer that names an artefact
differently writes to a key the consumer never reads.

### 3.1c The workers that read the list need no change

They download by raw key (`sqlmapm.py:166`, `dalfox.py:113`,
`sstichecker.py:73`) and fall back to the database when the object store
copy has gone. The key is unchanged; only the lifetime of the object
changes.

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
