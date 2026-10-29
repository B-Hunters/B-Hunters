# Design: asset collection and complete reporting

Date: 2026-10-29
Status: draft for approval
Companion to: `docs/superpowers/specs/2026-10-29-single-operator-platform-design.md`
Plan to follow: `docs/superpowers/plans/2026-10-29-durable-foundation.md` (Phase 0–1, already approved)

## 1. Intent

The platform finds findings and then drops most of what it learned. A
scan of WebGoat persists 15 URLs, 7 paths, 123 worker findings, 1
technology and 22 screenshots — and no JavaScript URLs and no images at
all, because nothing collects them. The agents have a tool called
`list_assets` that always returns zero. The console shows a flat list of
findings with no way to ask "what did the JS files say" or "which images
does this site serve", and no way to see whether every tool took part in
the scan or was quietly cut off.

The operator's requirement is blunt: **collect the URLs, the JS URLs,
the images and the rest of the surface; show everything in the console;
prove that every tool and every agent reported; and write it all down.**

The second requirement is the harder one. "Everything is reported" is
not a display problem. It means the platform must distinguish a tool
that ran and found nothing from a tool that was cut off, and the report
must not claim a clean bill of health for a scan that never finished.

## 2. Measured current state

From the live MongoDB of the running stack:

| Fact | Value |
|---|---|
| Worker output per scan | 15 `url`, 7 `path`, 123 `finding`, 1 `technology`, 22 `screenshot` |
| JavaScript URLs collected | 0 |
| Images collected | 0 |
| Tool calls recorded | 6098, output summaries capped at 2000 chars, 3.9 MB total, 643 bytes average |
| Tool call error rate per scan | 118–250 errors in 1104–1302 calls (15–21%) |
| Scan-level error events | 0 |
| Agent messages | 3107, average hypothesis ~1000 chars |
| `list_assets` tool result | always `{"count": 0, "assets": []}` — it reads `context.metadata["assets"]`, which nothing populates |
| Console scan tabs | Live activity, Task graph, Agents, Collaboration, Tool calls, Scanners, Services, Findings |
| Findings tab | shows the detecting tool (agent role or worker name) but offers no grouping or filter |
| Agent task status | `succeeded` / `budget_exhausted` / `failed` — already distinguishable, never surfaced |
| Built-in agent roles | 13 in `roles.py`; the standard profile plans 11 (10 hypothesis roles plus `adjudicator`); `orchestrator` is never planned, `verifier` is opt-in |
| Effective per-task wall clock | `min(role budget 900, settings 1800)` = 900 s — equal to the scan cap, not larger |
| Tool output ceiling | `ToolPermissions.max_output_bytes` = 512 KB; the `http_request` body is capped at 4 MB; MongoDB rejects a document over 16 MB |
| Worker liveness | `get_online_consumers()` returns identity → clients, but nothing uses it; `_connected_workers()` returns queue names, not identities |
| WebGoat lab health | "unhealthy" only because its healthcheck calls `curl`, which the image lacks; the app serves fine |
| Worker fleets | `bhunter_worker_*` (live, on the `bhunter` network) and `bh-worker-*` (leftover, on an isolated `dev` stack) — the latter does not compete |

## 3. Decisions taken

Everything in this section was decided in conversation with the
operator. The alternatives are recorded so the reasoning survives.

| Decision | Alternatives rejected | Why |
|---|---|---|
| **Collect assets with a new native `asset_crawl` adapter** | Classify existing worker output only; wait for the Phase 2a browser | Classifying alone cannot produce JS URLs or images — they do not exist anywhere. The browser is two phases away and would sit beside the adapter rather than replace it. |
| **Merge the adapter's crawl with the worker output into one inventory** | Adapter only; workers only | The workers found 15 URLs and the JS files; the crawl finds the rest. A merged row says which tools saw it, so a URL only the crawler found and a URL both found are distinguishable. |
| **Store assets in a new `platform_assets` collection** | Reuse `platform_worker_output` with a new kind; reuse `platform_services` | `platform_worker_output` is a flat "a worker produced this value" list with no status, size or content type, and it is replaced wholesale per scan. `platform_services` is per-URL fingerprinting. The inventory needs its own schema and its own dedup key. |
| **Three console tabs: URLs, JS, Images** | One Assets tab with a type filter; a separate Inventory page | The operator chose three tabs. The URLs tab is the **full inventory with a type filter**, so CSS, API endpoints and everything else still have a home; JS and Images are pre-filtered views of the same collection. The cross-scan Inventory page stays in Phase 3. |
| **Platform console only** | Also extend the Karton dashboard | The Karton dashboard (`dashboard/`) is a read-only view of worker output for the Karton side; maintaining the same view twice is how views drift. |
| **Report the full agent transcripts** | Summary only; console only | The operator chose full transcripts in both the console and the report. |
| **Store the full tool output, bounded by the gateway's existing 512 KB per-call limit** | Literally unbounded; the 8 MB scope limit | The 8 MB figure is the scope policy's per-*response* limit; the tool path already truncates what it renders to 512 KB, and the model never sees more. Storing more than the model saw would store something the platform never read. |
| **Verification passes when there are no *unexplained* errors** | Literally zero errors; platform errors only | 15–21% of tool calls fail in a normal scan — a 404, a refused connection, a timeout. A literal zero-error criterion fails every scan and reports a working platform as broken. "No unexplained errors" keeps the strictness that matters: nothing fails silently, every failure carries a reason, and an unexplained error fails the run. |
| **900 s per scan, worker phase gets 70% of it** | Unchanged 50/50 split; 900 s for the whole run | With the split unchanged the 17-container fleet is cut off mid-scan, and a worker cut off mid-scan is exactly the "did not report" outcome this workstream exists to eliminate. The 70% share is a setting, not a constant. |
| **All three labs, all scanner workers and every planned agent role** | One lab; scanners only | Each lab exercises a different tool class: DVGA breadth, Juice Shop an Angular SPA with real JS and images and a login, WebGoat authentication and access control. |

### 3.1 Resolutions of the builder check

An independent builder review of this document found ten places where a
wrong assumption would force rework. They are settled here.

1. **"Unexplained error" is defined, and the verdict is an artefact.**
   An error is *explained* when the platform can name its class: HTTP
   status failure, connection refused or reset, timeout, DNS failure,
   scope refusal, tool permission denial, unknown tool, budget
   exhaustion. An error is *unexplained* when it carries no
   classification — an unhandled exception, a traceback, a crash with no
   message, a tool that produced neither output nor error. The ledger
   reads the tool-call errors, the scanner errors, the worker errors and
   the agent task failures, classifies each one and counts the
   unexplained ones. The verdict is stored on the scan at completion
   (`integrity: {unexplained_errors, verdict, by_class}`) and served by
   `GET /api/v1/scans/{id}/integrity`.
2. **Participation reasons need facts that are not recorded today.**
   The worker phase must begin by snapshotting the online consumer
   identities (`get_online_consumers()`, whose Redis client name *is*
   the worker identity) and must persist the per-worker task and crash
   counts, which the Karton bridge currently discards. The snapshot and
   the per-worker counts are stored in a new `platform_worker_runs`
   collection, one row per scan and worker. "Not connected" is then a
   historical fact about the scan, not a live fact about the container
   when the report is read.
3. **The participation table covers the native adapters too.** The
   table has two sections: the seventeen Karton workers, and the
   platform's own native adapters (`asset_crawl`, `service_fingerprint`,
   `security_headers`, …). The coverage line counts both: "17 workers
   and 7 native adapters: 19 participated, 4 did not, 1 was not
   connected". The version column is the platform's **expected** version
   for a worker — the workers do not report one, and reading a real one
   would mean changing all seventeen worker repositories, which the
   companion design defers to Phase 2b. The label says "expected".
4. **The scan cap becomes an enforced deadline.** The orchestrator
   computes a deadline from `max_duration_seconds` and passes it into
   the agent phase. Before each batch it checks the deadline: tasks that
   have not started are marked `wall_clock` and never run; in-flight
   tasks are cancelled and marked `wall_clock`. The runtime records a
   wall-clock expiry as `status = "wall_clock"` instead of `failed` with
   an empty error, and every task result carries an explicit
   `stop_reason` (`completed`, `budget_exhausted`, `wall_clock`,
   `cancelled`, `failed`). Nothing is derived from an empty error
   string.
5. **The stored tool output is bounded at 512 KB** — the gateway's
   existing per-call output limit, not the 8 MB scope figure. The
   2000-character `output_summary` is **kept alongside** the full
   output rather than replaced: the summary is what the console lists,
   the full text is what the transcript shows. When the rendered output
   exceeds 512 KB the stored text is cut at 512 KB and the row records
   `output_truncated: true` and the true byte count — never a silent
   loss. A failed insert is not silent either: `ToolCallRepository.record`
   returns whether the write succeeded, and a failure emits a
   `tool.record_failed` scan event, so a tool that could not record
   itself is visible rather than absent.
6. **The PDF is not part of this workstream.** There is no Playwright
   dependency, no PDF route and no browser in the repository today;
   Playwright arrives in the companion design's Phase 2a and the PDF
   report in its Phase 4. This workstream delivers the HTML, JSON and
   SARIF reports, with the transcript support that the PDF will later
   need. The PDF's two-minute render budget and its plain-text fallback
   stay in the companion design's Phase 4.
7. **The verification runs twelve of the thirteen roles, and says so.**
   Thirteen roles are built in; the standard profile plans eleven. The
   verification run enables the independent `verifier` as well — it
   costs one request per candidate finding, capped at twelve — so
   twelve roles are planned and run. The `orchestrator` role is a
   collaboration facilitator with no scan task by design; the coverage
   statement reads "13 built-in roles: 12 planned and run, 1
   (`orchestrator`) has no scan task by design". The per-role table
   covers the planned roles and lists the unbuilt one explicitly, so the
   numbers reconcile.
8. **The merge reads three sources, and the crawl is ordered.** The
   merge reads the platform's copy of the worker output
   (`platform_worker_output`), the fingerprinted URLs
   (`platform_services`) and the adapter's own rows — not the legacy
   `reports`/`links`/`js` documents, because the platform copy is the
   source of truth and already exists per scan. Two gaps in the platform
   copy are closed: the jsscanner's JavaScript files are filed under
   kind `item` because `_kind_of()` has no `js` branch, so the merge
   classifies them as `js`; and `wayback`'s links are absent from
   `LINK_WORKERS`, so they are simply not in the inventory. Worker
   *paths* (dirsearch's `/admin`) are not URLs: they become assets only
   when they can be resolved against the scan's primary target scheme
   and host, and then they carry `status_code: 0` because they were
   never fetched. The crawl's seed list would be empty in practice —
   every native adapter currently runs in one concurrent gather, so
   `platform_services` is still empty when `asset_crawl` starts — so
   the orchestrator dispatches the native adapters in two waves: the
   fingerprinters first, then `asset_crawl`, which seeds from the
   targets plus the URLs they fingerprinted.
9. **A cross-origin reference is marked, not hidden.** The asset
   document gains a `scope` field: `first_party` or `external`. An
   external reference is recorded with `status_code: 0`,
   `size_bytes: 0` and no content type, and is never fetched. The kinds
   stay the six of §5.2. The JS tab defaults to first-party only —
   "which JS files does this site serve" must not answer with jQuery
   from a CDN — while the URLs tab shows the whole inventory with the
   third-party entries labelled.
10. **The transcript endpoint paginates.** One role's transcript can be
    hundreds of tool calls; the repositories cap at 1000 rows and the
    tool calls are stored newest-first while the messages are
    oldest-first, so the endpoint merges the two chronologically and
    raises the row limits. It returns at most 200 items and 2 MB per
    page, with a cursor and a `truncated` flag. The console pane fetches
    progressively. The HTML report embeds the transcript up to a stated
    per-scan cap of 2 MB and says what it omitted; the complete
    transcript is always available from the endpoint.

Two smaller points are settled the same way: the merge reads the
platform's copy rather than the legacy documents, and `list_assets` keeps
its old kind vocabulary as aliases — `javascript` maps to `js`, and the
schema gains `page`, `js`, `image`, `css`, `api` and `other` alongside
`url`, `route`, `host` and `technology` — so the role prompts that
already reference the old names keep working.

## 4. Goals, non-goals, anti-goals

**Goals**

1. Every URL the platform can see — from the crawlers, the workers, the
   fingerprinters and the new adapter — is recorded once, with its kind,
   its scope, its source and where it was found.
2. JavaScript URLs and image URLs are first-class, filterable things.
3. The console shows the asset inventory, the tool participation, the
   per-role agent outcomes including the stop reason, and the full
   transcript of any role.
4. The report carries the same material, so it can be sent to someone.
5. A scan's outcome says which tools took part, which did not and why,
   which roles finished, which were cut off, and how — and whether any
   error went unexplained.
6. `list_assets` returns the real inventory, so the agents are not blind.
7. The verification run produces measured evidence over all three labs.

**Non-goals**

* Browser-driven collection — that is Phase 2a; the adapter is written so
  the browser can replace it rather than sit beside it.
* The PDF report — that is the companion design's Phase 4, which will
  consume the transcript support built here.
* A cross-scan inventory page — Phase 3, as the companion design has it.
* Multi-tenant anything, notifications, scheduling — untouched here.
* Changing what the workers or the agents *decide*; this workstream
  changes what they can *see* and what the platform *records*.

**Anti-goals** — the failure modes this workstream exists to prevent:

* A report that says a tool found nothing when the tool was cut off.
* A finding count that silently doubles because the same URL was seen by
  two tools.
* A transcript that leaks a target credential into Mongo or the report.
* A tool output that fails to store and disappears without a trace.
* An agent told there are no assets when the platform has hundreds.

## 5. The asset inventory

### 5.1 The `asset_crawl` adapter

A native adapter in `b_hunters/platform/scanners/native.py`, registered
in the default registry under the name `asset_crawl` and added to the
standard profile's scanner list, so it runs on every scan unless the
operator removes it.

* **Seeds**: the scan targets plus the URLs the fingerprinters recorded
  in `platform_services`. It runs in the second native wave so those
  rows exist (§3.1, item 8).
* **Traversal**: same-origin links and same-origin `fetch`/XHR targets
  visible in the response body, plus `src`/`href` attributes. Hash
  routes are recorded. It does not execute JavaScript and does not
  follow cross-origin links; a cross-origin reference is recorded as an
  external reference and never fetched.
* **Requests**: `GET` only, through `ScopeEnforcer`, at the scan's rate
  limit and concurrency.
* **Limits**: 2000 assets per scan, depth 3 from the seeds, 256 KB read
  per response, in-scope only.
* **What it stores**: metadata only — never a body, never an image
  byte.

### 5.2 The asset document

```
asset_id, scan_id, url (normalised), host, path, query (redacted),
kind (page | js | image | css | api | other),
scope (first_party | external),
status_code, content_type, size_bytes, depth,
sources (list of the tools that saw it), source (the first one),
discovered_from (the URL it was found on),
extension, first_seen_at, last_seen_at
```

Indexes: `(scan_id, url)` unique, `(scan_id, kind)`, `(host)`,
`(kind, last_seen_at)`.

`url` is normalised: scheme and host lowercased, default port removed,
path normalised, fragment dropped, query sorted and its credential-shaped
parameters redacted.

### 5.3 Classification and the merge

Classification, in order:

1. By response content type: `text/html` → `page`;
   `application/javascript`, `text/javascript`, `application/x-javascript`
   → `js`; `image/*` → `image`; `text/css` → `css`;
   `application/json`, `application/xml`, `text/xml` → `api`;
   anything else → `other`.
2. By extension, when there is no content type: `.js`, `.mjs` → `js`;
   `.css` → `css`; `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.webp`,
   `.ico`, `.bmp` → `image`; `.json`, `.xml` → `api`; `.html`, `.htm` →
   `page`; otherwise `other`.
3. By path, for a URL never fetched: a path containing `/api/` or
   `/graphql` → `api`.

The merge runs at the end of the worker phase and reads three sources:
the adapter's rows, `platform_worker_output` and `platform_services`. It
adds every URL and JavaScript file the workers reported, resolves
dirsearch's paths against the scan's primary target, and merges them
into the adapter's rows by normalised URL. A URL seen by both the crawler
and `katana` is one row whose `sources` lists both.

Scanner screenshots stay out of the Images tab: a screenshot is a
picture *of* the target, not a picture the target serves. They remain
in the Scanners tab where they are today.

### 5.4 `list_assets` becomes real

The tool reads the `platform_assets` collection for the scan instead of
the empty metadata dictionary. Its kind vocabulary keeps the old names
as aliases (`javascript` → `js`) and gains the six new kinds. The
result gains a `by_kind` count so an agent can see the shape of the
surface before listing it.

## 6. Reporting

### 6.1 Tool participation

A new endpoint, `GET /api/v1/scans/{scan_id}/participation`, returns two
sections.

**Karton workers** — one row per identity from the seventeen the
platform knows:

```
worker, participated (bool), reason, items, findings, crashed_tasks,
expected_version, connected_at_scan_start
```

The reasons are decided by facts recorded during the scan, not inferred
at read time:

| Reason | Decided by |
|---|---|
| `not connected` | the identity was absent from the online-consumer snapshot taken at scan start |
| `never dispatched` | it was connected, but consumed no task for this scan |
| `ran, found nothing` | it consumed at least one task and produced no finding |
| `errored` | it consumed at least one task and had at least one crashed task |
| `ran` | it consumed at least one task and produced findings |

**Native adapters** — one row per platform adapter, with its real
version from the registry, its status (`succeeded`, `failed`, `not
selected`), and the items it produced.

The coverage line counts both sections. The rule that governs the
wording: **a tool that ran and found nothing is reported as having run
and found nothing.** It is never reported as absent, and it is never
reported as a failure.

### 6.2 Agent outcomes and stop reasons

`GET /api/v1/scans/{scan_id}/agents/report` returns one row per planned
role:

```
role, tasks, status (succeeded | budget_exhausted | wall_clock |
failed | cancelled), stop_reason, rounds, tool_calls, tokens,
findings_raised, findings_confirmed, conclusion
```

`stop_reason` is read from the task result, never inferred from an empty
error string. The scan cap is an enforced deadline (§3.1, item 4), so a
role that did not start because the deadline passed is recorded as
`wall_clock` and a role that was cut off mid-flight is recorded as
`wall_clock` too — never as `succeeded`.

### 6.3 Transcripts

`GET /api/v1/scans/{scan_id}/transcript?role=&task_id=&cursor=&limit=`
returns the transcript of one role: every persisted message (hypothesis,
observations, evidence, confidence, budget) and every tool call
(arguments, status, duration, output), merged chronologically and
paginated — at most 200 items and 2 MB per page, with a cursor and a
`truncated` flag.

The stored tool output changes from a 2000-character summary alone to
the summary **plus** the full rendered output, bounded at 512 KB, with
`output_truncated` and the true byte count when it does not fit. The
rendering pipeline already redacts what it stores, so the stored output
carries the same redaction the model saw.

### 6.4 The report

The existing report in `b_hunters/platform/api/routers/findings.py` is
extended, not replaced. The HTML report gains:

* the summary block — assets by kind, findings by severity, the coverage
  line, the stop-reason counts and the integrity verdict;
* the asset table (URL, kind, scope, status, content type, size,
  sources);
* the participation table;
* the per-role table with stop reasons;
* a per-role transcript appendix, capped at 2 MB of transcript text per
  scan, stating what was omitted and pointing at the transcript
  endpoint for the rest.

The JSON export gains the same collections. The SARIF export is left
alone — it is a findings format and has no place for assets.

## 7. The console

New scan tabs, in this order: Live activity, Task graph, Agents,
Collaboration, Tool calls, Scanners, Services, **URLs**, **JS**,
**Images**, Findings.

* **URLs** — the full inventory with a type filter (All, Pages, JS,
  Images, CSS, API, Other) and a first-party/external toggle.
  Columns: kind, scope, URL, status, content type, size, sources, depth,
  discovered from.
* **JS** — the same table filtered to `js`, first-party only by default,
  with the source column showing which tool reported each file.
* **Images** — the same table filtered to `image`.
* **Scanners** — gains the participation table and the coverage line
  above the existing per-worker output.
* **Agents** — gains the per-role table with the stop reason, and a
  transcript button that opens a pane with that role's messages and tool
  calls, fetched page by page.
* **Findings** — gains a detected-by filter, so the worker findings and
  the agent findings can be looked at separately.

The console stays zero-build: native ES modules, no bundler, no
framework.

## 8. The verification run

After the durable foundation and this workstream are in place:

* Three scans, one per lab: DVGA, Juice Shop, WebGoat.
* Profile: the standard scanner list plus `asset_crawl`; every planned
  agent role, with the independent `verifier` enabled — twelve roles in
  all. The thirteenth built-in role, `orchestrator`, has no scan task by
  design and is reported as such.
* `max_duration_seconds` 900 per scan; the worker phase takes 70% of it
  (a setting, `worker_phase_share`, default 0.7).
* The runner executes them one at a time — the global concurrency is 1
  and the target lock forbids two scans of the same host.
* **Pass criteria**: every one of the seventeen worker identities and
  every native adapter is accounted for with a reason when it did not
  take part; every planned role is accounted for with a status and a stop
  reason; the integrity verdict reports no unexplained error.
* The results are written into `docs/verification.md` with the measured
  numbers: assets by kind per lab, findings by severity and by detector,
  the participation table, the stop-reason counts, the integrity verdict
  and the duration of each scan.

The run happens against the labs, which are the only targets the
platform may contact.

## 9. The security properties

* The adapter requests through `ScopeEnforcer`; it has no path that
  bypasses scope enforcement, and it never fetches a cross-origin URL.
* The inventory stores no request or response bodies — metadata only.
* Asset URLs are normalised with credential-shaped query parameters
  redacted, so a token in a query string does not become a stored
  secret.
* Tool outputs are stored with the redaction the model already saw, so
  a target credential in a response body is redacted in the transcript
  before it is written.
* The transcript endpoint is behind the same authentication and role
  checks as every other endpoint.
* The stored output is bounded by the gateway's existing 512 KB limit;
  the inventory count is bounded by the 2000-asset cap. Neither is a new
  limit on what the platform may read.
* An external reference is recorded but never fetched, so recording a
  third-party URL cannot become a request to it.

## 10. What is left to the builder

* The exact normalisation function for URLs, and the redaction of
  credential-shaped query parameters.
* The exact set of path patterns that classify a URL as an API endpoint.
* The wording of the participation reasons.
* The layout of the console tables.
* The transcript appendix's formatting in the print stylesheet.
* The exact split of the 900 seconds between the worker phase and the
  agent phase beyond the 70/30 setting.

## 11. Data model additions

| Collection | Purpose |
|---|---|
| `platform_assets` | The merged asset inventory: one row per URL, with kind, scope, status, size and sources |
| `platform_worker_runs` | What each worker did in each scan: tasks consumed, findings, crashed tasks, the connected-at-start snapshot |

Indexes: `platform_assets` — `(scan_id, url)` unique, `(scan_id, kind)`,
`(host)`, `(kind, last_seen_at)`. `platform_worker_runs` —
`(scan_id, worker)` unique, `(scan_id, crashed_tasks)`.

`platform_tool_calls` gains a full `output` field beside the existing
2000-character `output_summary`, with `output_truncated` and
`output_bytes`. `platform_findings`, `platform_services` and the legacy
collections are untouched.

## 12. API additions

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/scans/{scan_id}/assets` | The inventory; `kind`, `scope`, `limit`, `offset` |
| GET | `/api/v1/scans/{scan_id}/participation` | The per-tool tables, the coverage line, the worker health line |
| GET | `/api/v1/scans/{scan_id}/agents/report` | The per-role table with stop reasons and token usage |
| GET | `/api/v1/scans/{scan_id}/transcript` | One role's transcript, paginated |
| GET | `/api/v1/scans/{scan_id}/integrity` | The error ledger and the verdict |

## 13. Sequencing

| Phase | What | Exit criteria |
|---|---|---|
| **A. Durable foundation** | The approved plan: jobs, runner, resume, issues, secrets | 414+ tests pass, clean tree, restart proof |
| **B. Assets** | `asset_crawl` adapter, `platform_assets`, the merge, `list_assets` | A scan of Juice Shop records its JS URLs and images; the agent tool sees them |
| **C. Reporting** | Participation, stop reasons, transcripts, the error ledger, the extended report | The report names every tool and every role with its outcome |
| **D. Console** | The three tabs, the participation table, the per-role table, the transcript pane | The console shows the inventory and the participation |
| **E. Verification** | Three lab scans, the written results | Every worker and role accounted for, no unexplained error, `docs/verification.md` written |
| **F. Documentation** | `docs/assets.md`, `docs/console.md`, `docs/verification.md`, the status documents | Every claim is a measured command output |

Each phase leaves the system working and is committed separately.
