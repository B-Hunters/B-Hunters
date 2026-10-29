# Design: the single-operator assessment platform

Date: 2026-10-29
Status: draft for approval
Scope: authenticated assessment, durable execution, continuous assessment,
triage and reporting, agent quality, and production hardening.

## 1. Intent

B-Hunters is already a working platform: seventeen Karton workers, a
FastAPI console, thirteen agent roles on PydanticAI, central scope
enforcement and a benchmark laboratory. It is used by **one operator** —
the person who owns this machine.

The next version should remove the ceiling on what the platform can find
and the ceiling on how it is operated:

1. **Find real bugs on real applications.** Most of the interesting
   surface is behind a login. Today the scan form collects usernames but
   no credentials, there is no browser, and the WebGoat run left four
   findings unverified because it could not authenticate.
2. **Survive a restart and run unattended.** A scan is currently an
   `asyncio.create_task` inside the API process. An API restart kills it.
   There is no queue, no lease, no recovery, no global concurrency limit.
3. **Run continuously.** There are no schedules, no scan-to-scan diff, no
   asset inventory, no notifications and no CI entry point.
4. **Make the output usable.** Findings have verdicts but no lifecycle,
   no ownership, no comments, no cross-scan history, no CVSS/OWASP
   mapping and no executive report.
5. **Know whether the agents are worth their tokens.** The roles spend
   every round they are given; there is no per-role evaluation, no
   provider failover and no cost view.
6. **Make it safe to leave running.** Development credentials are in
   deployment files, the xray binary is committed, scanner tooling is
   unpinned, and the frontend is a 1,341-line file with no unit tests.

Success, one month after the last phase, means:

* a scan can log in with a stored identity, crawl the authenticated
  surface, and verify an access-control finding that needs two sessions;
* a blind SSRF probe produces a callback that is attached to a finding;
* killing the API or the runner mid-scan does not lose the scan;
* a nightly schedule runs without a human, and the morning view says what
  is new, what is fixed and what was reopened;
* a finding can be triaged, commented, reported as PDF, and traced across
  every scan of the same target;
* a per-role benchmark says what each role costs and what it found;
* the repository contains no usable production credential.

## 2. Current state, measured

* `feature/ai-agent-platform` is 16 commits ahead of `main`.
* 21 files are modified and 36 are untracked. The 2026-10-28 worker-output
  and PydanticAI work is complete but uncommitted.
* `pytest tests` — **414 passed**; `ruff check` and
  `ruff format --check` are clean.
* The stack is up: platform, seventeen workers, DVGA / Juice Shop /
  WebGoat, Karton dashboard.
* Benchmark: precision 1.0, recall 0.733, F1 0.846. WebGoat console scan:
  31 findings, 24 confirmed, 4 unverified for lack of a login.
* The platform executes scans in-process (`api/routers/scans.py`,
  `asyncio.create_task`).
* `test_accounts` carries usernames only; no password, cookie or session
  is stored (`api/routers/scans.py`; `web/app.js`).
* No schedule, webhook, ticket connector, API-token or CI entry point.
* Findings have `verification_status` and evidence, but no triage
  lifecycle, comments, cross-scan group or report PDF.
* No OAST listener; the SSRF role prompt mentions a controlled callback
  host, but no such host exists.

## 3. Decisions taken for a single operator

These are the calls made here, not questions for the operator.

| Decision | Why |
|---|---|
| **No multi-tenant, SSO, team assignment or organisation model.** Keep the existing admin/operator/viewer roles; one real account. | One user. These features would add surface without changing what the platform can do. |
| **No separate browser sidecar.** Playwright Chromium lives in the platform image; the runner launches it, the API uses it only to render report PDFs. | One image, one deployment; resource isolation is not worth a second service for one user. |
| **MongoDB remains the source of truth, including the job queue.** Redis stays Karton's backend. | Mongo already holds scan state. Atomic `find_one_and_update` is enough for one operator and avoids a second queue system. |
| **Secrets are encrypted at rest** with a key from `BHUNTERS_SECRET_KEY`; the API returns masked values only; decryption happens in the runner at use time. | A pentest platform holds target credentials. A database dump must not be a credential dump. |
| **The 17 Karton workers stay unauthenticated in phase 2a.** Authenticated coverage comes from platform-native adapters, the browser and the agents. Phase 2b extends the worker contract for the tools that support headers/cookies. | The workers install `b-hunters` from PyPI; changing them is a release cycle across 17 repositories. Platform-level auth delivers most of the value first. |
| **The frontend stays zero-build**, but is split into native ES modules and tested with `node --test` plus Playwright. | No Node toolchain, but no more 1,341-line single file. |
| **Schedules and notifications run in the runner service**, not the API. | One scheduler, one job owner, no double-run when the API is replicated. |
| **Report PDFs are rendered by Playwright** from the HTML report. | The browser dependency is already there; no WeasyPrint/Cairo system stack. |
| **GitHub/Jira connectors are optional and generic-webhook-first.** | A solo operator may not use either; the generic webhook covers Slack, Discord, ntfy and CI. |

### 3.1 Forks resolved after the builder check

An independent builder review found nine places where a wrong guess
would force rework. They are settled here so the implementation plan has
no hidden schema or security decisions.

1. **Findings are per-scan occurrences; triage lives on a durable
   issue.** `platform_findings` keeps one document per finding per scan.
   A new `platform_issues` document is keyed by `(target_key,
   fingerprint)` and owns `triage_status`, assignee, tags, due date,
   CVSS/OWASP overrides, first/last seen and observation state. Each
   occurrence carries `issue_id`; a one-shot `b-hunters admin
   migrate-issues` backfills existing rows, and read paths backfill
   lazily so the upgrade is safe before the command runs. Comments,
   history, diffs, trends and notifications operate on issues; finding
   IDs remain the UI entry point.
2. **The browser scope proxy does not intercept TLS.** Playwright
   `context.route` and `route_web_socket` check the full URL, method and
   every redirect hop before a request leaves the browser; service
   workers are blocked. The local CONNECT proxy independently validates
   the host and resolved address, with no direct fallback. This proves
   full-URL scope at the browser layer and host/IP scope at the network
   layer without a generated CA, MITM or certificate-pinning exceptions.
   Response bodies are size-bounded; oversized responses are aborted.
3. **The login recorder is a runner job.** `POST
   /identities/{id}/login` returns `202` with a job ID; the runner runs
   `kind=identity_login`, decrypts inside the runner, drives Playwright,
   stores the encrypted storage state and reports `verified` or `failed`
   with a reason. Scheduled scans preflight the stored state against an
   explicit protected `verify_url`; if it is missing, expired or failing,
   the runner refreshes it. A failed refresh fails the scan unless the
   template sets `on_login_failure=continue_unauthenticated`, and either
   way a notification is sent. `success_url` is not proof of a session.
4. **A diff only claims a fix when the two scans are comparable.** Each
   scan stores `comparison_key` — a hash of target key, sorted scope,
   profile, scanner set, role set and identity IDs — plus a `coverage`
   summary (hosts, URLs, worker tasks succeeded/failed, authenticated).
   The default baseline is the previous completed scan with the same
   `comparison_key` and a healthy worker phase. Otherwise the diff
   returns `not_comparable` with the reason and makes no `fixed` or
   `reopened` claims. A missing issue in a comparable scan is
   `not_observed`; it auto-closes after `BHUNTERS_AUTO_CLOSE_MISSES`
   (default 2) consecutive comparable misses. Manual `fixed` is
   immediate, and recurrence reopens the issue with an event.
5. **Agent-phase resume is per task, not per stage.** Tasks get a
   deterministic `task_id` and a status; the orchestrator upserts and
   skips `succeeded` tasks on resume, re-runs `queued`, `running` and
   `failed` ones, and reuses stored results. `verifying` and `reporting`
   are explicit stage boundaries. Re-running a task replaces its task
   document instead of appending a duplicate, and skipped tasks spend no
   tokens.
6. **Identities lead; `test_accounts` stays for compatibility.**
   Browser, native-adapter and agent requests use identities.
   `test_accounts` remains on the scan: its usernames still reach the
   phase 2a workers, and an "additional usernames" UI field covers
   registration or multi-user tests that need no password. When both are
   present, identities win for platform paths; workers never receive
   identity secrets. Phase 2b adds an `auth` payload only for scans that
   select an identity.
7. **State-changing requests stay off by default.** The scan flag
   `allow_state_changing` gates agent and browser methods other than
   GET/HEAD/OPTIONS. The login recorder is a narrow, audited exception
   allowed to POST only to the configured `login_url` origin and path,
   with no off-origin redirect. Authenticated crawls are GET-only.
   XSS/CSRF validation that needs a state change requires the operator
   to enable the flag.
8. **The secret key covers every stored credential.** `BHUNTERS_SECRET_KEY`
   encrypts identity credentials and storage state, provider API keys,
   notification webhook secrets and SMTP passwords. API tokens are
   hashed, not encrypted. Existing plaintext provider and notification
   rows are encrypted on first write or by `b-hunters admin
   migrate-secrets`; startup fails with a clear error if ciphertext
   exists without a key. `rotate-key` re-encrypts all four kinds.
9. **Storage state is not an agent action.** The browser tool exposes
   `goto`, `click`, `fill`, `press`, `wait`, `extract_text`,
   `extract_html`, `screenshot` and `session_status` (a boolean and a
   summary only). Storage state stays in the login recorder; cookies and
   localStorage never enter model context, events, logs or reports.

## 4. Workstream 1 — durable execution

### The problem

`POST /scans/{id}/start` calls `asyncio.create_task`. The scan lives in
the API process's memory. A restart loses it; two API replicas would
double-run it; there is no global limit on how many scans compete for the
seventeen worker containers.

### The design

A new `platform_jobs` collection and a `runner` process.

```
API                     MongoDB                      runner
 │  create scan           │                            │
 │  enqueue job ─────────▶ platform_jobs (queued)      │
 │                        │◀──── claim (lease 60s) ────│
 │                        │      heartbeat every 10s   │
 │                        │      run orchestrator      │
 │                        │◀──── complete / fail ──────│
 │  SSE reads events ◀──── platform_scan_events        │
```

**Job document**

```
job_id, kind ("scan" | "benchmark"), status ("queued" | "leased" |
"running" | "succeeded" | "failed" | "cancelled"), priority,
available_at, lease_owner, lease_expires_at, heartbeat_at, attempts,
max_attempts, payload, created_at, updated_at
```

Claim: `find_one_and_update` over `{status: queued, available_at <= now}`
or `{status: leased, lease_expires_at < now}` sorted by priority and
`created_at`, setting a new lease. A crashed runner's job is reclaimed
when its lease expires. A job that exceeds `max_attempts` becomes
`failed`; the scan becomes `failed` with the reason.

**Runner command**

`b-hunters runner --concurrency 1` — a long-lived process that claims
jobs, builds the orchestrator, runs it, heartbeats the lease, and handles
SIGTERM by finishing the current job or releasing it. The API no longer
builds the orchestrator.

**Checkpoints**

The scan record gains `phase` (`workers`, `agents`, `verifying`,
`reporting`, `completed`) and each agent task gains a deterministic
`task_id` plus `status`. The orchestrator writes the phase after each
stage and checkpoints after every task. On resume, a scan whose phase is
`agents` skips the worker phase and skips tasks already `succeeded`,
reusing their stored results; `queued`, `running` and `failed` tasks are
re-run and their task document is replaced. `verifying` and `reporting`
are explicit stages, so a restart never repeats adjudication or report
rendering. The worker output repository already replaces per scan, so
re-ingestion is idempotent; a scan restarted at `workers` re-runs the
worker phase.

**Locks**

* Global concurrency: `BHUNTERS_RUNNER_CONCURRENCY`, default **1** for one
  operator.
* One scan per target: a `platform_target_locks` collection with a TTL
  lease keyed by a normalised target hash; a second scan of the same host
  waits rather than competing for the same worker containers.
* Pause/stop remain flags on the scan, checked by the orchestrator at
  stage boundaries and before each agent task.

**Acceptance**

* A scan started through the API runs in the runner container.
* `docker restart bhunter_platform` during a scan does not stop it.
* `docker restart bhunter_runner` resumes the scan from its last phase.
* Two scans of the same host do not run at once.
* Two runner processes never claim the same job.

## 5. Workstream 2 — authenticated assessment

### 5.1 Identity vault

A new `platform_identities` collection. An identity is a named target
credential:

```
identity_id, name, kind ("form" | "basic" | "bearer" | "cookie" |
"header"), login_url, username, password_ciphertext, totp_secret_ciphertext,
headers_ciphertext, cookies_ciphertext, username_field, password_field,
success_url, success_selector, verify_url, verify_selector, verify_text,
setup_steps, storage_state_ciphertext, session_expires_at,
created_at, updated_at, last_used_at, last_login_at, status
```

`verify_url` is required for form, cookie and header identities: it is a
protected page that must require the session, and the recorder checks
`verify_selector`/`verify_text` (or a login form's absence) after login.
A `success_url` that is also reachable anonymously does not count.

* Secrets are encrypted with AES-GCM (`cryptography`) using
  `BHUNTERS_SECRET_KEY` (32 random bytes, base64 in the environment).
* The API accepts secrets on create/update, never returns them; `GET`
  returns `has_password: true` and masked metadata. The UI re-prompts only
  when a secret is replaced.
* Every use is audited (`identity.use`, scan id, role) without values.
* A scan selects `identity_ids` (primary and secondary); the secondary is
  what access-control comparisons use.
* A **login recorder** runs as a runner job (`kind=identity_login`). It
  navigates to `login_url`, fills the fields, submits, waits for
  `success_url`/`success_selector`, captures `storage_state` (cookies +
  localStorage), validates it against `verify_url`, and stores the
  encrypted state on the identity. TOTP is generated with `pyotp` when
  configured. The API never decrypts: `POST /identities/{id}/login`
  returns `202` with a job ID and the UI polls the identity's `status`.
* A scheduled or queued scan **preflights** the stored state against
  `verify_url`. If the state is missing, expired or fails verification,
  the runner refreshes it before the scan. A failed refresh fails the
  scan unless the template sets `on_login_failure=continue_unauthenticated`;
  both outcomes raise a notification.
* Identities are reusable across scans; a scan may override the login
  fields without changing the stored identity.
* `test_accounts` remains for worker compatibility (usernames only).
  Identities win for browser, native-adapter and agent requests. Phase 2b
  passes an identity's headers/cookies to workers as an `auth` payload;
  workers never receive the secret values directly.

### 5.2 Scope-safe browser

Scope is enforced at two independent layers. The browser context uses
Playwright request routing (`context.route` and `route_web_socket`) to
check every request against the scan's `ScopePolicy` before it leaves the
browser:

1. the host must be in the authorised list;
2. the resolved addresses must pass the same private/link-local/CGNAT/
   metadata checks as `ScopeEnforcer`;
3. every redirect hop and WebSocket upgrade is checked separately;
4. request rate, concurrency and response size are bounded.

In addition, the browser is launched with
`--proxy-server=http://127.0.0.1:<port>` and no direct fallback. The
local CONNECT proxy independently validates the host and resolved IP, so
a request that somehow bypasses Playwright routing still cannot leave
the host. Service workers are blocked (`service_workers="block"`), which
removes a cache/proxy path that routing does not reliably see.

This deliberately does **not** intercept TLS. The browser layer sees the
full URL, method and headers of each request and each redirect; the
network layer sees the destination. No generated CA, no MITM, no
certificate-pinning exception. The cost is that a destination which
resolves to a public address but later rebinds internally is caught only
by the proxy's address check, not by payload inspection — acceptable for
scope enforcement, which is about where traffic goes, not what it says.

**Browser tool** (agent-facing): `browser` with actions `goto`, `click`,
`fill`, `press`, `wait`, `extract_text`, `extract_html`, `screenshot`,
`session_status`. No arbitrary JavaScript evaluation and no
`storage_state`: cookies and localStorage never enter model context.
Outputs are redacted, screenshots become artifacts, and every action is
audited. `click`/`press` that would issue a non-safe request are refused
unless the scan has `allow_state_changing` enabled.

**`browser_crawl` adapter**: a native scanner that follows links and
same-origin XHR/fetch calls, including hash routes, and writes the
discovered URLs into `platform_worker_output` as `kind=url`. This is what
makes an Angular application like Juice Shop visible.

**`http_request` identity argument**: every agent HTTP call and every
native adapter can name an identity. The gateway injects the stored
cookies/headers at call time; the model never sees the secret values.

### 5.3 Worker pass-through (phase 2b)

After the platform-level path works, the shared `b_hunters.bhunter`
base class gains `auth_headers(task)` and the worker contract accepts an
`auth` payload. The scanners that support custom headers/cookies —
nuclei, sqlmap, dalfox, wapiti, katana, gospider, dirsearch, xray where
possible — pass them through. This is a `b-hunters==1.3.0` release plus
the Dockerfile bump in those repositories, tested one worker at a time
with `dev/check_workers_one_by_one.py`.

### 5.4 OAST callback listener

A separate tiny `callback` service:

* `GET|POST /cb/{token}` records method, path, headers, body (bounded),
  source address and time; every other path returns 404.
* A token is created per scan and label; it is unguessable and expires.
* Tokens and events live in `platform_callback_tokens` and
  `platform_callbacks`, which the platform reads directly from Mongo.
* The public base URL is `BHUNTERS_CALLBACK_BASE_URL`. In the lab it can
  be the tailnet name; for real targets it must be publicly reachable
  (Tailscale Funnel or a reverse proxy). The callback service is the only
  thing exposed; the platform API is not.
* Agent tools: `create_callback(label)` returns the URL; `list_callbacks`
  returns hits. The SSRF, XSS and injection roles get both.
* A callback hit becomes evidence on the finding that used the token.

### Acceptance

* A scan of WebGoat with a test identity logs in, crawls an authenticated
  page, and confirms a finding that needs the session.
* The same scan with two identities demonstrates an access-control
  difference (A can, B cannot) and records it as evidence.
* A blind SSRF payload against a lab endpoint produces a callback row and
  a linked finding.
* An out-of-scope request from the browser is refused by the proxy, and
  the refusal is in the audit trail.
* No identity secret appears in the API response, the event stream, the
  logs or the report.

## 6. Workstream 3 — continuous assessment

### 6.1 Scan templates and schedules

* `platform_scan_templates`: a saved scan definition (targets, scope,
  profile, scanners, roles, identity IDs, budgets) with a name.
* `platform_schedules`: template id, cron expression, timezone, enabled,
  next_run_at, last_run_at, last_scan_id, created_at.
* The runner's scheduler loop claims due schedules atomically
  (`find_one_and_update` on `next_run_at`) and enqueues a scan job. One
  scheduler, so no double-run.
* `croniter` parses the expression; invalid expressions are rejected at
  create time.
* UI: **Schedules** page with create, edit, pause, run-now and last result.

### 6.2 Scan diffing and inventory

* `target_key` on a scan: a stable hash of the sorted authorised hosts and
  primary target. `comparison_key` adds the sorted scope, profile,
  scanner set, role set and identity IDs; `coverage` records hosts, URLs,
  succeeded/failed worker tasks and whether the scan was authenticated.
* `GET /scans/{id}/diff?against={other_id}` (default: previous completed
  scan with the same `comparison_key` and a healthy worker phase) returns
  `new`, `fixed`, `reopened`, `persistent` issues, matched by
  `(target_key, fingerprint)`, with severity and verification status for
  each. When no comparable baseline exists the response is
  `not_comparable` with the reason, and the `fixed`/`reopened` groups are
  empty rather than misleading.
* A missing issue in a comparable scan sets its occurrence to
  `not_observed`; the issue auto-closes after
  `BHUNTERS_AUTO_CLOSE_MISSES` (default 2) consecutive comparable misses.
  A manual `fixed` is immediate, and a recurrence reopens the issue with
  an event. This prevents a degraded or unauthenticated scan from
  reporting false fixes.
* A scan's **Changes** tab shows the four groups plus the comparability
  reason and coverage delta.
* `GET /inventory` aggregates hosts, services and URLs across scans:
  first seen, last seen, open issues, technologies, ports. Backed by
  `platform_services` and `platform_worker_output` aggregations, with
  indexes added for host/url/time.
* A **Findings history** view uses the global issue, so a finding can be
  traced from first appearance to fixed across every scan of the target.

### 6.3 Notifications

* `platform_notifications`: name, kind (`webhook` | `email`), target
  (URL / address), secret, enabled, events (`scan.completed`,
  `scan.failed`, `findings.new_high`, `finding.triaged`), filter
  (severity, target).
* A delivery worker in the runner posts JSON (optional HMAC signature) or
  sends SMTP mail; deliveries and failures are recorded.
* Generic webhook is the first-class path; GitHub and Jira connectors are
  optional adapters behind the same interface.

### 6.4 CI entry point

* `platform_api_tokens`: hashed token, name, scopes (`scan:create`,
  `scan:read`), expiry. The API accepts `Authorization: Bearer <token>`
  in addition to the session cookie, with CSRF exempt for token auth.
* `b-hunters ci scan --target ... --wait --fail-on high` creates a scan,
  streams its events, prints the findings and exits non-zero when the
  threshold is met.
* A GitHub Actions example is documented. The same command works in any
  CI.

### Acceptance

* A schedule runs a scan at the next cron time without a human.
* A second scan of the same target produces a diff with new/fixed/
  reopened/persistent findings.
* The inventory page lists a host seen in three scans with first/last
  seen.
* A webhook receives a signed scan-completed payload.
* A CI token can create a scan and fail a pipeline on a high finding.

## 7. Workstream 4 — triage and reporting

### 7.1 Finding lifecycle

Triage lives on the durable issue (`platform_issues`), not on the
per-scan occurrence:

```
issue_id, target_key, fingerprint, title, severity, vuln_class
triage_status: open | in_progress | fixed | risk_accepted | false_positive | duplicate
duplicate_of (issue_id, when duplicate)
assignee (username; "me" by default)
tags: list[str]
due_at (optional)
cvss_vector, cvss_score
owasp_category
first_seen_at, last_seen_at, last_seen_scan_id
observation_status: observed | not_observed | auto_closed
consecutive_misses
created_at, updated_at
```

Each `platform_findings` occurrence keeps its evidence, URL, request and
verification status and gains `issue_id`, `not_observed` and
`coverage_scan_id`. A one-shot migration and lazy read-path backfill
cover existing findings.

Comments live in `platform_issue_comments`:

```
comment_id, issue_id, scan_id, finding_id, author, body, created_at, updated_at
```

* Bulk update endpoint for selection in the findings table; the same
  issue is updated across scans.
* Every change is audited; comments are not editable by anyone but the
  author (one user, still a useful guarantee).
* "Seen in N scans" uses the issue; the history endpoint returns the
  scans, first/last seen and verification changes.
* Dashboard trend: open issues by severity over time, verified rate,
  mean time to triage, new vs fixed per week. Counting is per issue, not
  per occurrence.

### 7.2 CVSS and OWASP

* A small, tested CVSS 3.1 base-score calculator (no new dependency) and
  a vector parser. The adjudicator may set a vector; the platform
  computes the score.
* A mapping from `vuln_class` to OWASP Top 10 (2021) categories, with a
  manual override on the issue.
* The report shows the score and the category, not just the label.

### 7.3 Reports

* A print-optimised HTML report with:
  executive summary (scope, dates, counts, verified rate, top risks),
  findings grouped by severity with evidence, CVSS/OWASP, remediation,
  affected URLs, screenshots and callback evidence,
  methodology and limitations, and an appendix of scanned hosts.
* `GET /scans/{id}/report.pdf` renders the same HTML through Playwright
  and returns a PDF. JSON, HTML and SARIF exports remain.
* A technical report variant includes all evidence; the executive variant
  includes confirmed/likely findings only.
* Evidence attaches screenshots, request/response excerpts and callback
  hits; secrets are redacted.

### Acceptance

* A finding can be moved through open → in_progress → fixed, with a
  comment, and the audit trail shows it.
* The same fingerprint in three scans shows one history with three
  appearances.
* The PDF report opens, contains the summary and evidence, and leaks no
  secret.
* The dashboard trend shows the last 30 days.

## 8. Workstream 5 — agent quality

### 8.1 Stop when done

* The conclusion is already a PydanticAI output tool. Make it explicit:
  the role is told to call `final_result` as soon as it has enough
  evidence, and the runtime detects an early finish.
* Add a **no-new-evidence** counter: a round that produces no new tool
  result, finding, observation or URL increments it; three in a row ends
  the task with the current conclusion.
* Change the deployment round setting from a **floor** to a **cap**:
  `BHUNTERS_AGENT_MAX_ROUNDS` is the maximum, and each role's declared
  rounds still apply below it. This stops the "every role spends 24
  rounds" behaviour.
* Per-role budgets remain; the orchestrator records rounds, tool calls,
  tokens, wall clock and the stop reason per task.

### 8.2 Per-role evaluation

* `b-hunters bench agents --applications dvga,webgoat --roles recon,
  javascript,api,authn,access_control,vuln_injection,vuln_xss,vuln_ssrf,
  vuln_config --provider <name> --runs 1`.
* The runner executes the agent phase against the manifest, attributes
  findings to `detected_by`, and scores precision/recall/F1 per role and
  overall. Results go to `platform_benchmark_runs` with `mode=agent` and
  `platform_benchmark_results`.
* The benchmark page shows scanner and agent runs side by side: score,
  tokens, tool calls, duration, cost.
* A prompt/definition version is recorded with each run, so a change can
  be compared with the previous version.

### 8.3 Provider failover and cost

* Providers gain `priority`, `price_per_million_prompt`,
  `price_per_million_completion`, `enabled`.
* A `ProviderPool` tries providers in priority order on auth, rate-limit,
  timeout or server failure; the successful provider is recorded on the
  task. An exhausted plan is not retried (existing behaviour).
* The dashboard shows tokens and estimated cost per scan, per role and
  per provider; a budget alert fires a notification at 80% of the scan
  budget.
* Per-scan provider override remains.

### Acceptance

* A role that finds everything in six rounds stops at six, not
  twenty-four.
* A per-role benchmark produces scores and cost for each role.
* Killing the primary provider mid-scan makes the next request use the
  fallback, and the scan says which provider answered.
* The dashboard shows cost for the last ten scans.

## 9. Workstream 6 — hardening and maintainability

### 9.1 Secrets and deployment

* Replace `deploy/platform.ini` and `deploy/b-hunters.ini` in git with
  `*.example.ini`; generate the real files from `.env` with
  `scripts/render_config.py`. Add the real files to `.gitignore`.
* Generate strong development credentials; remove the published
  `admin` password from the runbook and change it on the live stack.
* `b-hunters admin set-password` command; `b-hunters admin rotate-key`
  for `BHUNTERS_SECRET_KEY` (re-encrypt identities and storage state,
  provider keys, webhook secrets and SMTP passwords), plus
  `admin migrate-secrets` and `admin migrate-issues` for the existing
  deployment.
* Remove the committed `.env` and public bucket policy from
  `B-Hunters-Playground`, or replace them with examples.
* `BHUNTERS_SESSION_COOKIE_SECURE=true` and HSTS when served over TLS.

### 9.2 Supply chain

* Replace the 69 MB xray binary with a pinned release download and
  SHA-256 check in `B-Hunters-xray/Dockerfile`; remove the binary from
  git.
* Pin the scanner tool versions and base images in the worker
  Dockerfiles; record the versions in `docs/supply-chain.md`.
* Add a CI secret scan and a dependency audit.

### 9.3 Production compose

A `docker-compose.prod.yml` overlay:

* Caddy (or Tailscale Serve) in front of the platform with TLS and HSTS;
* no published Mongo/Redis/S3 ports;
* `BHUNTERS_SESSION_COOKIE_SECURE=true`, `BHUNTERS_ENVIRONMENT=production`;
* resource limits for platform, runner, browser work and workers;
* a backup job: `mongodump` + S3 mirror to a backup volume;
* health checks for the runner and callback service.

### 9.4 Backend quality

* Run `mypy b_hunters/platform` and fix the errors; keep it in CI as a
  blocking job (the current job is wired but was never run locally).
* Add structured log fields for scan id, job id, role and provider.
* Add `/metrics` (Prometheus text format) with scan duration, job age,
  tool failure rate, token/cost counters and callback count. No external
  Prometheus dependency; the endpoint is optional.

### 9.5 Frontend

* Split `web/app.js` into ES modules:
  `js/api.js`, `js/router.js`, `js/format.js`, `js/components.js`,
  `js/views/*.js`, `js/main.js`.
* Add `node --test` tests for pure functions (escaping, formatting,
  route resolution, diff grouping, table rendering).
* Add Playwright smoke tests: login, dashboard, create scan, live tabs,
  findings triage, schedules, inventory, report print.
* Accessibility pass: labels, keyboard focus, contrast, reduced motion,
  empty/loading/error states.
* No framework, no bundler.

### 9.6 Documentation

* Update `STATUS.md`, `README.md`, `docs/implementation-report.md` and
  `docs/architecture-audit.md` after each phase.
* New docs: `authenticated-scanning.md`, `oast.md`, `runner.md`,
  `schedules.md`, `triage.md`, `agent-evaluation.md`, `supply-chain.md`.
* Every claim in the docs is a measured command output, as before.

### Acceptance

* `git grep` finds no live credential in a tracked file.
* The xray image builds from a pinned release without the committed
  binary.
* `docker compose -f docker-compose.prod.yml up` serves HTTPS with
  secure cookies.
* `mypy` is clean and blocking.
* The console loads from ES modules and the JS tests pass.
* `STATUS.md` matches the code and the test count.

## 10. Data model additions

| Collection | Purpose |
|---|---|
| `platform_jobs` | Durable scan/benchmark/login jobs, leases, retries |
| `platform_target_locks` | One-scan-per-target leases |
| `platform_identities` | Encrypted target credentials and session state |
| `platform_issues` | Durable findings: triage, ownership, CVSS/OWASP, observation state |
| `platform_issue_comments` | Triage comments on an issue |
| `platform_scan_templates` | Reusable scan definitions |
| `platform_schedules` | Cron schedules |
| `platform_callback_tokens` | OAST tokens per scan |
| `platform_callbacks` | OAST hits |
| `platform_notifications` | Webhook/email rules |
| `platform_notification_deliveries` | Delivery results |
| `platform_api_tokens` | Hashed CI tokens |
| `platform_provider_usage` | Tokens and cost per provider per scan |
| `platform_agent_evaluations` | Per-role benchmark scores and definition version |

Indexes: job claim (`status`, `available_at`, `priority`), lease expiry,
target lock TTL, identity name, schedule `next_run_at`, callback token,
issue `(target_key, fingerprint)` unique, issue `(triage_status,
severity)`, occurrence `issue_id` and `(scan_id, fingerprint)`, comment
`issue_id`, notification enabled, API token hash, provider usage
scan/provider, scan `comparison_key` and `target_key`.

Encryption-at-rest covers `platform_identities` secrets and storage
state, `platform_providers.api_key`, `platform_notifications.secret` and
the SMTP password. Existing plaintext rows are migrated by the
`admin migrate-secrets` command or encrypted on first write.

## 11. API additions (summary)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/identities` | Create an identity (secrets in, masked out) |
| GET | `/api/v1/identities` | List identities (masked) |
| POST | `/api/v1/identities/{id}/login` | Queue a login job; `202` + job ID |
| GET | `/api/v1/identities/{id}` | Status, verification time and masked metadata |
| DELETE | `/api/v1/identities/{id}` | Delete an identity |
| POST | `/api/v1/scans/{id}/diff` | Compare with another scan |
| GET | `/api/v1/scans/{id}/diff` | Compare with the previous comparable scan |
| GET | `/api/v1/inventory` | Cross-scan asset inventory |
| POST | `/api/v1/templates` | Save a scan template |
| GET | `/api/v1/templates` | List templates |
| POST | `/api/v1/schedules` | Create a cron schedule |
| POST | `/api/v1/schedules/{id}/run` | Run now |
| GET | `/api/v1/callbacks/{token}` | Callback hits (authenticated) |
| GET | `/api/v1/issues` | Durable issues with triage state |
| GET | `/api/v1/issues/{id}/history` | Cross-scan appearances and verification changes |
| POST | `/api/v1/issues/bulk` | Bulk triage update |
| POST | `/api/v1/issues/{id}/comments` | Add a comment |
| GET | `/api/v1/scans/{id}/report.pdf` | PDF report |
| POST | `/api/v1/tokens` | Create a CI API token |
| GET | `/api/v1/usage` | Tokens and cost by scan/provider |
| POST | `/api/v1/admin/runner/drain` | Stop claiming new jobs |

## 12. UI additions

* **New scan**: identity selector with verification status, template
  save/load, "test login" button that queues a login job.
* **Scan**: Changes tab (diff, comparability reason, coverage delta),
  Browser tab (screenshots and session status only), Callbacks tab,
  improved report actions (HTML/PDF/SARIF).
* **Findings**: durable issue with triage status, assignee, tags, due
  date, comments, history, bulk actions, CVSS/OWASP.
* **Inventory**: hosts, services, first/last seen, open findings.
* **Schedules**: list, create, run now, pause, next run.
* **Settings**: notifications, API tokens, provider priority/prices,
  runner status.
* **Benchmarks**: scanner and agent modes, per-role table, cost.
* **Dashboard**: trend charts, cost, job health, runner heartbeat.

## 13. Sequencing

Every phase leaves the system working and is committed separately.

| Phase | What | Exit criteria |
|---|---|---|
| **0. Protect the work** | Commit the 2026-10-28 worker-output/PydanticAI work; update STATUS; tag a baseline | 414+ tests pass; clean tree; tag |
| **1. Durable foundation** | Jobs/leases, runner service, target locks, stage and per-task checkpoints, issue/occurrence schema, new collections/indexes, secret key and `migrate-secrets` | Restart test passes; two runners do not double-claim; existing findings backfilled to issues |
| **2a. Authenticated platform** | Identity vault, `identity_login` runner job, scope-routed browser + CONNECT proxy, browser tool, `browser_crawl`, OAST callback service, native/agent identity injection | WebGoat authenticated scan; blind SSRF callback; login job reports verified |
| **2b. Worker auth pass-through** | `b-hunters==1.3.0` auth helper; patched workers; Dockerfile bumps; one-at-a-time verification | Named workers accept headers/cookies; no regression |
| **3. Continuous** | Templates, schedules, diffing, inventory, notifications, API tokens, CI command, optional GitHub/Jira | Nightly schedule + diff + webhook + CI fail |
| **4. Triage and reporting** | Lifecycle, comments, history, CVSS/OWASP, trends, HTML/PDF reports | Triage flow + PDF with evidence |
| **5. Agent quality** | Early stop, round cap, per-role bench, provider failover, cost dashboard | Role stops early; per-role scores; fallback works |
| **6. Hardening** | Secrets out of git, xray binary, pinning, prod compose/TLS, backups, mypy, frontend modules/tests, docs | No tracked credential; prod compose; mypy/JS tests clean |

Estimated effort for an agent working with the operator in the loop:
phase 0 is housekeeping; phase 1 is 2–3 days; phase 2a is 1–2 weeks;
phase 2b is 3–5 days; phase 3 is 1 week; phase 4 is 1 week; phase 5 is
1 week; phase 6 is 1 week. The estimate is not a promise; each phase is
re-estimated after its first task.

## 14. Testing strategy

| Layer | What it proves |
|---|---|
| Unit | Encryption/decryption, CVSS, comparison-key and diff grouping, issue auto-close, cron validation, job claim, lock expiry, redaction |
| Security | Identity secrets never in API/logs/events/reports; browser route and CONNECT proxy refuse out-of-scope; storage state not agent-reachable; callback tokens are unguessable; API tokens are hashed; CSRF rules |
| Integration (Mongo) | Job lease/reclaim, per-task resume, issue backfill, schedule claim, comparable/non-comparable diff, inventory aggregation, triage/history, notification delivery |
| Playwright | Login, scan creation, live tabs, triage, schedules, inventory, report print |
| Benchmark | Agent per-role scores; scanner scores unchanged |
| Live | WebGoat authenticated; blind SSRF callback; restart mid-scan; nightly schedule |

Every defect fixed gets a test. Every phase runs the full suite and
`ruff check`/`ruff format --check`; from phase 1, `mypy` too.

## 15. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Target credentials leak | AES-GCM at rest (identities, provider keys, webhook/SMTP secrets), masked API, redaction, no secrets in events/reports, storage state never agent-facing, audit every use, rotate-key command |
| Browser escapes scope | Playwright per-request routing plus mandatory CONNECT proxy, per-request and per-CONNECT IP validation, service workers blocked, no direct fallback, tests that try loopback/metadata/out-of-scope |
| A degraded scan causes false "fixed" | `comparison_key` and coverage gate, `not_observed` instead of `fixed`, auto-close after two consecutive comparable misses, login preflight |
| OAST endpoint is abused | Unguessable token, expiry, body/rate limits, only `/cb` exposed, no platform API on that surface |
| Runner race/double-run | Atomic claim, lease, heartbeat, target lock, two-runner test |
| Schema migration breaks legacy | Additive collections/indexes only; legacy `scans`/`domains`/`reports`/`js` untouched |
| Cost of reasoning models | Round cap, no-new-evidence stop, per-role budgets, cost dashboard, provider failover |
| Worker release cycle | Phase 2b is separate; platform works without it |
| Scope of "do all" | Phases are independently shippable; the operator can stop after any phase |

## 16. What is deliberately not built

* Multi-tenant organisations, SSO/OIDC, team assignment, per-tenant
  isolation.
* A mobile app, a public SaaS control plane, Kubernetes.
* A full rewrite of the 17 workers; phase 2b is a targeted auth
  pass-through.
* Arbitrary JavaScript execution in the browser tool; eval is not a
  capability.
* TLS interception with a generated CA. Scope is enforced on the request
  URL and destination address, not on decrypted payloads.
* A second database or a message broker beyond MongoDB and the existing
  Redis/Karton backend.

These are not needed for one operator and would slow the parts that
change what the platform can find.
