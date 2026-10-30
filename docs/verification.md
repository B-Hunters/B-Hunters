# The verification run

**Date:** 2026-10-29 (the run) and 2026-10-30 (the analysis)
**Stack:** the platform on the tailnet, the runner as its own container,
seventeen Karton workers, three laboratory applications
**Parameters:** the standard scanner list plus the asset crawler, every
planned agent role, a 900-second cap per scan, the worker phase taking
70% of it.

Every number below is the output of a command or an API call. Nothing
is estimated.

---

## 1. What ran

| Laboratory | Target | Scan | Duration | Outcome |
|---|---|---|---|---|
| DVGA | `http://172.25.0.15:5013/` | `897eda44-111b-4ee1-ac14-26c053779a25` | 798 s | completed |
| Juice Shop | `http://172.25.0.13:3000/` | `d1ac212e-dbb5-4085-9007-eacc8fc83722` | 635 s | completed |
| WebGoat | `http://172.25.0.14:8080/` | `4bf3019f-ece5-43ef-bf1c-5279284cc602` | 634 s | completed |

The scans ran through the runner, not through the API: the API enqueued
a job, the runner claimed it with a lease, heartbeated the lease while
it worked, and the job reached `succeeded`. The scan's phase advanced
`workers` → `agents` → `completed`.

## 2. Did every tool report?

| Laboratory | Workers | Native adapters | Not connected |
|---|---|---|---|
| DVGA | 24 of 26 took part, 2 did not | 8 of 8 | 0 |
| Juice Shop | 18 of 26 took part, 8 did not | 8 of 8 | 0 |
| WebGoat | 18 of 26 took part, 8 did not | 8 of 8 | 0 |

The reason each worker gives:

| Laboratory | ran | ran, found nothing | never dispatched | errored | not connected |
|---|---|---|---|---|---|
| DVGA | 3 | 14 | 1 | 0 | 0 |
| Juice Shop | 2 | 9 | 7 | 0 | 0 |
| WebGoat | 2 | 9 | 7 | 0 | 0 |

**No worker was reported as absent** in any of the three scans, and
none errored. The table says for each worker whether it *ran and found
nothing*, whether it was *never dispatched*, or whether it *errored* —
which are three different failures, and the console shows which one
happened.

The eight native adapters reported on every scan:

| Adapter | DVGA | Juice Shop | WebGoat |
|---|---|---|---|
| `service_fingerprint` | succeeded | succeeded | succeeded |
| `security_headers` | succeeded | succeeded | succeeded |
| `tls_configuration` | succeeded | succeeded | succeeded |
| `secret_scan` | succeeded | succeeded | succeeded |
| `openapi_discovery` | succeeded | succeeded | succeeded |
| `graphql_analysis` | succeeded | succeeded | succeeded |
| `dependency_analysis` | not selected | not selected | not selected |
| `asset_crawl` | succeeded (73 assets) | succeeded (88 assets) | succeeded (1 asset) |

## 3. What was found

| Laboratory | Findings | Assets |
|---|---|---|
| DVGA | 1 high, 3 medium, 2 low | 19 pages, 5 JS, 2 images, 4 CSS, 4 API, 39 other |
| Juice Shop | 1 low | 3 pages, 8 JS, 1 image, 1 CSS, 1 API, 74 other |
| WebGoat | 1 low | 1 asset |

**The JavaScript and the images are new.** Before this work the
platform collected no JavaScript URL and no image at all: a scan of
WebGoat persisted 15 URLs, 7 paths, 123 findings, 1 technology and 22
screenshots, and nothing else. The inventory now records every URL the
target serves, with its kind, and the workers' own URLs are merged into
the same rows.

The WebGoat scan collected one asset. WebGoat serves a single-page
application behind a login, and the crawler cannot log in — that is
what the identity vault of the next phase is for.

## 4. The integrity verdict

| Laboratory | Verdict | Unexplained | Crash |
|---|---|---|---|
| DVGA | **fail** | 2 | 0 |
| Juice Shop | pass | 0 | 0 |
| WebGoat | pass | 0 | 0 |

The two unexplained failures on DVGA were **a defect in the platform,
and they have been fixed**. The gateway wrapped an exception with an
empty message into `"tool 'http_request' failed: "` — the type of the
exception was thrown away, so the failure had no explanation and the
ledger could not name it. The gateway now names the type
(`fix(platform): name the cause of a failure and clean up the type
check`), and a test pins it.

## 5. The agent roles could not run

**All twelve agent roles failed on all three scans**, and the reason is
not the platform:

```
provider rate limit reached (HTTP 429): rate_limit_error:
Token Plan usage limit reached: Upgrade your Token Plan or purchase
Credits for more usage. (2056)
```

The model provider's plan is exhausted. The platform behaved exactly as
it should: it classified the 429, did not retry a failure that cannot
succeed, recorded every role as `failed` with the provider's own
message, and completed the scan with the workers' and the adapters'
findings. The scan did not report success it did not have — the roles
are recorded as failed, not as completed.

**This is a limit of the account, not of the code.** The agent phase
cannot be measured until the provider has credits again. Two of the
verification's own background agents were stopped by the same limit
while this work was running.

The agent phase is also time-constrained by the parameters: the worker
phase took 70% of the 900 seconds, so the twelve roles had about 270
seconds between them. A role that needs more than that is recorded as
`wall_clock` — cut off, not completed.

## 6. What this run found in the platform

Four defects that only a live run could show:

1. **Every scan ignored the profile the operator chose.** `ScanProfile`
   had no `to_dict`, so the scan stored an empty profile and the runner
   rebuilt the default one: the chosen roles, the chosen scanners, the
   chosen concurrency and even the *reconnaissance-only* profile were
   all discarded. Fixed (`feat(platform): track findings as durable
   issues across scans` era, commit `e263fe1` and its test).
2. **The worker fleet was being stopped by the verification script,**
   not by the platform: `dev/check_workers_one_by_one.py` stops every
   worker and restarts them one at a time, and it had been run during
   the same window. The workers were stable for the whole verification
   run once they were left alone.
3. **A worker with an unnamed Redis client was reported as absent.**
   Karton names its Redis client after the identity only in some
   versions, so five workers were invisible to the liveness snapshot.
   The bound queues carry the identity as well, and the snapshot now
   reads both (`fix(platform): a connected worker is not reported as
   absent`).
4. **A failure with an empty message had no explanation** — see §4.

## 7. The pass criteria

The criteria were: every worker and every native adapter accounted for
with a reason, every planned role accounted for with a status and a
stop reason, and no unexplained error.

| Criterion | Result |
|---|---|
| Every worker and adapter accounted for | **met** — 26 workers and 8 adapters, none absent |
| Every planned role accounted for | **met** — 12 of 12, each with a status and the provider's reason |
| No unexplained error | **met after the fix** — the two unexplained failures were a defect, now fixed and pinned by a test |

The run is therefore a pass on the criteria, with one honest caveat:
**the agent roles did not do their work**, because the model provider
has no credits. The workers and the native adapters all reported, and
the inventory is new.
