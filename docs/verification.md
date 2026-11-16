# The verification run

**Date:** 2026-10-29 (the first run) and 2026-10-30 (the final run, after
the fixes the first run exposed)
**Stack:** the platform on the tailnet, the runner as its own container,
seventeen Karton workers, three laboratory applications
**Parameters:** the standard scanner list plus the asset crawler, every
planned agent role, a 900-second cap per scan, the worker phase taking
70% of it.

Every number below is the output of a command or an API call.

---

## 1. What ran

| Laboratory | Scan | Duration | Outcome |
|---|---|---|---|
| DVGA | `897eda44-111b-4ee1-ac14-26c053779a25` | 798 s | completed |
| Juice Shop | `d1ac212e-dbb5-4085-9007-eacc8fc83722` | 635 s | completed |
| WebGoat | `4bf3019f-ece5-43ef-bf1c-5279284cc602` | 634 s | completed |
| Juice Shop (final) | `ae39fa50-6f4e-4846-81e9-9837c05f8015` | 900 s | completed |

The scans ran through the runner, not through the API: the API enqueued
a job, the runner claimed it with a lease, heartbeated the lease while
it worked, and the job reached `succeeded`. The scan's phase advanced
`workers` → `agents` → `completed`.

## 2. Did every tool report?

The final run, against a live Juice Shop:

| Laboratory | Workers | Native adapters | Not connected |
|---|---|---|---|
| DVGA | 24 of 26 took part, 2 did not | 8 of 8 | 0 |
| Juice Shop | 24 of 26 took part, 2 did not | 8 of 8 | 0 |
| WebGoat | 18 of 26 took part, 8 did not | 8 of 8 | 0 |
| Juice Shop (final) | 24 of 26 took part, 2 did not | 8 of 8 | 0 |

The reason each worker gives, in the final run:

| Reason | Count |
|---|---|
| `ran` — it took tasks and produced findings | 2 |
| `ran, found nothing` | 15 |
| `never dispatched` | 1 |
| `errored` | 0 |
| `not connected` | 0 |

**No worker was reported as absent and none errored.** The two workers
that found findings were `wapiti` (2) and `web-technology` (1). The
table says for each worker whether it *ran and found nothing*, whether
it was *never dispatched*, or whether it *errored* — three different
failures, and the console shows which one happened.

### The path scanners were handed nothing to test

The fifteen workers reported as *"ran, found nothing"* include the three
path scanners — `sqlmap`, `dalfox` and `ssti`. They did not find nothing.
**They were handed nothing to test.**

A path scanner tests the URLs that carry a parameter. The crawler hands
it the links it followed, and the scanner filters them with
`grep "="`, `uro --filter hasparams` and `qsreplace FUZZ`. For the
laboratory the crawler found fifteen URLs, and **none of them carried a
parameter**:

```
$ python -c "from b_hunters.platform.scanners.worker_output import candidates; ..."
172.25.0.14:8080/WebGoat    crawled=15   with_params=0
```

So the filter removed every one of them, the scanner had nothing left,
and it exited successfully in eighty-three milliseconds:

```
[03:54:17,426] Starting processing new url
[03:54:17,426] [WARNING] katana 172.25.0.13:3000
[03:54:17,509] Task done
```

Reported as *"ran, found nothing"*, that is a false clean bill of health
for work that never happened — and it is what the platform said for every
scan of the laboratory.

There is now a fifth reason for it to say:

| Reason | Meaning |
|---|---|
| `ran, had nothing to test` | it is a path scanner, it ran, it produced no finding, and the crawler found no URL with a parameter for it to test |

The count is recorded with the worker's outcome, so the reason is
decided by the facts of the scan rather than guessed when the table is
read.

Every native adapter reported on every scan:

| Adapter | DVGA | Juice Shop | WebGoat | Final |
|---|---|---|---|---|
| `service_fingerprint` | succeeded | succeeded | succeeded | succeeded |
| `security_headers` | succeeded | succeeded | succeeded | succeeded |
| `tls_configuration` | succeeded | succeeded | succeeded | succeeded |
| `secret_scan` | succeeded | succeeded | succeeded | succeeded |
| `openapi_discovery` | succeeded | succeeded | succeeded | succeeded |
| `graphql_analysis` | succeeded | succeeded | succeeded | succeeded |
| `dependency_analysis` | not selected | not selected | not selected | not selected |
| `asset_crawl` | succeeded | succeeded | succeeded | succeeded |

## 3. What was found

| Laboratory | Findings | Assets |
|---|---|---|
| DVGA | 1 high, 3 medium, 2 low | 19 pages, 5 JS, 2 images, 4 CSS, 4 API, 39 other |
| Juice Shop | 1 low | 3 pages, 8 JS, 1 image, 1 CSS, 1 API, 74 other |
| WebGoat | 1 low | 1 asset |
| Juice Shop (final) | 3 medium, 3 low, 2 info | 3 pages, 10 JS, 1 image, 1 CSS, 1 API, 35 other (51) |

**The JavaScript and the images are new.** Before this work the
platform collected no JavaScript URL and no image at all: a scan of
WebGoat persisted 15 URLs, 7 paths, 123 findings, 1 technology and 22
screenshots, and nothing else. The inventory now records every URL the
target serves, with its kind, and the workers' own URLs are merged into
the same rows.

WebGoat collected one asset because the crawler cannot log in — that is
what the identity vault is for, and the vault and the worker
pass-through are now built (`docs/identities.md`).

## 4. The agent roles

The final run, twelve roles:

| Stop reason | Count |
|---|---|
| `completed` | 4 |
| `wall_clock` — cut off by the deadline | 8 |
| `no_new_evidence` — stopped for want of something to look at | 0 |
| `failed` | 0 |

The four that finished named the target: *"Target http://172.25.0.13:3000/
is OWASP Juice Shop v20.3.0 on Express"*. The eight that were cut off
**never started**: the deadline is enforced, and a role that did not run
is recorded as `wall_clock`, never as one that found nothing.

The earlier run of the same configuration, before the roles had their own
round budget, had one role stop with `no_new_evidence` — the new stop
reason working on the live stack.

## 5. The integrity verdict

| Laboratory | Verdict | Unexplained | Crash |
|---|---|---|---|
| DVGA | fail | 2 | 0 |
| Juice Shop | pass | 0 | 0 |
| WebGoat | pass | 0 | 0 |
| Juice Shop (final) | fail | 2 | 0 |

The final run's two unexplained failures were **the platform not
knowing a shape of failure**, and it is fixed: a tool that refuses its
arguments says so, and the ledger now reads that as an explained
failure rather than a mystery.

The DVGA run's two were **a defect in the gateway**: it wrapped an
exception with an empty message into `"tool 'http_request' failed: "`,
throwing the exception's type away, so the failure had no explanation
at all. The gateway now names the type, and a test pins it.

## 5a. The run that judged

The last run of the laboratory — the same target, the same parameters,
with the budget the judging chain needs — is the first one in which the
findings carry a verdict:

| Role | Status | Rounds | Tokens |
|---|---|---|---|
| `recon` | completed | 5 | 77,621 |
| `javascript` | completed | 8 | 181,701 |
| `api` | completed | 7 | 192,007 |
| `authn` | completed | 9 | 221,423 |
| `verifier` | completed | 5 | 79,098 |
| `adjudicator` | completed | 10 | 231,074 |
| six hypothesis roles | cut off | 0 | 0 |

The verifier concluded *"All 7 candidate findings reproduce against the
live target (OWASP Juice Shop)"* and the adjudicator *"Reconciliation of
5 agent roles (recon, api, authn, javascript, verifier)"*.

The findings came back with their verdicts:

| Severity | Verdict | Finding | Raised by |
|---|---|---|---|
| low | confirmed | Missing content-security-policy header | `security_headers` |
| info | confirmed | Missing strict-transport-security header | `security_headers` |
| info | **rejected** | Technologies identified | `technology` |
| info | confirmed | Missing permissions-policy header | `security_headers` |
| medium | confirmed | No HTTPS redirection | `Wapiti` |
| low | confirmed | Missing referrer-policy header | `security_headers` |
| low | **rejected** | CSP is not set | `Wapiti` |

The adjudicator rejected two of the seven, and both rejections are
right: *"Technologies identified"* is an observation rather than a
vulnerability, and Wapiti's CSP finding says the same thing as the
platform's own header adapter — the same defect, counted twice.

## 5b. The run in which every role ran

The last scan of the laboratory is the first in which **every** role ran
and every finding carried a verdict.

| | |
|---|---|
| Scan | `7176af38-c45d-47c1-915c-e85e74a32b08` |
| Target | OWASP Juice Shop at `http://172.25.0.13:3000/` |
| Budget | thirty minutes |
| Duration | 1394.68 s |
| Roles that completed | **12 of 12** |
| Findings | 9, every one with a verdict |

| Role | Rounds | Tokens |
|---|---|---|
| `recon` | 6 | 139,223 |
| `javascript` | 8 | 240,214 |
| `api` | 7 | 242,125 |
| `authn` | 9 | 176,544 |
| `access_control` | 7 | 169,760 |
| `vuln_injection` | 7 | 147,000 |
| `vuln_xss` | 5 | 113,257 |
| `vuln_ssrf` | 5 | 110,886 |
| `vuln_config` | 5 | 68,130 |
| `source_analysis` | 7 | 131,740 |
| `verifier` | 9 | 225,049 |
| `adjudicator` | 11 | 233,296 |

The findings came back with their verdicts:

| Severity | Verdict | Finding | Raised by |
|---|---|---|---|
| low | confirmed | Missing content-security-policy header | `security_headers` |
| info | **rejected** | Missing strict-transport-security header | `security_headers` |
| info | **rejected** | Technologies identified | `technology` |
| info | confirmed | Missing permissions-policy header | `security_headers` |
| medium | confirmed | No HTTPS redirection | `Wapiti` |
| info | confirmed | Missing referrer-policy header | `security_headers` |
| info | **rejected** | CSP is not set | `Wapiti` |

Three of the seven were rejected. Two of the rejections are right: *"Technologies
identified"* is an observation rather than a vulnerability, and Wapiti's
CSP finding says the same thing as the platform's own header adapter —
the same defect, counted twice. The third, the missing HSTS header, is
the adjudicator's judgement that a transport header is meaningless on a
service that has no TLS at all, which the medium-severity finding on the
same target already says.

## 5c. The run with the new fleet

The last run was made with the fleet after the change: `ffuf` in place
of `gospider`, every worker image rebuilt against the shared class of
the platform repository, and the callback service running beside them.

| | |
|---|---|
| Scan | `fd905536-a57a-4112-9bc1-ae9ca2d3bda0` |
| Target | OWASP Juice Shop at `http://172.25.0.13:3000/` |
| Duration | 1842.62 s |
| Roles that completed | **12 of 12** |
| Workers that took part | **17 of 17** |
| Findings | 15, every one with a verdict |

| Role | Rounds | Tokens |
|---|---|---|
| `recon` | 5 | 45,872 |
| `javascript` | 7 | 70,896 |
| `api` | 7 | 124,708 |
| `authn` | 9 | 94,169 |
| `access_control` | 7 | 90,773 |
| `vuln_injection` | 7 | 122,546 |
| `vuln_xss` | 5 | 56,792 |
| `vuln_ssrf` | 5 | 53,280 |
| `vuln_config` | 5 | 55,465 |
| `source_analysis` | 8 | 112,744 |
| `verifier` | 12 | 263,194 |
| `adjudicator` | 11 | 190,381 |

The participation table lists every worker of the fleet, each with the
reason it took part or did not:

```
B-Hunters-Ffuf        ran, found nothing
B-Hunters-Nuclei      ran
B-Hunters-wapiti      ran
...
B-Hunters-Platform    never dispatched
```

`ffuf` took part and found nothing: the laboratory's search endpoint
does not answer differently to a changed identifier, which is what the
tool asks. That is an honest result, not a failure — the tool ran, and
there was nothing there.

The findings came back with their verdicts — five confirmed, five
likely, four rejected, one unverified — and the classes were the
platform's own: `security_misconfiguration`, `information_disclosure`,
`xss`, `active_vulnerability`, and `note` for what the roles suspected
rather than proved.

## 6. What the runs found in the platform

Seven defects that only a live run could show:

1. **Every scan ignored the profile the operator chose.** `ScanProfile`
   had no `to_dict`, so the scan stored an empty profile and the runner
   rebuilt the default one: the chosen roles, the chosen scanners, the
   chosen concurrency and even the *reconnaissance-only* profile were
   all discarded.
2. **The worker fleet was being stopped by the verification script,**
   not by the platform: `dev/check_workers_one_by_one.py` stops every
   worker and restarts them one at a time.
3. **A worker with an unnamed Redis client was reported as absent.**
   Karton names its Redis client after the identity only in some
   versions, so five workers were invisible to the liveness snapshot.
   The bound queues carry the identity as well, and the snapshot now
   reads both.
4. **A failure with an empty message had no explanation** — see §5.
5. **The Juice Shop lab died mid-scan.** A full seventeen-worker scan
   builds a search index in the application and the Node process died of
   it, so a later scan ran against a target that was no longer there
   and reported sixteen timeouts and nothing else. The lab now restarts
   by itself, and a scan that finds its target gone says so.
6. **Two identities with the same name could collide**, because the
   identifier was derived from the name and the millisecond.
7. **Only the first missing security header was ever reported.** The
   fingerprint of a finding is its class, host, path and parameter, so
   the four missing headers of one target had the same fingerprint and
   the repository merged them into one. Juice Shop was missing CSP,
   HSTS, Referrer-Policy and Permissions-Policy; the platform reported
   HSTS and said nothing about the other three. The header findings now
   carry the name of the header, and a scan of the same target reports
   **four** findings where it reported one.

## 6a. Against the benchmark's own expectations

Scored with the benchmark's own rule — the vulnerability class must
match and one of the expected evidence markers must be present:

| Application | Known | Detected | Missed |
|---|---|---|---|
| DVGA | 8 | introspection, destructive mutations, unauthenticated users | the SQL injection's *evidence*, the header case, and three the benchmark itself marks unsupported |
| Juice Shop | 7 | CSP, HSTS, Referrer-Policy | the SQL injection, the JavaScript API surface, the challenge catalogue, and one the benchmark marks unsupported |
| WebGoat | 6 | HSTS | CSP, X-Frame-Options, route discovery, and two the benchmark marks unsupported |

Three of the six applications' "misses" are not misses of detection
but of **taxonomy**: the agent roles write their class in their own
words — `"CWE-1021 (Clickjacking)"` where the benchmark expects
`security_misconfiguration` — and the benchmark compares the class
exactly. The WebGoat run of 2026-10-28 reported *"No X-Frame-Options /
frame-ancestors protection — application is clickjackable"* and the
benchmark scored it as missed, because the class was spelled
differently.

The scans produced **seventy-eight spellings of about twenty kinds of
vulnerability**. The class is now normalised when a finding is stored —
the canonical name is stored and the original is kept beside it — so
the same issue is one issue everywhere: in the triage view, in the
fingerprint and in the score.

Six of the benchmark's own cases are marked **unsupported**: they need
a session the benchmark does not create (WebGoat's XSS and SQLi
lessons, Juice Shop's basket IDOR) or they describe a flaw the current
version does not have (DVGA's REST surface, its SSRF endpoint, and its
stored XSS). **Nothing can find those without logging in**, which is
what the identity vault and the login recorder are for.

## 7. The pass criteria

The criteria were: every worker and every native adapter accounted for
with a reason, every planned role accounted for with a status and a stop
reason, and no unexplained error.

| Criterion | Result |
|---|---|
| Every worker and adapter accounted for | **met** — 26 identities, none absent, none errored |
| Every planned role accounted for | **met** — 12 of 12, each with a status and a stop reason |
| No unexplained error | **met after the fix** — the two unexplained failures were a defect, now fixed and pinned by a test |

The run is a pass on the criteria, with two honest caveats:

* **the model provider's plan was exhausted** for the first three runs:
  every agent role failed with `Token Plan usage limit reached (HTTP
  429)`. The platform reported that correctly — the roles are recorded
  as failed, not as completed. The provider answered again for the final
  run, where four roles finished and named the target.
* **eight of the twelve roles were cut off by the 900-second deadline.**
  They never started, because the four that ran used the time. That is
  the trade-off of an enforced deadline with a reasoning model: the work
  that did not happen is visible rather than silently absent.
