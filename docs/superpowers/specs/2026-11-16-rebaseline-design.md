# Rebaseline — the open issues, against the running system

**Date:** 2026-11-16
**Author:** audit pass over `/home/sniper/pentest/`
**Status:** this document replaces the issue list in the 2026-11-16 gap matrix
for the live tree. The gap matrix remains valid **as an audit of the upstream
GitHub clones**; it is not a description of the running system.

---

## 0. Why this document exists

On 2026-11-16 an audit was written against the repositories in
`/home/sniper/bhunters-audit` — eleven clones of the public `B-Hunters`
GitHub organisation at their `main` branches. It recorded thirty findings.

That tree is **not the system that runs**. The running system is
`/home/sniper/pentest/`, whose framework repository is at **v1.3.0
(2026-11-02)** on the branch `feature/ai-agent-platform`. It has a platform
package, a web console, an API, an agent runtime, a durable runner, an
authentication layer, a browser tool, a benchmark laboratory, and 101 test
files.

The two trees share a history — the live repository has the same `origin` —
but the live one is roughly six months of work ahead, and it has its own
audit (`docs/architecture-audit.md`), its own specs and plans under
`docs/superpowers/`, and a status document that tracks its open issues
(`/home/sniper/pentest/STATUS.md`).

**Consequence.** Most of the thirty findings in the gap matrix were already
addressed in the live tree, and the ones that were real there are a
different, smaller, better-defined set. This document reconciles the two and
states the issue list the remaining specs are written against.

### 0.1 What the live tree already has

| Gap-matrix finding | Live-tree state | Evidence |
|---|---|---|
| No web UI (P2) | **Built.** `b_hunters/web/`, `b_hunters/platform/api/`, `dashboard/` | `STATUS.md` §4; `b_hunters/platform/api/` |
| No authentication (P2) | **Built.** Argon2id hashing, sessions, RBAC, identity vault, login recorder | `platform/security/sessions.py`, `passwords.py`, `docs/identities.md` |
| No LLM / no agent runtime (P4) | **Built.** Twelve roles, provider abstraction, tool gateway, collaboration, orchestrator, budget, stop reasons | `platform/agents/`; `docs/agent-authoring.md`, `docs/agent-quality.md` |
| No deeper scanners (P3) | **Built.** GraphQL adapter, browser adapter, fingerprint adapter, native registry, asset crawl, dependency analysis, OpenAPI discovery, secret scanning, TLS config, security headers | `platform/scanners/`, `platform/browser/` |
| No test suite (F6) | **Built.** 101 test files: unit, integration, security, bench, frontend | `tests/` |
| No scope enforcement (F4) | **Built.** `platform/security/scope.py`, scope-routed browser, private-address guard | `bhunter.py:140` imports `is_blocked_ip` |
| No observability (F27) | **Partly.** Structured logs, participation table, error ledger, transcripts, stop reasons | `docs/verification.md` §2 |
| No findings schema (F29) | **Built.** Finding class normalisation, CVSS scoring, host inheritance | `tests/integration/test_finding_class_normalisation.py`; `STATUS.md` #26 |
| No benchmark lab (P5) | **Built.** DVGA, Juice Shop, WebGoat running; manifests, runner, scoring | `platform/bench/`; `bench-lab/` |
| No SARIF / interchange | **Not present.** PDF report exists; SARIF does not | — |
| Dead stages (F3) | **Partly.** `gospider` retired, `ffuf` added; `url/new`/`url/wordpress` still exist upstream | `STATUS.md` #31 |
| Workers run stale published code (F7) | **Fixed.** `scripts/build_workers.sh` builds every worker against the shared class of this repository | `STATUS.md` #30 |

### 0.2 Findings from the gap matrix that still hold in the live tree

| Gap-matrix finding | Live-tree state | Evidence |
|---|---|---|
| **F1** — the report generator reads `domains`, workers write `reports` | **Still true in the legacy CLI path.** The platform has its own report; the legacy `b-hunters report` command has not been corrected. | `b_hunters/cli.py:611` reads `db["domains"]`; `nmapscan.py:101` writes `db["reports"]` |
| **F11** — artefacts attributed to a domain by substring match | **Still true.** | `b_hunters/cli.py:656` — `filename for filename in files if domain in filename` |
| **F10** — the report command blocks on `input()` | **Still true.** | `b_hunters/cli.py:638` |
| **F9** — a domain cannot be re-scanned | **Still true.** | `b_hunters/cli.py:345-351` — `run_scan` refuses an existing domain |
| **F5** — no licence on any repository | **Still true, and worse:** none of the **19** live repositories carries one. | `ls` over `/home/sniper/pentest/repos/B-Hunters*/` |
| **F25** — the failure escalation is dead code | Still true in the legacy base class. | `bhunter.py` |
| **F7** — unpinned tooling, non-reproducible builds | **Partly fixed.** Worker images are built from source now; the tools inside them are still `@latest`. | `scripts/build_workers.sh`; `go install …@latest` |

### 0.3 The gap matrix is wrong about one thing worth correcting

The gap matrix §1.2 states, correctly, that Karton inherits persistent
payloads across a task subtree — verified against Karton v5.5.0
`Producer.send_task` → `merge_persistent_payload`. That still holds, and the
live tree relies on it: `karton_bridge.py` says so in its own docstring.

What the gap matrix could not have known is the consequence, because the live
tree does something the upstream tree never did: **it writes to the Karton
bucket from outside Karton.** That single difference is the root cause of the
system's largest live defect (see §2).

---

## 1. The live issue list, reconciled

Sources: `STATUS.md` §7 (items not marked *Resolved*), `docs/misses.md`
(the four real misses), and the gap-matrix findings that survive (§0.2).

Severity: **S1** the platform reports something untrue or misses a real
defect · **S2** security or legal exposure · **S3** a capability is missing
or degraded · **S4** hygiene.

### 1.1 Group A — Scanner handoff integrity *(the four real misses)*

The benchmark scores the platform against known-vulnerable applications.
Thirteen cases were missed. Nine are unmeasured because the application was
never scanned. Four are real misses, and all four share two causes.

| # | Issue | Severity | Root cause | Owner |
|---|-------|----------|------------|-------|
| **A1** | The path scanners — `sqlmap`, `dalfox`, `ssti` — have produced **no findings in any scan since mid-October**, and the platform reports them as *"ran, found nothing"*. | **S1** | They are handed the crawler's links, filter them to the URLs that carry a parameter, and the filter leaves **nothing**: the crawler's haul for the laboratory has fifteen URLs and not one parameter. The scanner exits successfully having tested nothing, and the platform says it found nothing. | Spec A |
| **A2** | The search endpoint of a single-page application is never tested, because the crawler's link list is filtered down to one parameterised URL and the API routes live in the JavaScript bundle. | **S1** | Nothing hands the routes the JavaScript role recovers to the scanners that can test them. | Spec A |
| **A3** | The API surface of a JavaScript bundle is never stated as a finding. | **S1** | The bundle is read by one role; the routes are never converted into a finding. | Spec A |
| **A4** | Two classes of finding are never produced: an unauthenticated disclosure whose evidence is the body content, and the reachability of a route. | **S3** | The finding-class taxonomy has no member for either. | Spec A |

### 1.2 Group B — Supply chain, secrets, licensing

| # | Issue | Severity | Note |
|---|-------|----------|------|
| **B1** | The `xray` worker image builds from a **69 MB binary committed to git**. | S2 | Fetch from a pinned release with a checksum. |
| **B2** | Development credentials are committed in `deploy/*.ini` and in the Compose file. | S2 | Move to the secret store; `scripts/render_config.py` already exists for this. |
| **B3** | `admin` / `TailnetAdmin2026!` appear in the transcript. | S2 | Treat as public and rotate. |
| **B4** | `B-Hunters-Playground` is unmodified: a committed `.env` with credentials and a **public** artefact-bucket policy. | S2 | The original deployment is still unsafe if copied. |
| **B5** | **No licence in any of the 19 repositories**, while shipping GPL-2 (`nmap`, `dirsearch`, `wapiti`) and AGPL-3 (`xray`) tools. | S2 | Decide the posture of the wrappers and the xray question. |

### 1.3 Group C — Quality gates

| # | Issue | Severity | Note |
|---|-------|----------|------|
| **C1** | The frontend has **no unit test suite** — only the Playwright browser check. | S3 | Add a JS test runner to CI. `tests/frontend/` holds 14 browser tests. |
| **C2** | `mypy` is wired into CI but was **never run to completion locally**. | S3 | Run it and fix what it finds. |
| **C3** | `dev/check_workers_one_by_one.py` **stops every worker** and restarts them one at a time. | S3 | Running it during a scan makes the workers vanish and the scan reports tools that never ran. |
| **C4** | **The MongoDB container is killed under test load.** It has restarted **2038 times**; the last restarts were unclean kills during a test run, and the suite fails with `AutoReconnect: connection closed` whenever it creates a fresh test database. | S3 | Reproduced on the pristine tree, so it is not caused by the code. A previous crash (2026-11-02) was a WiredTiger *"No space left on device"*; the recent ones are unclean kills. The container also warns that its open-file limit is 1024 where 64000 is recommended. |

### 1.4 Group D — Agent lifecycle

| # | Issue | Severity | Note |
|---|-------|----------|------|
| **D1** | The hypothesis roles spend **all their rounds** on one scan. | S3 | They conclude at the budget, not when they have nothing left to test. |
| **D2** | The benchmark cannot measure the agent phase because two applications have manifests but **no reachable image**. | S3 | crAPI and Mutillidae; pull the images elsewhere or build from source. |

### 1.5 Group E — The legacy CLI report

| # | Issue | Severity | Note |
|---|-------|----------|------|
| **E1** | The legacy `b-hunters report` reads the wrong collection, matches artefacts by substring, blocks on `input()`, and refuses a re-scan. | S1 | The platform has its own report; the legacy command is either fixed or retired. |
| **E2** | No SARIF export. | S4 | The normalised finding schema makes this cheap. |

### 1.6 Blocked on the operator — not code work

| # | Blocker | What is needed |
|---|---------|----------------|
| **O1** | Every agent role fails with `Token Plan usage limit reached (HTTP 429)`. | Credits on the model provider account. The platform reports the failure correctly and claims no success it did not have. |
| **O2** | The `1.3.0` release is prepared — wheel and sdist built, `twine check` passes — but **not uploaded**. | `PYPI_API_TOKEN` for the owning account, then `scripts/publish_release.sh`. |
| **O3** | Nothing is on `main`. The branches were never pushed and no pull request exists. | Git push credentials, and a decision about what `main` should carry. |

---

## 2. The root cause behind A1

This is the most valuable defect in the system and it was not obvious, so it
is documented in full.

### 2.1 What happens

The crawler (`katana`) follows the links of the target and writes them to
the `links` collection. It publishes a `paths`/`scan` task, and three
scanners consume it: `sqlmap`, `dalfox` and `ssti`.

Each of them reads the list and filters it down to the URLs that carry a
parameter, because that is what it needs in order to test anything:

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

### 2.2 What the filter leaves

For the laboratory it leaves nothing. The crawler's haul for WebGoat is
fifteen URLs, and not one of them carries a parameter:

```
172.25.0.14:8080/WebGoat    crawled=15   with_params=0
```

The seven links in the `links` document are four CSS files and three
paths — `/WebGoat/registration`, `/WebGoat/login`, `/WebGoat/start.mvc` —
and none of them contains a `=`. The `grep -v css` step removes the four
style sheets and the `grep "="` step removes the other three.

### 2.3 What the scanner does with nothing

`newlinks == []` and the scanner returns immediately:

```
[2026-11-02 03:54:17,426] Starting processing new url
[2026-11-02 03:54:17,426] [WARNING] katana 172.25.0.13:3000
[2026-11-02 03:54:17,509] Task done
```

Eighty-three milliseconds. **It succeeded.** It tested nothing.

### 2.4 What the platform said

The participation table reported `ran, found nothing` — a false clean
bill of health for work that never happened. This is the same class of
defect as the one recorded for the agent roles in `STATUS.md` §7 #15:
*"A role that was cut off looks like a role that found nothing."*

### 2.5 The garbage collector is not the cause

It is worth saying what the cause is **not**, because it was the first
hypothesis and it is wrong.

* The crawler already publishes the list as a Karton `LocalResource`
  (`B-Hunters-Katana/katanam/katanam.py:144`), so the collector keeps it
  for the life of the scan.
* All three scanners already fall back to the database when the object
  store copy has gone (`sqlmapm.py:166`, `dalfox.py:103`,
  `sstichecker.py:63`), so they never depended on the object store at
  all.
* **An empty bucket after a scan has finished is the correct steady
  state** — the collector removes the object when the last task that
  referenced it is done.

The bucket on the host's port 9000 was empty, but that is the **older**
`bh-*` stack's bucket. The current platform's object store publishes no
host port and is reachable only on the `bhunter` network. The
observation that appeared to confirm the hypothesis was about the wrong
stack.

### 2.6 What has to change

Two things, and they are separate:

1. **The report must be honest.** A scanner that was handed nothing must
   not be reported as one that found nothing. The platform already
   computes the count — `candidates()` returns `urls_with_parameters` —
   and `_status()` ignored it.
2. **The scanners must be given something.** The routes that carry
   parameters are in the JavaScript bundle, not in the links a crawler
   follows. They have to be recovered and handed over.

---

## 3. The specs

| Spec | Covers | Groups |
|------|--------|--------|
| `2026-11-16-scanner-handoff-integrity-design.md` | A1–A4 | A |
| `2026-11-16-supply-chain-and-secrets-design.md` | B1–B5 | B |
| `2026-11-16-quality-gates-design.md` | C1–C3 | C |
| `2026-11-16-agent-lifecycle-design.md` | D1–D2 | D |
| `2026-11-16-legacy-cli-report-design.md` | E1–E2 | E |

Plan for the first spec: `../plans/2026-11-16-scanner-handoff-integrity.md`.

---

## 4. What this document does not cover

* **The gap matrix's other twenty-nine findings** are superseded by this
  document where the live tree has already addressed them. The gap matrix
  stays as the audit record of the upstream organisation — useful, because
  the upstream repos are what a new contributor clones.
* **The operator blockers** (O1–O3) are not code work and are not planned
  here.
* **The two unmeasured applications** (crAPI, Mutillidae) are an image
  availability problem, not a platform defect.

---

## 5. Evidence index

| Claim | Where |
|-------|-------|
| Live tree is v1.3.0 on `feature/ai-agent-platform` | `repos/B-Hunters` — `git log -1` = `ff90c9d 2026-11-02`; `b_hunters/__version__.py` |
| 101 test files | `repos/B-Hunters/tests/` — `find . -name 'test_*.py'` |
| Gap collector deletes unreferenced bucket objects | Karton v5.5.0 `karton/system/system.py` — `gc_collect_resources` |
| The bucket is empty | `boto3.list_objects_v2(Bucket="bhunters")` → 0 objects, 2026-11-16 |
| The path list is a raw write | `B-Hunters-Katana/katanam/katanam.py:101`; `b_hunters/platform/bench/workers.py:518` |
| The three scanners read it | `B-Hunters-Sqlmap/sqlmapm/sqlmapm.py:145`; `B-Hunters-DalFox/dalfox/dalfox.py`; `b-hunters-SSTI-Checker/sstichecker/sstichecker.py` |
| The legacy report reads the wrong collection | `b_hunters/cli.py:611` against `B-Hunters-NMap/nmapscan/nmapscan.py:101` |
| No licence anywhere | `ls` over `repos/B-Hunters*/` — 19 of 19 empty |
| Open issues | `/home/sniper/pentest/STATUS.md` §7; `repos/B-Hunters/docs/misses.md` |
