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
| **A1** | The path scanners — `sqlmap`, `dalfox`, `ssti` — have produced **no findings in any scan since mid-October**. | **S1** | The URL list they download is deleted by the Karton garbage collector before they read it. | Spec A |
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

The crawler (`katana`) uploads the URLs it found to the object store, under
the key `{source}_{scan_id}_{encoded_target}`, and publishes a
`paths`/`scan` task. Three scanners consume that task and download the list
by that key.

The upload is a **raw S3 write**:

```python
# B-Hunters-Katana/katanam/katanam.py:101
senddata = self.backend.upload_object(
    "bhunters", "katana_" + scan_id + "_" + self.encode_filename(urlstripped), resultdata
)
```

The platform's own benchmark harness does the same thing with its own client:

```python
# b_hunters/platform/bench/workers.py:518
client.put_object(Bucket=self.s3_bucket, Key=key, Body=body)
```

### 2.2 What deletes it

The Karton router runs a garbage collector. Verified in Karton v5.5.0,
`karton/system/system.py`:

```python
GC_INTERVAL = 3 * 60

def gc_collect_resources(self) -> None:
    karton_bucket = self.backend.default_bucket_name      # "bhunters"
    resources_to_remove = set(self.backend.list_objects(karton_bucket))
    tasks = self.backend.iter_all_tasks()
    for task in tasks:
        for resource in task.iterate_resources():
            if resource.bucket == karton_bucket and resource.uid in resources_to_remove:
                resources_to_remove.remove(resource.uid)
    if resources_to_remove:
        self.backend.remove_objects(karton_bucket, resources_to_remove)
```

**Every object in the `bhunters` bucket that no registered task references is
deleted, every three minutes.** The objects the workers write are raw S3
writes: no task references them, so the collector takes them.

### 2.3 The observation that confirms it

`docs/misses.md` records it: *"a probe object was uploaded and gone within
sixty seconds, and no object has survived in the bucket since the 29th of
October."*

Verified against the running stack during this audit:

```
$ boto3 list_objects_v2(Bucket="bhunters")
bhunters: 0 objects
```

The bucket the three scanners read from is empty. The two workers that
still produce findings — `nuclei` and `wapiti` — are the two that scan the
target directly and never read the list. `ffuf`, the newest worker, produces
its own inventory and does not read the list either.

**The symptom in `docs/misses.md` — "sqlmap, dalfox and ssti produce nothing,
in any scan, since the middle of October" — is fully explained by this.**

### 2.4 Why the obvious fixes are wrong

| Tempting fix | Why it is wrong |
|---------------|-----------------|
| Disable the garbage collector | The object is then never reclaimed; the bucket grows without bound, and the leak is worse than the bug. |
| Raise `--gc-interval` | Turns a systematic failure into a timing race. A scan that takes longer than the interval still fails. |
| Point the scanners at a different bucket | The collector only ever touches `backend.default_bucket_name`. A second bucket would work — but it moves the problem rather than solving it, and the workers download from `"bhunters"` by a key they compute. |
| **Make the object a tracked Karton resource** | **Correct.** A task that carries the resource keeps it alive for exactly as long as the scan needs it, and the collector removes it when the last task that used it finishes. The lifecycle becomes correct rather than suppressed. |

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
