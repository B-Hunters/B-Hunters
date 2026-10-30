# B-Hunters architecture audit

**Scope of this audit.** Every repository in the `B-Hunters` GitHub
organisation was cloned and inspected at the time of writing: the 19
public repositories, their READMEs, dependency manifests, Dockerfiles,
Compose files, worker implementations, configuration, message contracts and
test suites. The audit was performed against the `main` branch of the
framework repository and the default branch of each module repository.

**Method.** The worker modules were read as source, not as documentation.
Karton task contracts were verified against the installed
`karton-core==5.5.0` package (`karton/core/task.py`,
`karton/core/karton.py`, `karton/core/inspect.py`) rather than inferred from
the README. Repository metadata was cross-checked with the GitHub API.

**Status, 2026-10-29.** This audit describes the organisation as it was
before the platform was built. Most of its findings have since been
closed — the API, the console, the scope enforcement, the agent runtime
and the test suite all exist, and the audit's gap numbers no longer
describe the repository. It is kept for the reasoning and the evidence.

The gaps that are still open, with the evidence as measured on
2026-10-29:

| Gap | Still open? | Evidence |
|---|---|---|
| 3.1 No authentication, no API, no UI | Closed | `b_hunters/platform/api/`, `b_hunters/web/` |
| 3.2 No tests anywhere | Closed | 414 tests in 38 modules |
| 3.3 Failed tasks are silently swallowed | Partly | A failed task is still not visible per worker; the participation table is planned, not built |
| 3.4 Private-address guard has gaps | Closed | `b_hunters/platform/security/scope.py` |
| 3.6 Committed credentials | Open | `deploy/*.ini` still carries development credentials |
| 3.7 Unpinned tooling | Open | The worker Dockerfiles are not pinned |
| 3.8 The 69 MB binary | Open | `B-Hunters-xray` still commits it |
| 3.13 No scope enforcement | Closed | Every outbound request goes through `ScopeEnforcer` |
| 3.14 No agent runtime | Closed | `b_hunters/platform/agents/` |

Three gaps this audit did not find, because they are properties of the
platform rather than of the workers, are recorded in
`docs/superpowers/specs/2026-10-29-asset-collection-and-reporting-design.md`
§2: a scan runs in the API process and dies with it; nothing collects
JavaScript URLs or images; and a tool that was cut off is
indistinguishable from a tool that found nothing.

---

## 1. Existing architecture

### 1.1 Repository inventory

The organisation contains 19 repositories. One is the framework, one is a
deployment playground, and 17 are individual scanner workers.

| Repository | Purpose | Language | Karton identity | Task filter (`type`/`stage`) |
|---|---|---|---|---|
| `B-Hunters` | Framework: CLI, shared base class, MongoDB persistence | Python | `B-Hunters-ClI` (producer) | – |
| `B-Hunters-Playground` | Docker Compose deployment | YAML | – | – |
| `B-Hunters-Subrecon` | Subdomain enumeration | Python/Go | `B-Hunters-subrecon` | `domain`/`new` |
| `B-Hunters-NMap` | Port scan | Python | `B-Hunters-Nmap` | `subdomain`/`new` |
| `B-Hunters-gowitness` | Screenshots, headers | Python/Go | `B-Hunters-GoWitness` | `subdomain`/`new` |
| `B-Hunters-Dirsearch` | Directory brute force | Python | `B-Hunters-dirsearch` | `subdomain`/`new` |
| `B-Hunters-ParamSpider` | Parameter discovery | Python | `B-Hunters-ParamSpider` | `subdomain`/`new` |
| `B-Hunters-Wayback` | Historical URLs | Python/Go | `B-Hunters-wayback` | `subdomain`/`new` |
| `B-Hunters-Ffuf` | Fuzzer | Go | `B-Hunters-Ffuf` | `url`/`new`, `path`/`new` |
| `B-Hunters-Katana` | Crawler | Python/Go | `B-Hunters-Katana` | `url`/`new`, `path`/`new`, `subdomain`/`new` |
| `B-Hunters-GetJS` | JavaScript collection | Python/Go | `B-Hunters-getjs` | `url`/`new`, `path`/`new`, `subdomain`/`new` |
| `B-Hunters-Web-Technology` | Technology fingerprinting | Python | `B-Hunters-web-technology` | `url`/`new`, `path`/`new`, `subdomain`/`new` |
| `B-Hunters-jsscanner` | JavaScript secret detection | Python | `B-Hunters-jsscanner` | `js`/`new` |
| `B-Hunters-Nuclei` | Template vulnerability scan | Python/Go | `B-Hunters-Nuclei` | `subdomain`/`new`, `paths`/`scan` |
| `B-Hunters-Sqlmap` | SQL injection | Python | `B-Hunters-SQLMap` | `subdomain`/`new`, `paths`/`scan` |
| `B-Hunters-DalFox` | XSS | Python/Go | `B-Hunters-DalFox` | `paths`/`scan` |
| `b-hunters-SSTI-Checker` | SSTI | Python | `B-Hunters-SSTI-Checker` | `paths`/`scan` |
| `B-Hunters-Wapiti` | Broad web scanner | Python | `B-Hunters-wapiti` | `subdomain`/`new` |
| `B-Hunters-xray` | Active vulnerability scan | Python | `B-Hunters-xray` | `subdomain`/`new` |

### 1.2 Runtime components

```
                      ┌──────────────────────────────┐
   operator ──CLI───▶ │ b-hunters scan / report      │
                      │  (karton Producer)           │
                      └───────────────┬──────────────┘
                                      │ Task {type: domain, stage: new}
                                      ▼
                      ┌──────────────────────────────┐
                      │ Redis (Karton backend)       │
                      │  unrouted → subsystem queues │
                      └───────────────┬──────────────┘
                                      │
        ┌────────────┬────────────┬───┴─────┬─────────────┬──────────────┐
        ▼            ▼            ▼         ▼             ▼              ▼
   subrecon       nmap       dirsearch   katana       nuclei        dalfox
        │            │            │         │             │              │
        │  (subdomain/new)        │         │             │              │
        ▼            ▼            ▼         ▼             ▼              ▼
                      ┌──────────────────────────────┐
                      │ MongoDB                      │
                      │  scans, domains, reports, js │
                      └───────────────┬──────────────┘
                                      │
                      ┌───────────────▼──────────────┐
                      │ MinIO / S3 ("bhunters" bucket)│
                      │  tool artefacts, screenshots  │
                      └──────────────────────────────┘

                      ┌──────────────────────────────┐
                      │ Discord webhooks (outbound)   │
                      └──────────────────────────────┘
```

Infrastructure required by the existing deployment (from
`B-Hunters-Playground/docker-compose.yml`): Redis 6.2 with
`redis-stack-server`, MongoDB, MinIO, `certpl/karton-system:v5.5.0`,
`certpl/karton-dashboard:v1.6.0`, the `bormaa/b-hunters` stuck-task
handler and an `xray` reverse server.

### 1.3 The shared base class

All 17 workers inherit from `b_hunters.bhunter.BHunters`
(`b_hunters/bhunter.py`), which extends `karton.core.Karton` and provides:

* MongoDB connection and a `waitformongo()` retry helper;
* `update_task_status(url, status)` — tracks `status.processing`,
  `status.finished` and `status.failed` arrays per domain;
* `checklinksexist()` — deduplicates discovered links against the scan
  document;
* `send_discord_webhook()` — outbound notifications;
* `is_local_ip()` / `no_resolve_or_local_ip()` — a private-address guard;
* `generate_random_filename()` and `encode_filename()`.

### 1.4 Current scan lifecycle

1. `b-hunters scan -d <domain> -t <single|multi>` inserts a document into
   the `scans` collection and sends a Karton task
   `{"type": "domain", "stage": "new"}` with the persistent payload
   `{domain, scantype, scan_id}`.
2. `B-Hunters-subrecon` consumes it. In `single` mode it creates a
   `reports` document and a `domains` document, then emits
   `{"type": "subdomain", "stage": "new"}` with
   `report_id` (persistent) and `source` payloads. In `multi` mode it
   enumerates subdomains, emits `{"type": "subdomain", "stage": "new"}`
   for live hosts and `{"type": "subdomain", "stage": "takeover"}` for
   unresponsive ones.
3. Nine modules consume `subdomain`/`new` and each writes into the
   `reports` document: `Ports`, `Technology`, `Paths`, `Paths403`,
   `Screenshot`, `Vulns.<tool>` and `data.<tool>`.
4. `Dirsearch` emits `{"type": "path", "stage": "new"}`; `Katana`
   and `ParamSpider` emit `{"type": "paths", "stage": "scan"}`
   and `{"type": "js", "stage": "new"}`.
5. `Nuclei`, `SQLMap`, `DalFox` and `SSTI-Checker` consume `paths`/`scan`
   and append to `Vulns.<tool>`.
6. `b-hunters report -d <domain>` reads `scans` and `domains` from MongoDB
   and pulls the matching artefacts out of the S3 bucket, writing a
   directory tree of JSON and text files.

### 1.5 Karton message contracts

**Headers.** Tasks are routed by `type` and `stage` only. There is no
priority, no deadline and no correlation field beyond what Karton itself
adds (`origin`, `parent_uid`, `root_uid`).

**Persistent payload.** `scan_id` is set persistent on the root task and
inherits down the chain. `report_id` is set persistent by `Subrecon` on the
`subdomain`/`new` tasks.

**Karton inheritance semantics** (verified in `karton/core/task.py`):

```python
def merge_persistent_payload(self, other_task: "Task") -> None:
    for name, content in other_task.payload_persistent.items():
        self.payload_persistent[name] = content
        if name in self.payload:
            del self.payload[name]
```

`Karton.send_task` calls this with the currently handled task. Two
consequences matter:

* the child's `payload_persistent` inherits everything from the parent, so
  `scan_id` survives the whole chain;
* **a non-persistent payload key that collides with an inherited persistent
  key is silently deleted from the child.**

**Observed payload usage across the modules:**

| Key | Read by | Written by | Persistent |
|---|---|---|---|
| `domain` | Dirsearch, GetJS, Wapiti, Wayback, Web-Technology, xray, Subrecon | CLI root task | yes |
| `scan_id` | 13 modules | CLI root task | yes |
| `scantype` | GetJS, Subrecon | CLI root task | yes |
| `report_id` | 15 modules | Subrecon | yes |
| `data` | 14 modules | many | no |
| `subdomain` | 14 modules | Subrecon | no |
| `source` | 13 modules | many | no |
| `file` | jsscanner | Katana | no |

### 1.6 Storage

MongoDB is the only database. Three collections are actively written:

* `scans` — one document per scan (`Domain`, `Type`, `Description`);
* `domains` — one document per discovered host (`Scanid`, `Domain`,
  `report_id`, `resolve`, `active`, `status.{processing,finished,failed}`);
* `reports` — one document per host (`Domain`, `Ports`, `Technology`,
  `Vulns`, `Paths`, `Paths403`, `Screenshot`, `data`);
* `js` — one document per JavaScript asset (`report_id`, `domain`, `url`,
  `Vulns`).

Large artefacts (screenshots, raw tool output) live in MinIO/S3 under the
`bhunters` bucket, keyed `<source>_<scan_id>_<encoded filename>`.

**There is no API, no web UI, no authentication, no user model and no
agent runtime.** The framework README lists "Create Web Interface" under
*Future Plan*.

---

## 2. Tool inventory

Versions are those actually resolved by the module Dockerfiles. **Every
tool is installed with `@latest`**, so the table records the version that
was current when the image was built, not a pinned version.

| Capability | Tool | Version source | Pinned? | Container base | License | Maintenance |
|---|---|---|---|---|---|---|
| Subdomain enumeration | subfinder, assetfinder, chaos, httpx, vita 0.1.16, findomain, Sublist3r | `go install @latest`, release tarball | No | `ubuntu:latest` | mixed | mixed |
| Port scan / service detection | nmap | apt | No | `python:3.10-slim` | GPL-2.0 | maintained |
| Screenshots | gowitness + chromium | `go install @latest` | No | `golang:1.23-bookworm` | MIT | maintained |
| Directory brute force | dirsearch | PyPI | No | `python:3.10-slim` | GPL-2.0 | maintained |
| Parameter discovery | ParamSpider (bormaa fork) | git clone | No | `python:3.12-slim` | MIT | maintained |
| Historical URLs | waybackurls, gau, waymore | `go install @latest`, pip VCS | No | `python:3.12-slim` | MIT | mixed |
| Crawling | katana, gf, qsreplace | `go install @latest` | No | `python:3.12-slim` | MIT | maintained |
| Crawling | katana | `go install @latest` | No | `python:3.12-slim` | MIT | maintained |
| JS collection | getJS | `go install @latest` | No | `python:3.12-slim` | MIT | maintained |
| Technology detection | wappalyzer-cli | pip VCS | No | `python:3.10-slim` | MIT | maintained |
| JS secret detection | SecretFinder | git clone | No | `python:3.12-slim` | MIT | maintained |
| Template vuln scan | nuclei + nuclei-templates | `go install @latest`, git clone | No | `python:3.12-slim` | MIT | maintained |
| SQL injection | sqlmap | git clone | No | `python:3.10-slim` | GPL-2.0 | maintained |
| XSS | dalfox, qsreplace | `go install @latest` | No | `python:3.12-slim` | MIT | maintained |
| SSTI | SSTImap + extras | git clone | No | `python:3.10-slim` | GPL-3.0 | maintained |
| Broad web scan | wapiti3 | PyPI | No | `python:3.11` | GPL-2.0 | maintained |
| Active vuln scan | xray | committed 69 MB binary | **Binary in git** | `python:3.10-slim` | unknown | unknown |
| Screenshot / headers | gowitness | see above | No | | | |
| URL utilities | uro, gf, qsreplace | `pip install uro`, `go install @latest` | No | | | |

### 2.1 Dependency graph

```
B-Hunters (framework, pip: b-hunters)
├── b_hunters/bhunter.py  ──► karton-core==5.5.0
│                              pymongo, tldextract, requests, colorama
├── b_hunters/cli.py      ──► karton-core, pymongo, colorama
└── b_hunters/platform/   ──► fastapi, uvicorn, httpx, pydantic,
                            argon2-cffi, jsonschema            (new)

B-Hunters-Subrecon ──► b-hunters==1.1.13 (PyPI!)  + subfinder/assetfinder/chaos/httpx/vita/findomain/Sublist3r
B-Hunters-NMap     ──► b-hunters==1.1.16 (PyPI!)  + nmap
B-Hunters-Nuclei   ──► b-hunters==1.1.13 (PyPI!)  + nuclei/httpx/uro
B-Hunters-DalFox   ──► b-hunters==1.1.16 (PyPI!)  + dalfox/qsreplace/uro
B-Hunters-Dirsearch──► b-hunters==1.1.13 (PyPI!)  + dirsearch
B-Hunters-GetJS    ──► b-hunters==1.1.13 (PyPI!)  + getJS
B-Hunters-Ffuf     ──► b-hunters==1.3.0 (PyPI!)  + ffuf
B-Hunters-gowitness──► b-hunters==1.1.13 (PyPI!)  + gowitness
B-Hunters-jsscanner──► b-hunters==1.1.13 (PyPI!)  + SecretFinder/anew/nipejs
B-Hunters-Katana   ──► b-hunters==1.1.13 (PyPI!)  + katana
B-Hunters-ParamSpider─► b-hunters==1.1.13 (PyPI!) + ParamSpider
B-Hunters-Sqlmap   ──► b-hunters==1.1.13 (PyPI!)  + sqlmap/qsreplace/uro
B-Hunters-SSTI-Checker─► b-hunters==1.1.13 (PyPI!) + SSTImap/qsreplace/uro
B-Hunters-Wapiti   ──► b-hunters==1.1.16 (PyPI!)  + wapiti3
B-Hunters-Wayback  ──► b-hunters==1.1.13 (PyPI!)  + waybackurls/gau/anew/waymore
B-Hunters-Web-Technology─► b-hunters==1.1.13 (PyPI!) + wappalyzer-cli
B-Hunters-xray     ──► b-hunters==1.1.16 (PyPI!)  + xray (committed binary)

B-Hunters-Playground ──► certpl/karton-system:v5.5.0, certpl/karton-dashboard:v1.6.0,
                           bormaa/b-hunters:latest, bormaa/xray:latest,
                           mongo:latest, minio/minio, redis/redis-stack-server:6.2.6-v12
```

**Every worker installs `b-hunters` from PyPI, not from the repository.**
The framework repository is at version `1.1.15`; the workers pin
`1.1.13` or `1.1.16`; PyPI's latest is `1.1.16`. A change to
`b_hunters/bhunter.py` in the repository therefore **does not reach the
workers** until a new release is published and every Dockerfile is bumped.
This is the single most important structural constraint on the project.

### 2.2 Component compatibility matrix

| Component | Requires | Python | Karton | MongoDB | Redis | MinIO | Status |
|---|---|---|---|---|---|---|---|
| `b-hunters` framework | `karton-core==5.5.0` | ≥3.8 | 5.5.0 | any | any | for S3 | working |
| Worker base class | `karton-core` via PyPI | ≥3.8 | 5.5.0 | any | any | for S3 | working |
| Karton system | `certpl/karton-system:v5.5.0` | – | 5.5.0 | – | 6.2+ | – | working |
| Karton dashboard | `certpl/karton-dashboard:v1.6.0` | – | 5.x | – | 6.2+ | – | working, external UI only |
| `b-hunters` CLI | `karton-core`, `pymongo` | ≥3.8 | 5.5.0 | 4.x | 6.2+ | – | working |
| Report generator | `boto3` (via karton) | ≥3.8 | 5.5.0 | 4.x | – | S3 API | working |

---

## 3. Confirmed gaps and the evidence for each

Each gap below was confirmed by reading the source, not inferred from the
absence of a feature.

### 3.1 No authentication, no API, no UI

*Evidence.* `b_hunters/` contains exactly four modules: `cli.py`,
`bhunter.py`, `__init__.py`, `__version__.py`. The CLI exposes `scan`,
`report` and `status`. The README lists "Create Web Interface" under
*Future Plan*. The only web interface in the deployment is the external
`certpl/karton-dashboard`, which shows Karton task state and has no notion
of scans, findings, users or agents.

*Consequence.* Every capability the platform needs — creating a scan with
a validated scope, reviewing findings, administering model providers —
has no surface at all.

### 3.2 No tests anywhere in the organisation

*Evidence.* A search of all 19 repositories for `test_*.py`, `*_test.py`,
`tests/` or `conftest.py` returns **zero** files. There is no CI
configuration in any repository.

*Consequence.* Regressions are undetectable. Several of the defects below
are exactly the kind that a single unit test would have caught.

### 3.3 Failed tasks are silently swallowed

*Evidence* (`b_hunters/bhunter.py`, `update_task_status`):

```python
if status=="failed":
    raise Exception(f"Failed to process {url}")
```

The method is called with `"Failed"` (capital F) from all 17 workers. The
comparison never matches, so the exception is never raised and Karton
records a failed task as successfully finished. The `status.failed` array
is still populated, so the data looks right while the orchestration is
wrong — the scan appears to complete.

### 3.4 Private-address guard has gaps

*Evidence* (`b_hunters/bhunter.py`, `is_local_ip`): the guard matches
string prefixes `"127."`, `"192.168."`, `"10."` and `"172.16."` …
`"172.31."`. It does **not** cover:

* `169.254.0.0/16` — link-local, which includes the cloud metadata
  endpoint `169.254.169.254`;
* `100.64.0.0/10` — carrier-grade NAT;
* `0.0.0.0/8`, multicast and reserved ranges;
* IPv6 equivalents (`::1`, `fc00::/7`, `fe80::/10`).

The guard is also applied *before* DNS resolution and only to the
subdomain name, so a hostname that resolves to a private address after
the check is not caught by the prefix list.

### 3.5 Configuration path is hard-coded in the workers

*Evidence.* `BHunters.__init__` uses `Config(path="/etc/b-hunters/b-hunters.ini")`.
The CLI's `--config` flag therefore only affects the CLI; a worker
container cannot be pointed at a different configuration file.

### 3.6 Committed credentials and an over-permissive artefact bucket

*Evidence.*

* `B-Hunters-Playground/.env` is committed and contains the actual values
  the Compose file uses (`MINIO_SECRET_KEY=B-Hunter-Secret`,
  `REDIS_PASS=B-Hunter-Redis`, `MONGO_PASS=MongoPass`).
* `B-Hunters-Playground/docker-compose.yml` sets the `recon` bucket policy
  to **public**: `mc policy set public myminio/recon`.
* Redis, MongoDB and MinIO are published on host ports without a loopback
  restriction.

*Consequence.* A deployment that copies the playground as-is exposes the
artefact bucket and the data stores to the network.

### 3.7 Unpinned tooling and base images

*Evidence.* Every Go tool is installed with `go install …@latest`;
`nuclei-templates`, `SecretFinder`, `sqlmap` and `SSTImap` are cloned from
the default branch; base images are `ubuntu:latest`, `mongo:latest`,
`python:3.10-slim`, `python:3.11`, `python:3.12-slim`,
`golang:1.21.1`, `golang:1.23-bookworm`.

*Consequence.* Two builds of the same commit are not the same software.
The benchmark cannot be reproduced, and a compromised upstream release is
picked up silently.

### 3.8 A 69 MB binary committed to the repository

*Evidence.* `B-Hunters-xray/xray/xray` is a 69,682,828-byte stripped ELF
executable checked into git, with no provenance record or checksum.

### 3.9 Orphaned task types

*Evidence.* `Katana`, `ParamSpider` and `Wayback` each emit a
task with `{"type": "file"}`. No module filters on `type=file`. The
`jsscanner` module *reads* `task.payload["file"]` but filters on
`{"type": "js", "stage": "new"}`. These `file` tasks are routed to a queue
that no consumer ever binds to.

Similarly, `Subrecon` emits `{"type": "subdomain", "stage": "takeover"}` in
`multi` mode. No module filters on `stage=takeover`.

### 3.10 Status tracking is recorded against the wrong key

*Evidence.* `jsscanner` calls `self.update_task_status(url, "Started")`
where `url` is the **JavaScript asset URL**, but `update_task_status`
writes to the `domains` collection keyed by `Domain`. The update matches
no document, so JavaScript analysis never appears in the per-domain
status. Four modules (`Dirsearch`, `GetJS`, `Wapiti`, `Wayback`,
`Web-Technology`, `xray`) record their status against the persistent
`domain` payload — the *root* domain — rather than the `subdomain` they
are actually processing.

### 3.11 Discord webhook failure mode

*Evidence.* `send_discord_webhook` reads `self.config["Webhook"]` without
a guard, so a configuration file without a `[Webhook]` section raises
`KeyError` inside every worker. The `requests.post` call has no timeout,
so an unresponsive Discord endpoint blocks the worker indefinitely.

### 3.12 Deprecated packaging

*Evidence.* `b_hunters/__init__.py` contains
`__import__('pkg_resources').declare_namespace(__name__)`. `pkg_resources`
is deprecated and removed in setuptools ≥ 81; the package cannot be
imported on a modern setuptools.

### 3.13 No scope enforcement

*Evidence.* `is_local_ip` is the only guard, and it is applied to
subdomain names by the reconnaissance worker only. No HTTP-capable worker
validates that the host it is about to contact is one the operator
authorised. Crawled links are followed without a scope check. Redirects
are not validated. There is no rate limit, no concurrency limit, no
response-size limit and no scan-duration limit.

*Consequence.* A scan of `example.com` that discovers
`internal.corp.example.com` will follow it.

### 3.14 No agent runtime, no model integration

*Evidence.* No repository contains a model client, a prompt, an agent
loop, a tool interface or a finding schema.

---

## 4. Proposed architecture

The target architecture extends the existing framework rather than
replacing it. The Karton workers keep their identity, their task filters
and their result format; the platform adds an authenticated API, an agent
runtime and an operational UI around them.

```
                    ┌──────────────────────────────────────────┐
   operator ───────▶│  Web UI (vanilla ES-module SPA)          │
                    │  dashboard · create scan · live monitor   │
                    │  findings · agent workspace · admin       │
                    └───────────────────┬──────────────────────┘
                                        │ REST + SSE
                    ┌───────────────────▼──────────────────────┐
                    │  FastAPI application                       │
                    │  ┌────────────┐ ┌──────────┐ ┌─────────┐ │
                    │  │ auth (argon│ │ scans    │ │ karton  │ │
                    │  │ + session  │ │ findings │ │ monitor │ │
                    │  │ + CSRF)    │ │ exports  │ │         │ │
                    │  └────────────┘ └──────────┘ └─────────┘ │
                    └───────┬──────────────────────┬───────────┘
                            │                      │
             ┌──────────────▼──────────┐   ┌───────▼──────────────┐
             │  Orchestrator            │   │  Scope enforcement    │
             │  plan → dispatch →       │   │  host allow-list,     │
             │  verify → adjudicate      │   │  IP range checks,     │
             └───┬───────────┬──────────┘   │  redirect validation, │
                 │           │              │  rate/size/duration   │
      ┌──────────▼───┐  ┌────▼────────────┐ └───────┬──────────────┘
      │ Agent runtime │  │ Scanner adapters │         │
      │ 13 roles      │  │ 23 adapters      │◀────────┘
      │ provider      │  │ 17 Karton        │
      │ tool gateway  │  │  6 native        │
      └───────┬───────┘  └────┬────────────┘
              │                │
    ┌─────────▼────────┐  ┌───▼──────────┐  ┌──────────────┐
    │ OpenAI-compatible│  │ Redis (Karton│  │  MongoDB     │
    │ chat completions │  │ backend)     │  │  scans, tasks│
    └──────────────────┘  └──────┬───────┘  │  findings,   │
                                   │          │  events, users│
                          ┌────────▼─────────┴──────────────┐
                          │  17 existing Karton workers    │
                          │  (unchanged identities)        │
                          └────────────────────────────────┘
```

### 4.1 Design decisions

**Keep MongoDB.** The instruction is to inspect the current persistence
layer before introducing another database, and the existing layer is
MongoDB with three actively written collections. The platform adds
namespaced collections (`platform_*`) and leaves `scans`, `domains`,
`reports` and `js` untouched so that the existing workers and the
`report` command keep working.

**Keep the Karton workers as they are.** Every worker keeps its identity
and its filters. The platform reaches them through the real Karton
producer, so a scan started from the UI uses exactly the same code path as
a scan started from the CLI.

**Zero-build frontend.** The repository is pure Python with no JavaScript
toolchain and no CI. Adding a Node build would introduce a second build
system for no functional gain. The UI is an ES-module SPA served
directly by FastAPI: no bundler, no `node_modules`, no build cache.

**Provider abstraction, not a vendor SDK.** The provider layer speaks the
OpenAI `chat/completions` contract over plain `httpx`. Native tool
calling is probed at runtime; when an endpoint does not support it, a
compatibility layer asks the model to emit a JSON tool call and validates
it against the *same* schema and the *same* permission checks.

**Custom agent runtime rather than an off-the-shelf coding agent.** The
requirements that actually drive this decision are: the tool gateway must
enforce scope and permissions; the agent must not receive an unrestricted
host shell; the collaboration protocol must be structured; and the audit
trail must record conclusions and evidence rather than model
chain-of-thought. A general-purpose coding agent is built for editing a
repository on a developer machine, which is the opposite of what a
scanning agent needs. The runtime is ~450 lines and depends only on
`httpx`.

### 4.2 Package layout

```
b_hunters/
├── bhunter.py               # existing base class, with the defects fixed
├── cli.py                   # existing CLI, extended with serve/admin/bench
└── platform/
    ├── settings.py          # environment + legacy INI configuration
    ├── db/
    │   ├── client.py        # MongoDB connection, indexes, retention
    │   └── repositories.py   # domain repositories
    ├── security/
    │   ├── scope.py         # the scope enforcement layer
    │   ├── redact.py        # secret redaction
    │   ├── passwords.py     # argon2id hashing
    │   └── sessions.py      # sessions and CSRF
    ├── agents/
    │   ├── provider.py      # OpenAI-compatible client
    │   ├── compat.py        # tool-calling compatibility layer
    │   ├── roles.py         # the 13 agent roles
    │   ├── schemas.py       # structured message and finding contracts
    │   ├── runtime.py       # the bounded agent loop
    │   ├── collaboration.py # the structured collaboration protocol
    │   └── orchestrator.py  # the scan orchestrator
    ├── tools/
    │   ├── gateway.py       # permission, scope and budget enforcement
    │   └── builtin/         # http, files, shell, parsing, scan queries
    ├── scanners/
    │   ├── base.py          # the scanner adapter interface
    │   ├── registry.py      # the 23 adapters
    │   └── native.py        # the 6 in-process adapters
    ├── bench/
    │   ├── manifest.py      # the vulnerable application manifests
    │   ├── lab.py           # the isolated laboratory
    │   ├── runner.py        # the benchmark runner
    │   └── scoring.py       # precision, recall, F1 and the rest
    └── api/
        ├── app.py           # the FastAPI application
        ├── deps.py          # authentication and role dependencies
        └── routers/         # auth, scans, findings, karton, admin,
                             # dashboard, benchmarks
```

---

## 5. Migration plan

The plan is ordered so that each milestone leaves the system working.

### Milestone 1 — Audit *(this document)*

Establish the baseline: repository map, Karton contract inventory, tool
inventory, dependency graph, compatibility matrix, confirmed gap list.

### Milestone 2 — Core infrastructure

* Add the `b_hunters.platform` package.
* Fix the four defects in the shared base class (failed-task swallowing,
  the private-address guard, the hard-coded configuration path, the
  webhook guard) — these reach all 17 workers because they inherit from
  it.
* Add the scope enforcement layer and make it the only path to the
  network.
* Add the authenticated API, the persistence layer and the Karton
  monitoring endpoints.
* Keep `scan`, `report` and `status` working exactly as before.

### Milestone 3 — UI

Build the authenticated dashboard, the create-scan form with server-side
scope validation, the live scan monitor over SSE, the findings browser,
the agent workspace and the administration pages.

### Milestone 4 — Agent runtime

Add the provider abstraction, the 13 agent roles, the tool gateway, the
collaboration protocol, the independent verification workflow and the
orchestrator.

### Milestone 5 — Scanner integration

Introduce the scanner adapter interface and register the 17 existing
Karton workers against it. Add the 6 native adapters for the capabilities
the existing modules do not cover.

### Milestone 6 — Benchmark laboratory

Bring up the isolated vulnerable applications, write the manifests, build
the runner and the scoring.

### Milestone 7 — Quality

Unit, integration, security, end-to-end and benchmark tests; linting;
CI.

### Milestone 8 — Documentation

Threat model, configuration reference, deployment guide, benchmark guide
and the operator runbook.

### Compatibility commitments

* The legacy `scan`, `report` and `status` commands keep their flags,
  their output and their storage layout.
* The legacy MongoDB collections are not migrated or renamed.
* The workers' Karton identities, filters and payload keys are unchanged.
* The INI configuration file is still read for the infrastructure
  coordinates it carries.
* The `b-hunters` package name, the console-script entry point and the
  `b_hunters.bhunter.BHunters` import path are unchanged.

### Known migration caveat

The workers install `b-hunters` from PyPI. The base-class fixes in
milestone 2 therefore only reach a worker once a new release is published
and the 17 Dockerfiles are bumped from `1.1.13`/`1.1.16` to that
release. Until then the workers run the old base class. This is called out
again in `docs/deployment.md`, and the Dockerfile change is mechanical: one
version string per repository.
