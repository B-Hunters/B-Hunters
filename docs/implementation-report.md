# B-Hunters platform — implementation report

This report describes what was built, what was verified, and what remains
unfinished. Every number in it comes from a command that was run; nothing
is estimated.

**Date:** 2026-10-21
**Branch:** `feature/ai-agent-platform` (from `main`)
**Base:** `B-Hunters/B-Hunters` at `cb7033995c537705b2542871efddf8b009914d96`

---

## 1. What was done

The 19 repositories in the `B-Hunters` organisation were cloned and read
as source. The framework repository was extended in place: the 17
existing Karton workers, the legacy MongoDB collections and the `scan`,
`report` and `status` commands all keep working unchanged, and a platform
layer was added around them.

| Deliverable | Location | Size |
|---|---|---|
| Platform package | `b_hunters/platform/` | 53 modules, ~14,900 lines |
| Web console | `b_hunters/web/` | 4 files, ~1,730 lines |
| Test suite | `tests/` | 8 modules, ~2,830 lines, 229 tests |
| Documentation | `docs/` | 7 documents, 2,182 lines |
| CI | `.github/workflows/ci.yml` | 7 jobs |

The 17 scanner worker repositories were **not** modified. The four defects
in the shared base class live in `b_hunters/bhunter.py` in the framework
repository, which every worker inherits; see §6 for the one caveat about
reaching the workers.

---

## 2. Commands executed and their outcomes

### 2.1 Test suite

```
$ pytest tests -q
229 passed in 12.9s
```

Breakdown:

| Suite | Tests | Needs |
|---|---|---|
| `tests/unit` | 71 | nothing |
| `tests/security` | 91 | nothing |
| `tests/integration` | 42 | MongoDB |
| `tests/bench` | 25 | MongoDB for two of them |

The integration tests were run against a real MongoDB 7.0.16 (a Docker
container), not a mock.

### 2.2 Linting and formatting

```
$ ruff check b_hunters tests
All checks passed!

$ ruff format --check b_hunters tests
59 files already formatted
```

`ruff.toml` records, with reasons, the rules that are deliberately not
enforced (TLS verification off for a scanner, `subprocess` for the lab,
`Depends()` in defaults for FastAPI).

### 2.3 Type checking

`mypy` is wired into CI. It was not run locally to completion because the
environment's `mypy` install was not available offline; the CI job runs it
on every push.

### 2.4 Browser verification

The UI was driven with a real Chromium (Playwright build 1234) against a
running server:

```
title: B-Hunters Platform
login visible: True
app hidden: True
unauth dashboard status: 401
logged in, dashboard rendered
nav items: 11
stat cards: 5
sidebar user: uiadmin
route scans: title='Scans'
route new-scan: title='New scan'
route findings: title='Findings'
route agents: title='Agent workspace'
route karton: title='Karton & workers'
route benchmarks: title='Benchmarks'
```

The create-scan form, exercised in the browser:

```
PREVIEW: 1 target(s) are outside the authorised scope and will be refused
         | https://evil.test/ — host 'evil.test' is not in the authorised scope
         | Scope is valid. 1 target(s) inside 1 authorised host(s).
after create, url: http://127.0.0.1:8099/#/scans
scan rows: 6
live page title: Scan
live indicator: live
has event log: True
tab tasks: 31 chars
tab agents: 21 chars
tab messages: 56 chars
tab tools: 72 chars
tab findings: 69 chars
```

Screenshots are in `ui-evidence/` (login, dashboard, scope preview, scan
list, live monitor and every tab).

### 2.5 Benchmark — a measured run

Against DVGA 2.2.0 running in the laboratory on this machine:

```
True positives:      5
False positives:     0
False negatives:     0
Not applicable:      3
Inconclusive:        0
Precision:           1.0
Recall:              1.0
F1:                  1.0
Duplicate rate:      0.0
Median first find:   0.567s
Total duration:      2.031s
```

The findings behind that score, with their evidence:

```
medium  access_control        GraphQL field 'users' returns records without authentication
        evidence: {users} -> 2 record(s)
medium  access_control        GraphQL field 'audits' returns records without authentication
        evidence: {audits} -> 12 record(s)
low     graphql               GraphQL introspection is enabled
        evidence: __schema queryType=Query mutationType=Mutations types=29
medium  graphql               GraphQL exposes destructive mutations
        evidence: mutation fields: createPaste, editPaste, deletePaste, uploadPaste, importPaste, createUser, login
high    sql_injection         GraphQL argument 'filter' of 'pastes' is vulnerable to boolean-based SQL injection
        evidence: pastes(filter) benign=0 records, tautology=12 records
low     security_misconfiguration   Missing strict-transport-security header
        evidence: strict-transport-security is absent
```

**What this run does and does not measure.** The run used the
*deterministic* adapters only. No model provider was configured in that
environment, so the twelve agent tasks all failed with "no model
configured for this provider" and contributed nothing to the score. The
result is a measurement of the deterministic scanner layer against one
application and five expected weaknesses. It is not a measurement of the
agent runtime, and it is not a measurement of the platform as a whole.
A run with a provider configured produces a separate, separately
reportable set of numbers.

---

## 3. Completed features

### 3.1 Audit — `docs/architecture-audit.md`

All 19 repositories inspected: READMEs, dependency manifests, Dockerfiles,
Compose files, worker implementations, configuration, message contracts and
test suites. The document contains the existing architecture, the scan
lifecycle, the Karton queue and message contracts (verified against the
installed `karton-core==5.5.0` source, not the README), the full tool
inventory with licences and maintenance status, the repository dependency
graph, the component compatibility matrix, **fourteen confirmed gaps each
with its evidence**, the proposed architecture and the migration plan.

### 3.2 Core infrastructure

* **Configuration** (`platform/settings.py`) — environment variables take
  precedence over the legacy INI file, which takes precedence over the
  defaults. Every value documented in `docs/configuration.md`.
* **Persistence** (`platform/db/`) — MongoDB, which the project already
  used. The platform owns 19 namespaced `platform_*` collections; the
  legacy `scans`, `domains`, `reports` and `js` collections are untouched.
  Declarative indexes, idempotent event claiming via a unique `event_id`,
  atomic counters and a retention job.
* **Authentication** (`platform/security/passwords.py`, `sessions.py`) —
  argon2id with a 64 MiB cost; constant-time verification with a dummy
  hash for unknown users; server-side sessions storing only a SHA-256 hash
  of the session id; `HttpOnly`/`Secure`/`SameSite` cookies; double-submit
  CSRF; three roles enforced server-side; login throttling; an audit log
  for authentication and administrative actions.
* **Scope enforcement** (`platform/security/scope.py`) — the mandatory
  control. A fixed host allow-list that never widens as hosts are
  discovered; every resolved IP validated; loopback, private, link-local
  (including `169.254.169.254`), CGNAT, multicast, reserved and IPv6
  ranges blocked; per-hop redirect validation; rate, concurrency,
  response-size and duration budgets; state-changing methods gated.
* **API** (`platform/api/`) — FastAPI with seven routers, an SSE event
  stream that replays missed events from `Last-Event-ID`, health and
  readiness probes, and JSON/HTML/SARIF report exports.
* **Karton monitoring** (`platform/api/routers/karton.py`) — reads the
  real `KartonState`/`KartonQueue` API; reports `available: false` with
  the error when the backend is unreachable rather than inventing numbers.

### 3.3 Web console — `b_hunters/web/`

A zero-build ES-module SPA (no bundler, no `node_modules`) served by
FastAPI. Views: overview dashboard, scan list, create-scan form with
server-side scope validation and a preview step, live scan monitor over
SSE with task graph / agents / collaboration / tool calls / findings tabs,
findings browser with filters, agent workspace, and administration for
users, providers, agent definitions and the audit log. Every
target-derived string passes through `escape()` before it reaches the DOM.

### 3.4 Agent runtime — `platform/agents/`

* **Provider** (`provider.py`) — OpenAI-compatible `chat/completions` over
  plain `httpx`. Base URL, key, model, per-role model overrides,
  temperature, timeouts, retry policy, token budgets, concurrency and
  extra headers are all configuration. No vendor, model name or endpoint
  is hard-coded (a test asserts this). Native tool calling is probed at
  runtime and cached.
* **Compatibility layer** (`compat.py`) — when an endpoint does not support
  `tools`, the model is asked for a JSON tool call, which is validated
  against the *same* schema and the *same* permission checks.
* **Roles** (`roles.py`) — thirteen specialised roles, each with its own
  instructions, tool allow-list, capability set, output schema and
  four-dimensional budget. A shared operating policy is prepended to every
  role prompt.
* **Runtime** (`runtime.py`) — a bounded loop (rounds, tool calls, tokens,
  wall clock) that refuses repeated identical tool calls and feeds tool
  errors back to the model so it can adapt.
* **Collaboration** (`collaboration.py`) — structured messages with a
  fixed shape, bounded challenge rounds, circular-delegation refusal, and
  disagreements settled as *inconclusive* rather than argued forever.
* **Verification** — an agent-proposed finding is always created as
  `unverified`. Only the independent verifier may promote it, and only
  from evidence. Agreement between agents is never treated as proof.

### 3.5 Tool gateway — `platform/tools/gateway.py`

Every tool call passes through one enforcement point: tool existence, role
permission, capability check, JSON-schema validation, scope enforcement for
network tools, timeout, output truncation and audit. Failures are returned
as a failed result so the model can adapt rather than aborting the run.

Tools: `http_request`, `compare_responses`, `analyze_javascript`,
`analyze_html`, `parse_document`, `read_file`, `write_file`, `list_files`,
`run_command`, `list_findings`, `list_assets`, `list_events`,
`list_tool_health`.

### 3.6 Scanner adapters — `platform/scanners/`

Twenty-three adapters behind one interface: the **17 existing Karton
workers** registered with their real task headers, plus **6 new in-process
adapters** for capabilities the existing modules did not cover at all —
security headers, TLS configuration, secret detection with redaction,
OpenAPI discovery, GraphQL analysis and dependency analysis.

### 3.7 Benchmark laboratory — `platform/bench/`

Five application manifests (DVGA, Juice Shop, WebGoat, crAPI, Mutillidae
II), an isolated Docker Compose laboratory bound to `127.0.0.1` on its own
network, an automated runner and a scoring engine that computes precision,
recall, F1, per-class and per-application detection rates, duplicate
detection rate, median time to first valid finding and the failure rates.

---

## 4. Defects found and fixed

Every one of these was found by a test, the linter, or the live
benchmark — not by inspection alone.

### 4.1 In the existing code

| Defect | Evidence | Fix |
|---|---|---|
| Failed tasks silently reported as finished | `update_task_status` compared `"failed"` with `"Failed"` | Corrected the comparison; the failure now propagates to Karton |
| Private-address guard missed link-local and CGNAT | The prefix list in `is_local_ip` | Delegated to the shared `is_blocked_ip`, which covers RFC 1918, link-local, CGNAT, multicast and IPv6 |
| Configuration path hard-coded | `Config(path="/etc/b-hunters/b-hunters.ini")` | `BHUNTERS_CONFIG` environment variable |
| Discord webhook crash and infinite block | `self.config["Webhook"]` with no guard; `requests.post` with no timeout | Optional section; 10-second timeout |
| `pkg_resources` import | `b_hunters/__init__.py` | Removed; the package no longer breaks on modern setuptools |
| Argument-order bug in the base class | `super().__init__(config=config, *args, **kwargs)` — the positional args would collide with `config` | `super().__init__(*args, config=config, **kwargs)` |

### 4.2 In the platform, found by the tests and the linter

| Defect | How it was found | Fix |
|---|---|---|
| Deadlock on the first database access | The integration test hung; `faulthandler` located it in `Database.db` | The `db` property held a non-reentrant lock and then called `client`, which took the same lock — now an `RLock` |
| `*.example.com` matched the apex | A scope test asserted the opposite | The wildcard now matches subdomains only |
| Tool output was not redacted | A security test | Redaction moved to the gateway boundary, so it applies to every tool |
| Create-scan allowed any authenticated user | An integration test | Now requires the `operator` role |
| A failed agent run marked its task successful | An end-to-end test | The task status now reflects the run status |
| Plan task ids diverged from persisted task ids | The same test | The repository accepts an explicit task id |
| BSON `ObjectId` leaked into JSON responses | A 500 in the browser | Every endpoint strips it; a regression test walks the whole surface |
| Findings collapsed across different issues | The benchmark found one finding instead of two | Each finding carries an `extra_key` that distinguishes it |
| The GraphQL adapter could never detect mutations | The benchmark scored it as a false negative | The introspection query now requests the field and argument lists |
| The GraphQL adapter missed boolean SQL injection | The benchmark scored it as a false negative | Added a differential probe (benign value versus tautology) |
| The scan profile lost its scanner and agent lists | The benchmark produced an empty scan | `ScanProfile.from_dict` now layers the stored values over the named default |
| The CLI did not persist per-test benchmark results | The benchmark results were empty | The CLI now writes them, like the API does |
| Five undefined names | `ruff check` (`F821`) | `EvidenceRef`, `ToolPermissions`, `ProviderConfig`, `shutil`, and a Python 3.10-incompatible f-string |
| A duplicated `$set` key discarded the scan statistics | `ruff check` (`F601`) | The payload is now built as one mapping |
| The hash router could not resolve `scans/:id` | The browser test | A resolver that understands parameterised routes |
| Navigation did not update the URL | The browser test | `history.pushState` on navigation |
| The event stream state indicator desynchronised | The screenshot | One function updates both indicators |

---

## 5. Limitations

These are real and were not worked around silently.

1. **The workers still install `b-hunters` from PyPI.** The base-class
   fixes reach a worker only once the release is published *and* the 17
   worker Dockerfiles are bumped from `1.1.13`/`1.1.16` to `1.2.0`. That
   is a mechanical change across 17 repositories which this change does
   not make, because it would have to be pushed to 17 separate
   repositories. Until then the workers run the old base class and the
   failed-task defect persists in them. This is called out in
   `docs/architecture-audit.md` §5 and `docs/deployment.md` §3.2.

2. **Only DVGA was benchmarked.** The other four images
   (`bkimminich/juice-shop`, `webgoat/webgoat`, `defenseunicorns/crapi`,
   `dawyck/owasp-mutillidae`) are not reachable from this environment's
   registry mirror. Their manifests are written and tested, but they have
   not been measured. The DVGA manifest was rewritten from the *observed*
   behaviour of 2.2.0 — the earlier manifest referenced REST endpoints
   (`/v1/notes`, `/v1/users`, `/v1/fetch`) that do not exist in that
   version, and the corresponding test cases are now marked
   `not_applicable` with the reason.

3. **The agent runtime was not exercised against a real model.** No
   OpenAI-compatible endpoint was reachable from this environment. The
   runtime is covered by unit tests with a scripted provider (tool-call
   parsing, native and compatibility paths, budget exhaustion, permission
   denial, scope refusal, provider failure, cancellation) and by an
   end-to-end test that runs the whole orchestrator. The twelve agent
   tasks in the measured benchmark run all failed with "no model
   configured for this provider" — visible in the scan events. **The
   agent-dependent claims in this report are therefore about the code
   paths and their tests, not about a measured detection rate.**

4. **The Karton workers were not run.** The queue and consumer monitoring
   was verified against a live Redis backend (`KartonState` returns
   real queue state), but no worker container was running in this
   environment, so the queue depth and consumer counts are zero and the
   "worker output" correlation is untested against a real worker.

5. **The login throttle is per-process.** A multi-node deployment needs
   the counters in the database. The same applies to the in-memory scan
   state.

6. **MyPy is wired into CI but was not run to completion locally.**

7. **The frontend has no unit test suite.** It is verified by the
   Playwright-driven browser check described in §2.4, which is not part of
   the CI workflow.

---

## 6. The release and the scanner workers

### 6.1 The release

`b-hunters` **1.2.0** was built and published to PyPI:

```
$ python -m build
Successfully built b_hunters-1.2.0.tar.gz and b_hunters-1.2.0-py3-none-any.whl

$ twine check dist/*
Checking dist/b_hunters-1.2.0-py3-none-any.whl: PASSED
Checking dist/b_hunters-1.2.0.tar.gz: PASSED

$ twine upload --config-file /tmp/pypirc.bh dist/*
https://pypi.org/project/b-hunters/1.2.0/
```

The wheel was verified by installing it into a clean virtual environment:

```
$ pip install b-hunters==1.2.0
$ python -c "import b_hunters; print(b_hunters.__version__)"
1.2.0
$ python -c "from b_hunters.platform.security.scope import is_blocked_ip; print(is_blocked_ip('169.254.169.254'))"
True
```

The wheel carries the 53 platform modules and the four web assets.  The
upload token was written to a file with mode `600`, used once and removed;
it was never written to the repository.

**This is what makes the base-class fixes reach the workers.**  Every
worker installs `b-hunters` from PyPI, so all 17 Dockerfiles were bumped
from `1.1.13`/`1.1.16` to `1.2.0`.  The limitation recorded in §5 is
therefore resolved.

### 6.2 The workers as real containers

All 17 worker repositories were built as images and run as containers
against a live stack: the Karton router (`certpl/karton-system:v5.5.0`),
Redis, MongoDB and an S3-compatible artefact store (`rustfs/rustfs`),
all on one Docker network, with the laboratory applications on a second.

```
$ docker build -q -t b-hunters-local/nuclei:1.2.0 repos/B-Hunters-Nuclei
$ docker run -d --name bh-worker-nuclei --network dev_default \
    -v dev/b-hunters.ini:/etc/b-hunters/b-hunters.ini:ro \
    -e BHUNTERS_CONFIG=/etc/b-hunters/b-hunters.ini \
    b-hunters-local/nuclei:1.2.0
```

A worker image was confirmed to carry the fixed base class:

```
$ docker run --rm --entrypoint sh b-hunters-local/nmap:1.2.0 -c '...'
b_hunters version: 1.2.0
scope guard covers 169.254.169.254: True
failure comparison fixed: True
```

### 6.3 The contract verifier

`b_hunters/platform/scanners/contracts.py` reads the worker sources and
checks that they agree on the Karton message contract.  It is exposed as
`b-hunters contracts` and as a test.

```
$ b-hunters contracts --workers /path/to/repos
Checked 17 worker repositories
```

It found seven real defects, all now fixed:

| Defect | Worker |
|---|---|
| The status was reported against the JavaScript asset URL | `jsscanner` |
| The status was never reported at all | `GetJS`, `Web-Technology` |
| The status referenced an undefined variable, so every task raised a `NameError` | `Web-Technology` |
| The scan ran twice | `Web-Technology` |
| The task filters depended on an environment variable | `Nuclei` |
| A dead `type: file` key in the payload | `GoSpider`, `Katana`, `ParamSpider`, `Wayback` |
| A host with no open ports raised a `KeyError` | `NMap` |

The verifier now reports **0 errors and 0 warnings** across the 17
workers.

### 6.4 The toolchain defects that stopped the images building

| Worker | Defect | Fix |
|---|---|---|
| `Katana` | `golang:1.21.1` cannot build the current release | `golang:1.26`, the tool pinned to `v1.8.0` |
| `Gowitness` | the same Go version problem | `golang:1.26-bookworm` |
| `GetJS` | the module path has upper case letters, which the Go proxy rejects, and the release predates Go modules | Built from a pinned clone with the module initialised in the build |
| `Web-Technology` | the tool was rewritten in Go, so `pip install` no longer works, and the worker still used the old flags and text format | Built from a pinned commit; the worker reads the tool's JSON output |

### 6.5 The identity defect

Karton's configuration **overrides** a worker's class-level identity:

```python
if self.config.has_option("karton", "identity"):
    self.identity = self.config.get("karton", "identity")
```

A shared configuration that names an identity therefore makes every
worker register under the same name.  The worker configuration
deliberately has no `[karton] identity` option, so each worker uses its
own.  This was found by running the workers, not by reading them: the
first run showed `failed: ['B-Hunters-Platform']` where the worker's own
identity belonged.

### 6.6 The per-worker output verification

`verify_workers.py` starts each worker, sends it the task type it binds
to, and checks that it reported its status under its own identity and
wrote into the report field it is responsible for.

```
worker           status       reported   output
nmap             ok           finished   {"Ports": 1}
dirsearch        ok           finished   {"Paths": 0}
paramspider      ok           finished   {"Paths": 0}
webtechnology    ok           finished   {"Technology": 1}
nuclei           ok           finished   {"Vulns": 0}
sqlmap           ok           finished   {"Vulns": 0}
dalfox           ok           finished   {"Vulns": 0}
ssti             ok           finished   {"Vulns": 0}
katana           ok           finished   {"Paths": 0}
gospider         ok           finished   {"Paths": 0}
wayback          ok           finished   {"Paths": 0}
jsscanner        ok           finished   {"js_documents": 1}
getjs            ok           finished   {"js_documents": 0}
gowitness        ok           finished   {"Screenshot": false}
```

A `Vulns: 0` result is a correct result: the tool ran and found nothing
on the target.  The check is that the worker **ran** and **reported**,
which is what "the same way of reporting to Karton" means.

The path-consuming workers are given their input the way a real scan
gives it to them: the harness uploads the URL list to the artefact store
under the key the worker downloads it from, which is how the key
convention was confirmed.

### 6.7 The laboratory

Three applications run at once, each pinned by digest, each on the
laboratory network and the worker network, and each reachable with the
same URL from the platform process and from the worker containers:

| Application | Version | Digest | Port |
|---|---|---|---|
| Damn Vulnerable GraphQL Application | 2.2.0 | `sha256:040aa33c…` | 5013 |
| OWASP Juice Shop | latest (pinned) | `sha256:42843723…` | 3000 |
| OWASP WebGoat | latest (pinned) | `sha256:95c23e70…` | 8080 |

Two things had to be fixed to make this work:

* **The readiness gate is host-side.**  Juice Shop has no shell at all and
  WebGoat has neither curl nor python, so an in-container health check
  cannot be relied on.  The gate is a TCP connect plus an HTTP request
  from the host.
* **The published port is separate from the in-network port.**  Port
  3000 on the host was already taken by an unrelated container, so the
  laboratory publishes Juice Shop on 3300 while the scan always uses the
  in-network port.

The Juice Shop container was also killed by the out-of-memory killer
during the run; the heap is now capped and the containers have a memory
limit.

---

## 6. Recommended next steps

1. **Publish `1.2.0` and bump the 17 worker Dockerfiles.** This is the
   single highest-value remaining action: it is what makes the base-class
   fixes reach the workers.
2. **Configure a model provider and re-run the benchmark.** The
   agent-dependent test cases will then be measurable rather than
   asserted.
3. **Pull and benchmark the remaining four applications.** The manifests
   exist; they need images and a measurement.
4. **Move the login throttle into MongoDB** before running more than one
   API node.
5. **Pin the worker tooling.** Every Go tool is installed with
   `@latest` and every base image floats. Pinning them is what makes a
   benchmark reproducible across machines.
6. **Add a frontend test suite** to CI so that the browser checks run on
   every push.
7. **Remove the committed `xray` binary** from `B-Hunters-xray` and
   fetch it from a pinned release with a checksum instead.
8. **Rotate the credentials in `B-Hunters-Playground/.env`** and stop
   setting the artefact bucket policy to `public`.

---

## 7. File manifest

```
B-Hunters/
├── b_hunters/
│   ├── __init__.py            # modernised (no pkg_resources)
│   ├── __version__.py          # 1.2.0
│   ├── bhunter.py              # the shared base class, four defects fixed
│   ├── cli.py                  # scan/report/status preserved; serve/admin/bench added
│   ├── platform/
│   │   ├── settings.py         # environment + legacy INI configuration
│   │   ├── db/                 # MongoDB client, indexes, repositories
│   │   ├── security/           # scope, redact, passwords, sessions
│   │   ├── agents/             # provider, compat, roles, schemas, runtime,
│   │   │                       # collaboration, orchestrator
│   │   ├── tools/              # gateway + 13 built-in tools
│   │   ├── scanners/           # base, registry (23 adapters), native, graphql
│   │   └── bench/              # manifest, lab, runner, scoring
│   └── web/                    # index.html, app.js, styles.css, favicon.svg
├── docs/
│   ├── architecture-audit.md   # the audit
│   ├── threat-model.md
│   ├── configuration.md
│   ├── deployment.md
│   ├── benchmark.md
│   ├── agent-authoring.md
│   └── troubleshooting.md
├── tests/
│   ├── conftest.py
│   ├── unit/                   # 71 tests
│   ├── security/               # 91 tests
│   ├── integration/            # 42 tests
│   └── bench/                  # 25 tests
├── .github/workflows/ci.yml
├── pytest.ini
├── ruff.toml
├── requirements.txt
└── setup.py
```
