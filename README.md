<p align="center">
  <img src="images/logo/bhunters_logo@0.5x.png" alt="B-Hunters Logo">
</p>

# B-Hunters

```text
$$$$$$$\          $$\   $$\                      $$\
$$  __$$\         $$ |  $$ |                     $$ |
$$ |  $$ |        $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\   $$$$$$$\
$$$$$$$\ |$$$$$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ $$  _____|
$$  __$$\ \______|$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|\$$$$$$\
$$ |  $$ |        $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |       \____$$\
$$$$$$$  |        $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      $$$$$$$  |
\_______/         \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      \_______/
                                            0xBormaa - 2024
```

**B-Hunters** is an application security assessment platform built on the
[Karton](https://github.com/CERT-Polska/karton) framework. It runs the
scanners in isolated containers, adds an AI agent runtime that reasons
about the results, and exposes everything through an authenticated web
console.

The framework automates the reconnaissance and scanning pipeline with
Karton, Redis, MongoDB and MinIO. The platform layer adds:

* an **authenticated API and web console** — no scan, finding or
  administrative function is reachable without a session;
* an **AI agent runtime** with thirteen specialised roles, a controlled
  tool interface and an independent verification workflow;
* **central scope enforcement** that every HTTP-capable code path must
  pass through;
* a **vulnerable application laboratory** and a repeatable **benchmark
  harness** with real precision, recall and F1 scoring.

---

## Quick start

```bash
# 1. The infrastructure.
cd dev && docker compose -f docker-compose.dev.yml up -d && cd ..

# 2. The platform.
cd repos/B-Hunters
pip install -e ".[platform]"

export BHUNTERS_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"
export BHUNTERS_MONGO_DB="b-hunters-dev"

# 3. The first administrator.  There is no default credential.
b-hunters admin bootstrap --username admin

# 4. Run it.
b-hunters serve --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080/>.

---

## The legacy commands still work

```bash
# Start a scan exactly as before.
b-hunters scan -d example.com -t multi

# Produce the report directory exactly as before.
b-hunters report -d example.com -o /tmp/example.com

# Inspect the Karton queues.
b-hunters status
```

The existing `scans`, `domains`, `reports` and `js` MongoDB collections
are untouched, and the 17 scanner workers keep their Karton identities,
filters and payload keys.

---

## New commands

| Command | Purpose |
|---|---|
| `b-hunters serve` | Run the authenticated API and the web console |
| `b-hunters admin bootstrap` | Create the first administrator |
| `b-hunters admin add-user` | Create a user |
| `b-hunters admin list-users` | List the users |
| `b-hunters admin init-db` | Create the database indexes |
| `b-hunters admin seed-roles` | Seed the built-in agent definitions |
| `b-hunters bench sync` | Load the benchmark manifests |
| `b-hunters bench lab up\|down\|status` | Manage the vulnerable application laboratory |
| `b-hunters bench run` | Run the benchmark suite |
| `b-hunters bench scores` | Show the recorded benchmark scores |

---

## The agent runtime

Thirteen roles, each with its own instructions, tools, permissions,
output schema and budget:

| Role | Purpose |
|---|---|
| `orchestrator` | Builds the plan, assigns work, tracks evidence, stops on budget |
| `recon` | Maps hosts, services, technologies, routes and endpoints |
| `javascript` | Recovers routes, API paths, methods, parameters and auth logic from JavaScript |
| `api` | Correlates routes into an API surface; finds undocumented endpoints |
| `authn` | Traces registration, login, logout, reset and session handling |
| `access_control` | Compares permitted and forbidden operations across test identities |
| `vuln_injection` | Bounded, non-destructive injection probes |
| `vuln_xss` | Inert-marker XSS sink analysis |
| `vuln_ssrf` | Controlled-callback SSRF and path traversal analysis |
| `vuln_config` | Security headers, TLS, cookies and configuration defaults |
| `source_analysis` | Correlates source, configuration and build artefacts with HTTP behaviour |
| `verifier` | Independently re-evaluates candidate findings and rejects the weak ones |
| `adjudicator` | Reconciles disagreement, deduplicates, sets severity, writes the report |

Agents exchange **structured messages**, not chat. A finding proposed by
an agent is created as `unverified`; only the verifier can promote it, and
only from evidence. Agreement between agents is never treated as proof.

The model layer speaks the OpenAI `chat/completions` contract over plain
HTTP. Native tool calling is probed at runtime; an endpoint without it
falls back to a compatibility layer that validates the requested action
against the same schema and the same permission checks.

---

## Scope enforcement

Scope is enforced in code, not in a prompt. Every HTTP-capable tool,
browser action, agent request and worker request passes through
`b_hunters/platform/security/scope.py`, which:

* refuses any host outside the operator's explicit allow-list, and never
  widens it as hosts are discovered;
* validates **every resolved IP address**, so a DNS record that flips to
  `127.0.0.1` cannot reach a loopback service;
* blocks loopback, private, link-local, CGNAT, multicast and cloud
  metadata destinations;
* re-validates every redirect hop;
* bounds request rates, concurrency, response size and total duration;
* requires an explicit policy flag for state-changing methods.

See `docs/threat-model.md`.

---

## Tools integrated

The 17 existing B-Hunters workers are registered as scanner adapters with
their real Karton task contracts. Six capabilities that the existing
modules did not cover at all are added as in-process adapters: security
header assessment, TLS configuration, secret detection with redaction,
OpenAPI discovery, GraphQL analysis and dependency analysis.

See `docs/architecture-audit.md` for the full inventory, the dependency
graph and the compatibility matrix.

---

## Documentation

| Document | Contents |
|---|---|
| `docs/architecture-audit.md` | The audit of all 19 repositories, the inventory, the gaps and the migration plan |
| `docs/threat-model.md` | Assets, trust boundaries, threats, mitigations and residual risk |
| `docs/configuration.md` | Every environment variable, the INI file, providers, profiles and agent definitions |
| `docs/deployment.md` | Development and production deployment, health checks, backup, retention and the runbook |
| `docs/benchmark.md` | The laboratory, the manifests, the scoring and how to reproduce a run |
| `docs/agent-authoring.md` | How to write, version and test an agent |

---

## Development

```bash
pip install -e ".[platform,dev]"

# The unit and security tests need no services.
pytest tests/unit tests/security -q

# The full suite needs MongoDB.
export BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"
pytest tests -q

# Linting and formatting.
ruff check b_hunters tests
ruff format --check b_hunters tests
```

CI runs the lint, the type check, the unit and security tests, the
integration tests against a real MongoDB, the package build, a secret
scan and a container vulnerability scan.

---

## B-Hunters-Playground

[B-Hunters-Playground](https://github.com/B-Hunters/B-Hunters-Playground)
contains the original Compose deployment of the scanner workers. It is
still useful for running the workers on their own; the platform
deployment is documented in `docs/deployment.md`.

---

## License

BSD. The bundled tools carry their own licences; see the inventory in
`docs/architecture-audit.md`.
