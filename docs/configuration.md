# Configuration reference

The platform reads two configuration sources:

1. **The legacy INI file** (`/etc/b-hunters/b-hunters.ini` by default).
   It carries the infrastructure coordinates the existing workers use and
   is still honoured for them.
2. **Environment variables** (`BHUNTERS_*`). These take precedence and
   configure everything the platform adds.

Nothing secret is stored in the repository. The INI file is read from the
path given by `BHUNTERS_CONFIG` (or `--config` for the CLI).

---

## 1. Environment variables

### Core

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_ENVIRONMENT` | `development` | `production` tightens cookie and CORS behaviour |
| `BHUNTERS_BASE_URL` | `http://127.0.0.1:8080` | Public URL of the platform |
| `BHUNTERS_CONFIG` | `/etc/b-hunters/b-hunters.ini` | Legacy INI file path |

### Persistence

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_MONGO_URI` | `mongodb://127.0.0.1:27017` | MongoDB connection string |
| `BHUNTERS_MONGO_DB` | `b-hunters` | Database name |
| `BHUNTERS_MONGO_TIMEOUT_MS` | `5000` | Server selection timeout |

The legacy `[mongo]` INI section is mapped onto these when the environment
variable is absent.

### Karton

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_KARTON_CONFIG_PATH` | `/etc/b-hunters/b-hunters.ini` | Karton configuration file |
| `BHUNTERS_KARTON_IDENTITY` | `B-Hunters-Platform` | Producer identity |

### Artefact store

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_S3_ENDPOINT` | – | MinIO/S3 endpoint |
| `BHUNTERS_S3_ACCESS_KEY` | – | Access key |
| `BHUNTERS_S3_SECRET_KEY` | – | Secret key |
| `BHUNTERS_S3_BUCKET` | `bhunters` | Bucket name |
| `BHUNTERS_S3_SECURE` | `false` | Use HTTPS for the endpoint |

### Web server

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_HOST` | `0.0.0.0` | Bind address |
| `BHUNTERS_PORT` | `8080` | Bind port |
| `BHUNTERS_API_PREFIX` | `/api/v1` | API route prefix |
| `BHUNTERS_CORS_ORIGINS` | – | Comma-separated allowed origins |
| `BHUNTERS_TRUSTED_PROXY_HEADERS` | – | Comma-separated trusted proxy headers |

### Sessions and authentication

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_SESSION_COOKIE_NAME` | `bh_session` | Session cookie name |
| `BHUNTERS_SESSION_TTL_SECONDS` | `43200` | Session lifetime (12 h) |
| `BHUNTERS_SESSION_COOKIE_SECURE` | `false` | **Set to `true` behind TLS** |
| `BHUNTERS_SESSION_COOKIE_SAMESITE` | `Lax` | `Lax`, `Strict` or `None` |
| `BHUNTERS_CSRF_COOKIE_NAME` | `bh_csrf` | CSRF cookie name |
| `BHUNTERS_CSRF_HEADER_NAME` | `X-CSRF-Token` | CSRF header name |
| `BHUNTERS_LOGIN_MAX_ATTEMPTS` | `5` | Failed attempts before lockout |
| `BHUNTERS_LOGIN_LOCKOUT_SECONDS` | `300` | Lockout duration |
| `BHUNTERS_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Username used by `admin bootstrap` |
| `BHUNTERS_BOOTSTRAP_ADMIN_PASSWORD` | – | Password for the bootstrap command |

### Model providers

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_LLM_NAME` | `default` | Provider name |
| `BHUNTERS_LLM_BASE_URL` | – | Base URL of an OpenAI-compatible endpoint |
| `BHUNTERS_LLM_API_KEY` | – | API key |
| `BHUNTERS_LLM_MODEL` | – | Model identifier |
| `BHUNTERS_LLM_TEMPERATURE` | `0` | Sampling temperature |
| `BHUNTERS_LLM_MAX_OUTPUT_TOKENS` | `4096` | Maximum output tokens |
| `BHUNTERS_LLM_MAX_CONTEXT_TOKENS` | `128000` | Maximum context window |
| `BHUNTERS_LLM_TIMEOUT` | `120` | Request timeout in seconds |
| `BHUNTERS_LLM_MAX_RETRIES` | `2` | Retries on a retryable error |
| `BHUNTERS_LLM_CONCURRENCY` | `4` | Maximum concurrent requests |

These provide a fallback when no provider has been configured in the
admin UI. A provider configured in the UI always takes precedence.

### Agents

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_AGENT_MAX_ROUNDS` | `8` | Default round budget |
| `BHUNTERS_AGENT_MAX_TOKENS_PER_SCAN` | `400000` | Default token budget |
| `BHUNTERS_AGENT_MAX_TASK_BUDGET` | `60` | Default task budget |
| `BHUNTERS_AGENT_WALL_CLOCK_SECONDS` | `1800` | Default wall-clock budget |
| `BHUNTERS_AGENT_WORKSPACE_ROOT` | `/var/lib/b-hunters/workspaces` | Per-agent workspace root |
| `BHUNTERS_ENABLE_AGENTS` | `true` | Master switch for the agent runtime |

### Scope enforcement defaults

These are the *defaults*; a scan definition overrides them.

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_SCOPE_ALLOW_PRIVATE_NETWORK` | `false` | Permit loopback/private destinations |
| `BHUNTERS_SCOPE_ALLOW_HTTP` | `true` | Permit plain HTTP |
| `BHUNTERS_SCOPE_ALLOW_STATE_CHANGING` | `false` | Permit POST/PUT/PATCH/DELETE |
| `BHUNTERS_SCOPE_MAX_REQUESTS_PER_SECOND` | `10` | Per-host rate limit |
| `BHUNTERS_SCOPE_MAX_CONCURRENCY` | `16` | Simultaneous in-flight requests |
| `BHUNTERS_SCOPE_MAX_RESPONSE_BYTES` | `8388608` | Maximum response size |
| `BHUNTERS_SCOPE_DEFAULT_TIMEOUT` | `20` | Per-request timeout in seconds |
| `BHUNTERS_SCOPE_MAX_DURATION_SECONDS` | `3600` | Absolute scan duration budget |

### Retention and logging

| Variable | Default | Meaning |
|---|---|---|
| `BHUNTERS_ARTIFACT_RETENTION_DAYS` | `30` | Artefact retention |
| `BHUNTERS_EVENT_RETENTION_DAYS` | `90` | Event retention |
| `BHUNTERS_LOG_LEVEL` | `INFO` | Log level |
| `BHUNTERS_LOG_JSON` | `false` | Emit JSON log lines |

---

## 2. The legacy INI file

```ini
[redis]
host=10.0.0.10
password=change-me

[s3]
access_key = minioadmin
secret_key = change-me
address = http://10.0.0.10:9000
bucket = bhunters

[mongo]
user=bhunters
password=change-me
db=b-hunters
host=10.0.0.10
port=27017

[Webhook]
discord_report=https://discord.com/api/webhooks/...
discord_task_status=https://discord.com/api/webhooks/...
```

The `[Webhook]` section is now optional. A worker without it skips the
notification instead of raising `KeyError`.

The `[mongo]` and `[s3]` sections are mapped onto the platform's
environment variables when the corresponding `BHUNTERS_*` variable is not
set.

---

## 3. Provider configuration

The platform speaks the OpenAI `chat/completions` contract. Any endpoint
that implements it works, including self-hosted servers.

```json
{
  "name": "local-llm",
  "base_url": "http://llm.internal:8080/v1",
  "api_key": "not-needed-for-a-local-server",
  "model": "qwen2.5-coder",
  "role_models": { "verifier": "qwen2.5-coder-32b" },
  "temperature": 0.0,
  "max_output_tokens": 4096,
  "max_context_tokens": 32768,
  "timeout_seconds": 120,
  "max_retries": 2,
  "concurrency": 4,
  "extra_headers": { "X-Tenant": "security-team" },
  "enabled": true
}
```

**Configure it from the UI** under *Administration → Model providers*, or
from the environment with the `BHUNTERS_LLM_*` variables.

**What the platform assumes and what it does not.** The platform probes
the endpoint once per provider to determine whether it supports native
tool calling. If it does not, the runtime falls back to a compatibility
layer that asks the model to emit a JSON tool call and validates it
against the same schema and the same permission checks. The platform
never assumes a specific vendor, model name or endpoint.

**Health check.** *Administration → Model providers → Check health* calls
`GET {base_url}/models` and reports whether the configured model is
present, the measured latency and any error.

---

## 4. Scan profiles

A scan profile is a named bundle of agents, scanners and limits.

| Profile | Agents | Scanners |
|---|---|---|
| `standard` | Every hypothesis role, the verifier and the adjudicator | 16 adapters including the active scanners |
| `recon` | `recon`, `javascript`, `api` | 9 discovery-only adapters |

Profiles are stored on the scan definition, so a scan can be replayed with
exactly the configuration it used.

---

## 5. Agent definitions

Agent definitions are versioned. Editing a definition creates a new
version; a scan records the version it used.

```json
{
  "name": "Injection analyst",
  "role": "vuln_injection",
  "system_prompt": "You look for injection vulnerabilities…",
  "instructions": "Compare a benign value with one altered value…",
  "model_ref": "local-llm:qwen2.5-coder",
  "tools": ["http_request", "compare_responses", "list_findings"],
  "permissions": {
    "capabilities": ["network", "read_files"],
    "tools": ["http_request", "compare_responses", "list_findings"],
    "denied_tools": [],
    "escalation_capabilities": [],
    "max_output_bytes": 524288
  },
  "budget": {
    "max_rounds": 8,
    "max_tool_calls": 50,
    "max_tokens": 150000,
    "max_wall_clock_seconds": 900
  },
  "output_schema": {},
  "enabled": true
}
```

See `docs/agent-authoring.md` for the full contract.

---

## 6. Environment variable precedence

1. Explicit keyword arguments to `load_settings()`.
2. Environment variables.
3. The legacy INI file.
4. The declared defaults.

The only exception is `BHUNTERS_CONFIG`, which selects the INI file
itself.

---

## 7. The scope of a scan

The scope is what the scan is allowed to touch. It is fixed when the
scan is created, and it has three parts.

| Part | Where | Meaning |
|---|---|---|
| the authorised hosts | `targets.authorized_hosts` | the hosts the scan may touch |
| the excluded paths | `targets.excluded_paths` | the paths on those hosts the scan must not request |
| the denied hosts | `targets.denied_hosts` | the hosts the scan must not touch, even though a wildcard covers them |

A host may be named exactly (`api.example.com`) or with a leading
wildcard (`*.example.com`), which covers the subdomains of the domain
behind it and **not** the apex — so the apex has to be named as well.

### The denied hosts, and why they are separate

A bug bounty programme names the assets that are out of scope. The
wildcard that covers the domain covers them too:

```
in scope      *.rapyd.net
out of scope  community.rapyd.net, support.rapyd.net, docs.rapyd.net,
              sandbox.rapyd.net, ghost.rapyd.net
```

So the exclusions have to be said separately, or a scan of `*.rapyd.net`
would touch `support.rapyd.net` — which the programme rules out
explicitly.

They are enforced in two places, because the workers are separate
containers that discover hosts of their own:

* the **platform** refuses the target outright, and its own adapters
  never request a denied host;
* the **workers** inherit the list with the task and refuse the host
  before they send their first request.

### An example

```json
{
  "targets": {
    "urls": ["https://example.com/"],
    "authorized_hosts": ["*.example.com", "example.com"],
    "denied_hosts": ["community.example.com", "support.example.com"]
  }
}
```
