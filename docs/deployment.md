# Deployment and operations

---

## 1. Development deployment

The development stack is MongoDB, Redis and the platform API. MinIO is
optional.

```bash
cd dev
docker compose -f docker-compose.dev.yml up -d

# Point the platform at the development services.
export BHUNTERS_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"
export BHUNTERS_MONGO_DB="b-hunters-dev"
export BHUNTERS_KARTON_CONFIG_PATH="$PWD/karton.ini"

cd ../repos/B-Hunters
pip install -e ".[platform]"

# Create the first administrator.  There is no default credential.
b-hunters admin bootstrap --username admin

# Run the API and the web UI.
b-hunters serve --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/`.

**The development Compose file publishes MongoDB, Redis and MinIO on
`127.0.0.1` only.** This is a development convenience. Do not reuse it in
production.

---

## 2. Production deployment

### 2.1 Components

| Component | Image | Replicas | Exposure |
|---|---|---|---|
| Platform API + UI | `b-hunters-platform:1.2.0` | ≥2 | Behind TLS, internal only |
| MongoDB | `mongo:7.0.16` | 1 (or a replica set) | Internal only |
| Redis | `redis:7.2.5-alpine` | 1 | Internal only |
| Karton system | `certpl/karton-system:v5.5.0` | 1 | Internal only |
| Karton dashboard | `certpl/karton-dashboard:v1.6.0` | 1 | Internal only, optional |
| MinIO | `minio/minio:<pinned>` | 1 | Internal only |
| Scanner workers | `bormaa/<tool>:1.1.16` | as needed | Egress only to the targets |

### 2.2 The configuration file

The legacy CLI and the Karton workers read the **same** file, so it must
carry both the Karton sections and the legacy ones. This is the format
the original deployment used:

```ini
[karton]
identity = B-Hunters-Platform

[redis]
host = redis
port = 6379
password = <secret>
db = 0

[minio]
access_key = <secret>
secret_key = <secret>
address = http://minio:9000
secure = 0

[s3]
access_key = <secret>
secret_key = <secret>
address = http://minio:9000
bucket = bhunters

[mongo]
user = <user>
password = <secret>
db = b-hunters
host = mongo
port = 27017

; Optional.  A worker without a webhook skips the notification.
[Webhook]
discord_report = https://discord.com/api/webhooks/...
discord_task_status = https://discord.com/api/webhooks/...
```

Point the platform at it with `BHUNTERS_CONFIG` (or `-c` for the CLI):

```bash
export BHUNTERS_CONFIG=/etc/b-hunters/b-hunters.ini
b-hunters -c /etc/b-hunters/b-hunters.ini scan -d example.com -t multi
```

The `[mongo]` and `[s3]` sections are mapped onto the platform's
environment variables when the corresponding `BHUNTERS_*` variable is not
set, so a single file can configure both the legacy tools and the
platform.

### 2.3 Required configuration

```bash
BHUNTERS_ENVIRONMENT=production
BHUNTERS_BASE_URL=https://b-hunters.internal.example
BHUNTERS_HOST=0.0.0.0
BHUNTERS_PORT=8080
BHUNTERS_MONGO_URI=mongodb://user:password@mongo:27017/?authSource=admin
BHUNTERS_MONGO_DB=b-hunters
BHUNTERS_KARTON_CONFIG_PATH=/etc/karton/karton.ini
BHUNTERS_SESSION_COOKIE_SECURE=true
BHUNTERS_SESSION_COOKIE_SAMESITE=Lax
BHUNTERS_CORS_ORIGINS=https://b-hunters.internal.example
BHUNTERS_AGENT_WORKSPACE_ROOT=/var/lib/b-hunters/workspaces
BHUNTERS_ARTIFACT_RETENTION_DAYS=30
BHUNTERS_EVENT_RETENTION_DAYS=90
```

**Secrets** belong in a secret store (Docker secrets, Kubernetes secrets,
Vault). Never bake them into an image, never commit them, and prefer
injecting them at run time over putting them in a long-lived process
environment.

### 2.4 First administrator

There is no default credential and no self-registration.

```bash
# Interactive, prompts for the password.
b-hunters admin bootstrap --username admin

# Or non-interactively, from a secret store.
BHUNTERS_BOOTSTRAP_PASSWORD="$(vault kv get -field=password secret/b-hunters/admin)" \
  b-hunters admin bootstrap --username admin
```

The password must be at least 12 characters and mix at least three of
lower case, upper case, digits and symbols. Change it after the first
sign-in; the platform invalidates every other session on a password
change.

### 2.5 Health checks

| Endpoint | Purpose | Behaviour |
|---|---|---|
| `GET /healthz` | Liveness | `200` when the process is up |
| `GET /readyz` | Readiness | `200` when MongoDB answers, `503` otherwise |
| `GET /api/v1/health` | Detailed | Reports the database status and the version |

A load balancer should use `/readyz` for its readiness probe.

### 2.6 Network policy

The platform makes outbound requests to the authorised targets. Restrict
container egress to the approved target set at the network layer — the
application-level scope enforcement is one layer, the network policy is
the second.

The API, MongoDB, Redis and MinIO must not be reachable from an untrusted
network. In particular:

* do **not** set the artefact bucket policy to `public` (the playground
  Compose file does; that is a development convenience);
* do **not** publish Redis, MongoDB or MinIO on all interfaces;
* do **not** expose the Karton dashboard to untrusted users.

### 2.7 Backup and restore

**MongoDB** holds the scans, findings, events, audit log and agent
definitions. Back it up with `mongodump`:

```bash
mongodump --uri="$BHUNTERS_MONGO_URI" --db="$BHUNTERS_MONGO_DB" --out=/backup/$(date +%F)
```

**MinIO/S3** holds the tool artefacts and screenshots. Back it up with
`mc mirror`:

```bash
mc mirror /backup/minio bhunters/bhunters
```

**The agent workspace** (`BHUNTERS_AGENT_WORKSPACE_ROOT`) holds
intermediate analysis and is regenerable; it does not need backing up,
but it should be on a volume that is cleaned on a schedule.

Restore:

```bash
mongorestore --uri="$BHUNTERS_MONGO_URI" --db="$BHUNTERS_MONGO_DB" /backup/2026-01-15
mc mirror /backup/minio bhunters/bhunters
```

Restore the database before the artefact store: the findings reference
artefact keys, and a restore in the other order would leave the references
dangling until the artefacts arrive.

### 2.8 Retention

The platform applies retention when `apply_retention` is called (on a
schedule, from an administrative job):

* events older than `BHUNTERS_EVENT_RETENTION_DAYS` are deleted;
* artefacts older than `BHUNTERS_ARTIFACT_RETENTION_DAYS` are deleted;
* expired sessions are deleted.

The audit log is **not** subject to automatic retention — it is the
evidence of who did what, and how long you keep it is a policy decision.

---

## 3. Container images

### 3.1 The platform image

```dockerfile
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BHUNTERS_HOST=0.0.0.0 \
    BHUNTERS_PORT=8080

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY b_hunters ./b_hunters
COPY setup.py ./

RUN useradd --system --uid 10001 --create-home --home-dir /home/bhunters b-hunters \
 && mkdir -p /var/lib/b-hunters/workspaces \
 && chown -R b-hunters:b-hunters /var/lib/b-hunters /app

USER b-hunters
VOLUME ["/var/lib/b-hunters"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/readyz || exit 1

ENTRYPOINT ["b-hunters"]
CMD ["serve"]
```

### 3.2 Worker images

The workers install `b-hunters` **from PyPI**. To make the base-class
fixes reach the workers, publish a release and bump the version in all 17
module Dockerfiles:

```dockerfile
RUN pip install --no-cache-dir b-hunters==1.2.0
```

Until that happens the workers run the previous base class. This is the
one part of the migration that spans repositories, and it is called out in
`docs/architecture-audit.md` §5.

### 3.3 Pinning the tools

Every worker currently installs its tool with `@latest` or clones the
default branch. To make a deployment reproducible, pin each tool to a
released version and record the digest:

```dockerfile
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.1.7
RUN git clone --branch v9.9.4 --depth 1 https://github.com/projectdiscovery/nuclei-templates /app/templates
```

Pin the base images too (`ubuntu:24.04`, `mongo:7.0.16`,
`python:3.12.7-slim`).

---

## 4. Upgrading the platform

1. Take a MongoDB backup.
2. Deploy the new image.
3. The indexes are created idempotently at startup. New collections are
   created; existing ones are left alone.
4. No data migration is required — the platform uses its own
   `platform_*` collections and does not touch the legacy ones.

Rolling back is a matter of redeploying the previous image: the platform
collections are additive, so the old version ignores them.

---

## 5. Operational runbook

### A scan is stuck

```bash
b-hunters status            # queue and consumer state
b-hunters status -s         # restart tasks stuck for over 90 minutes
```

The platform's own view of the same state is at
`GET /api/v1/karton/state` and on the *Karton & workers* page.

### A scan is not making progress

1. Check the scan's status on the live monitor page. If it is `paused`,
   resume it.
2. Check *Tool calls* for repeated failures. A failing tool usually means
   a scope or configuration problem, not a platform fault.
3. Check the agent's conclusion in the *Agents* tab. An agent that
   concludes "no provider is configured" means no model provider has been
   set up.

### The agents are not running

```bash
# Is a provider configured?
curl -s -H "Cookie: $COOKIE" https://platform/api/v1/admin/providers | jq
```

If no provider is configured, the orchestrator fails every agent task
with "no model provider is configured". Configure one under
*Administration → Model providers* or through the `BHUNTERS_LLM_*`
environment variables.

### The provider is failing

Check the provider health from the UI. `401` means the credential is
wrong; `404` usually means the base URL is wrong (the platform appends
`/chat/completions` unless the URL already ends with it); `429` means the
provider is rate limiting.

### Scope violations are being reported

The *Karton & workers* page and `GET /api/v1/scans/{id}` report scope
violations. A violation means something tried to contact a destination
outside the authorised scope and was refused. That is the control
working. Investigate *which* tool attempted it — the tool-call record
contains the arguments.
