# Troubleshooting

---

## Platform

### `b-hunters serve` fails with "Mongo Connection Failed"

The platform cannot reach MongoDB.

```bash
# Is it running?
docker ps --filter name=bh-mongo
mongosh "mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin" \
  --eval 'db.adminCommand("ping")'
```

Check that `BHUNTERS_MONGO_URI` matches the credentials in
`dev/docker-compose.dev.yml`. The URI must include `?authSource=admin`
when the account was created as a root user.

### The UI shows "Your session has expired"

The session TTL (`BHUNTERS_SESSION_TTL_SECONDS`, 12 hours by default)
elapsed, or the password was changed — a password change invalidates every
other session. Sign in again.

### The UI shows the login page even though I just signed in

The session cookie was rejected. In production this is almost always
`BHUNTERS_SESSION_COOKIE_SECURE=true` being served over plain HTTP: the
browser refuses to store a `Secure` cookie on an insecure origin. Either
terminate TLS in front of the platform or set the variable to `false` for
a non-production deployment.

### The login is rate limited

Five failed attempts for a username or an IP lock the pair out for
`BHUNTERS_LOGIN_LOCKOUT_SECONDS` (300 by default). The counter is
in-process, so it resets when the API restarts. In a multi-node
deployment, move the counters into MongoDB.

### "CSRF token missing or invalid"

An unsafe request (`POST`, `PATCH`, `DELETE`) arrived without a valid
`X-CSRF-Token` header. The frontend reads the token from the `bh_csrf`
cookie and echoes it back. If you are calling the API directly, read the
token from that cookie and send it in the header:

```bash
CSRF=$(awk '/bh_csrf/{print $7}' cookies.txt)
curl -X POST https://platform/api/v1/scans \
  -H "Cookie: $(cat cookies.txt | tr '\n' ' ')" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" \
  -d @scan.json
```

### The dashboard shows "Karton is not reachable"

The platform cannot read the Karton state.

```bash
# Is the configuration file there?
ls -l "$BHUNTERS_KARTON_CONFIG_PATH"

# Does the Redis instance answer?
redis-cli -h 127.0.0.1 -p 6379 -a "$REDIS_PASS" ping
```

`/api/v1/karton/state` returns `available: false` with the error rather
than fabricating numbers. The most common cause is a `karton.ini` that
points at a Redis instance that is not running.

---

## Scans

### "no target is inside the authorised scope"

Every target you supplied is outside the authorised host list. The
validation is exact: `https://staging.example.com` is inside
`staging.example.com` and inside `*.example.com`, but **not** inside
`example.com` — and `*.example.com` matches subdomains only, never the
apex. Add the host to the authorised list.

### A host discovered during the crawl was not scanned

That is intentional. The authorised host list is fixed when the scan is
created, so a link to `internal.corp.example.com` does not authorise a
scan of it. Add the host to the list before creating the scan.

### The scan is stuck in `queued`

The scan was created but never started. Press **Start** on the live
monitor page. `b-hunters scan` starts a scan immediately; the API
separates creation from start so that the operator can review the scope
first.

### The scan is `paused` and will not resume

The pause is a real backend control: the orchestrator does not start new
tasks while the scan is paused. Press **Resume**. If the scan was
paused before it started, resuming it moves it to `running`.

### The agents are not doing anything

Check, in order:

1. **Is a provider configured?** *Administration → Model providers*. With
   no provider, every agent task fails with "no model provider is
   configured".
2. **Does the provider answer?** *Check health* on the provider row. A
   `401` means the credential is wrong; a `404` usually means the base URL
   is wrong.
3. **Did the agent run out of budget?** The agent's conclusion on the
   *Agents* tab says "budget exhausted" when it hit a round, token, tool
   call or wall-clock limit.

### An agent says it cannot use a tool

It cannot, by design. Each role has an explicit tool allow-list and a
set of capabilities. The *Agent workspace* page shows the tools and the
capabilities of every role. Granting a tool means creating a new version
of the agent definition with a wider allow-list.

### The scan produced no findings

Check the *Tool calls* tab. A failing tool usually means a scope or
configuration problem rather than a platform fault — the record contains
the arguments and the error.

---

## The benchmark laboratory

### `b-hunters bench lab up` fails

```bash
# Is docker available?
docker info

# Does the image exist locally?
docker images | grep dvga
```

The laboratory does **not** pull images. Pull them once beforehand:

```bash
docker pull dolevf/dvga:2.2.0
```

A benchmark run never depends on the network at measurement time.

### The benchmark reports everything as `inconclusive`

The application did not become ready within its startup window. Check it
directly:

```bash
b-hunters bench lab status
curl -s http://127.0.0.1:80/graphql
```

Juice Shop and WebGoat are slow to start; their manifests allow 90 and 120
seconds respectively.

### A benchmark run finds nothing

The deterministic adapters need to reach the application. The benchmark
scan sets `allow_private_network`, so the scope check permits
`127.0.0.1`. If the application is on a different port than the manifest
declares, the probes go nowhere.

### The score looks wrong

Compare the *not applicable* and *inconclusive* counts first. A run where
most cases are `not_applicable` has a low precision denominator by design
— the application simply does not contain those vulnerability classes.

---

## Workers

### A worker reports "MongoDB is not available after 10 tries"

The worker's MongoDB is unreachable. The worker inherits the MongoDB
coordinates from `/etc/b-hunters/b-hunters.ini` — mount the file at that
path, or set `BHUNTERS_CONFIG` to point somewhere else.

### A worker's task is never consumed

Check that the task's `type` and `stage` match the worker's `filters`.
The `file` task type and the `takeover` stage are not consumed by any
worker in the current organisation; see the audit.

### A failed task is reported as finished

This was a defect in the shared base class (`update_task_status`
compared `"failed"` against `"Failed"`). It is fixed in `1.2.0`. The
workers install `b-hunters` from PyPI, so **the fix only reaches a worker
once the release is published and the Dockerfile version is bumped** —
see `docs/deployment.md` §3.2.

### A worker crashes on a Discord notification

Older workers required a `[Webhook]` section in the configuration file.
That is now optional: a worker without it skips the notification. Update
to `1.2.0` to pick the fix up.

---

## Development

### `pytest tests/integration` skips everything

The integration tests need a MongoDB. They skip when
`BHUNTERS_TEST_MONGO_URI` is unreachable:

```bash
export BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"
export BHUNTERS_TEST_MONGO_DB="b-hunters-test"
pytest tests/integration -q
```

### `ruff check` reports `F821 Undefined name`

A genuine bug: a name is used that was never imported or defined. These
were found by the linter during the platform work — see the audit for the
ones that mattered (`EvidenceRef`, `ToolPermissions`, `ProviderConfig`
and `shutil`).

### The package will not import

`b_hunters/__init__.py` used `pkg_resources`, which is removed in
modern setuptools. That was replaced in `1.2.0`. On an older checkout,
either upgrade setuptools or apply the fix.
