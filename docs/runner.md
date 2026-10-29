# The runner

The runner executes the scans. It is a separate process from the API on
purpose.

A scan used to be an `asyncio.create_task` inside the API process: the
scan lived in that process's memory, so restarting the API killed it, two
API replicas would have run it twice, and there was no limit on how many
scans competed for the seventeen worker containers. The runner replaces
that with a durable queue in MongoDB.

## How a scan moves

```
API                     MongoDB                      runner
 │  create scan           │                            │
 │  enqueue job ─────────▶ platform_jobs (queued)      │
 │                        │◀──── claim (lease 60s) ────│
 │                        │      heartbeat every 10s   │
 │                        │      run the orchestrator   │
 │                        │◀──── complete / fail ──────│
 │  SSE reads events ◀──── platform_scan_events        │
```

The API never runs a scan. `POST /api/v1/scans/{id}/start` writes a job
document into `platform_jobs` and returns `{"status": "queued",
"job_id": ...}`.

The runner claims a job with one atomic `find_one_and_update` over
`{status: "queued", available_at <= now}` — or a job whose lease has
expired — sorted by priority and age. A job can therefore only ever be
claimed once, no matter how many runners are running.

## The lease

The claim sets `lease_owner` and `lease_expires_at` (60 seconds by
default). While the runner works, it heartbeats the lease every 10
seconds, which pushes the expiry forward. If the runner is killed, the
heartbeat stops, the lease expires, and another runner claims the job.

A job that fails is retried until `BHUNTERS_JOB_MAX_ATTEMPTS` (3 by
default) and then marked `failed`; the scan is marked `failed` with the
reason. The lease is what makes "kill the runner mid-scan" recoverable
rather than fatal.

## Resuming

The scan record carries a `phase`: `workers`, `agents`, `verifying`,
`reporting` or `completed`. The orchestrator writes it after every
stage, and each agent task carries its own status. A scan that is
reclaimed resumes at the phase it reached: the worker phase is skipped,
and the agent tasks that already succeeded are skipped with their
results reused. A role that was already run is not paid for twice.

## One scan per target

The runner takes a lease on the target before it starts, keyed by the
target's hash. A second scan of the same host waits for the lock — the
job goes back to the queue with a 30-second delay — rather than
competing for the same worker containers.

## Running it

```bash
docker compose --env-file ../.env -f docker-compose.platform.yml up -d runner
docker compose --env-file ../.env -f docker-compose.platform.yml exec runner b-hunters runner status
```

`b-hunters runner status` prints every runner, the age of its heartbeat
and the job it is working on. It exits non-zero when no heartbeat is
fresh, which is what the container health check uses.

`b-hunters runner --once` claims a single job, runs it and exits — the
way to drain the queue by hand.

`POST /api/v1/admin/runner/drain` stops the runner from claiming new
jobs; the job it is working on finishes. `DELETE` on the same path
clears it.

## Recovering a stuck scan

```bash
# What is queued, leased and running?
docker compose --env-file ../.env -f docker-compose.platform.yml exec runner \
  b-hunters runner status

# Stop the runner from claiming more work.
curl -X POST http://bhunter/api/v1/admin/runner/drain

# Cancel the job of one scan (the API does it when the scan is stopped).
curl -X POST http://bhunter/api/v1/scans/<scan_id>/stop
```

Stopping a scan cancels its job. A job that was already leased is
cancelled by the runner when it notices that the scan was stopped; a job
that is still queued is cancelled in the queue.

## The settings

| Setting | Default | What it does |
|---|---|---|
| `BHUNTERS_RUNNER_CONCURRENCY` | `1` | How many jobs one runner executes at a time. One operator, one at a time. |
| `BHUNTERS_RUNNER_LEASE_SECONDS` | `60` | How long a claimed job is owned before it can be reclaimed. |
| `BHUNTERS_RUNNER_HEARTBEAT_SECONDS` | `10` | How often the lease is pushed forward. |
| `BHUNTERS_RUNNER_POLL_SECONDS` | `2.0` | How long the runner waits when there is nothing to do. |
| `BHUNTERS_RUNNER_SHUTDOWN_GRACE_SECONDS` | `300` | How long a SIGTERM waits for the current job. |
| `BHUNTERS_JOB_MAX_ATTEMPTS` | `3` | How many times a failed job is retried. |
| `BHUNTERS_SECRET_KEY` | — | The key that encrypts the stored credentials. The API and the runner need the same one. |

## The collections

| Collection | What it holds |
|---|---|
| `platform_jobs` | The queue: the status, the priority, the lease, the attempts, the payload. |
| `platform_target_locks` | The one-scan-per-target leases, with a TTL so a dead runner's lock expires. |
| `platform_runner_heartbeats` | One row per runner: the identity, the last time it was seen, the job it is working on. |
