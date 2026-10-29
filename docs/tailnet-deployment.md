# Running B-Hunters on the tailnet

The platform is deployed as a Docker Compose stack whose only public
address is a **Tailscale node named `bhunter`**. Nothing is published on the
host's public interfaces: the platform container shares the network
namespace of a Tailscale sidecar, so it *is* the node.

```
              ┌──────────────────────────────────────┐
  tailnet     │  bhunter.tail057c15.ts.net  (100.x)  │
              └──────────────────┬───────────────────┘
                                 │  the platform container shares
                                 │  the sidecar's network namespace
   ┌─────────────────────────────▼──────────────────────────────┐
   │  bhunter_platform      the API, the web console, agents   │
   │  bhunter_ts            the Tailscale node (sidecar)       │
   │  bhunter_mongo         bhunter_redis   bhunter_s3        │
   │  bhunter_karton        the task router                   │
   │  bhunter_worker_*      the scanner workers               │
   └──────────────────────────────────────────────────────────┘
```

---

## 1. Prerequisites

* Docker with the Compose plugin.
* The `NET_ADMIN` and `SYS_MODULE` capabilities, and `/dev/net/tun` — the
  Tailscale sidecar needs them to create the tunnel.
* A Tailscale auth key, and a tailnet that allows the key to be used.

The auth key lives in the workspace `.env`:

```
TS_AUTHKEY=tskey-auth-...
```

**Never commit that file.** It is excluded by `.gitignore`, and the
Compose file reads it with `--env-file` rather than baking it into an
image.

---

## 2. Build the worker images

The scanner workers are separate images, built from their own
repositories:

```bash
for worker in nuclei katana dalfox sqlmap nmap webtechnology; do
  case "$worker" in
    nuclei)         dir=B-Hunters-Nuclei ;;
    katana)         dir=B-Hunters-Katana ;;
    dalfox)         dir=B-Hunters-DalFox ;;
    sqlmap)         dir=B-Hunters-Sqlmap ;;
    nmap)           dir=B-Hunters-NMap ;;
    webtechnology)  dir=B-Hunters-Web-Technology ;;
  esac
  docker build -q -t "b-hunters-local/$worker:1.2.0" "../repos/$dir"
done
```

---

## 3. Start the stack

```bash
cd repos/B-Hunters
docker compose --env-file ../../.env -f docker-compose.platform.yml up -d --build
```

The first start takes a moment: the Tailscale sidecar has to join the
tailnet before the platform is reachable.

Check that the node appeared:

```bash
tailscale status | grep bhunter
```

```
100.97.164.87    bhunter    bormaaalking@    linux    -
```

---

## 4. Use it

The console is at the MagicDNS name:

```
http://bhunter
```

The API documentation is at `http://bhunter/api/docs`.

The Karton dashboard is a second tailnet node, named `karton-dashboard`.
It shows which services are connected to the task router, what each of
them binds to, and the tasks that are pending or crashed:

```
http://karton-dashboard
```

It has no authentication and it can restart and cancel tasks, so it is
published on the tailnet and on the loopback interface of the host only.

Create the first administrator:

```bash
docker exec bhunter_platform b-hunters admin bootstrap --username admin
```

The platform and the workers must share **one MongoDB database**, or the
workers will write their results where the platform does not look for
them. The Compose file gives them the same `b-hunters` database, and the
`mongo` service is the only database in the stack.

---

## 5. The two configuration files

| File | Used by | Contains `[karton] identity`? |
|---|---|---|
| `deploy/platform.ini` | the platform, the task router | **yes** — `B-Hunters-Platform` |
| `deploy/b-hunters.ini` | the scanner workers | **no** |

The reason is in Karton itself:

```python
# karton/core/base.py
if self.config.has_option("karton", "identity"):
    self.identity = self.config.get("karton", "identity")
```

The configuration **overrides** the worker's class-level identity. A
shared configuration that names an identity therefore makes every worker
register under the same name: they compete for the same queue and
overwrite each other's status records. Leaving the option out of the
worker configuration lets each worker use its own identity.

The platform and the router *do* need an identity, so they get their own
file.

---

## 6. Operating it

```bash
# The state of the stack.
docker compose -f docker-compose.platform.yml ps

# The platform's log.
docker logs -f bhunter_platform

# The tailnet node's own log.
docker logs -f bhunter_ts

# The live queue state (through the API).
curl -s -b cookies.txt http://bhunter/api/v1/karton/state | jq .totals
```

The *Karton & workers* page of the console shows the same state.

---

## 7. Troubleshooting

### The platform is not reachable over the tailnet

```bash
tailscale status | grep bhunter     # is the node there?
docker logs bhunter_ts | tail -20   # did it authenticate?
```

A Tailscale sidecar needs `--cap-add NET_ADMIN --cap-add SYS_MODULE`
and the `/dev/net/tun` device. Without them it cannot create the
tunnel, and the log says so.

### The workers are up but the queues are empty

The workers are not sharing the Redis of the platform. Check that
`deploy/b-hunters.ini` points at the same `redis` service the platform
uses, and that the password matches.

### The Karton page shows "Internal Server Error"

An old image. Karton's `KartonQueue.last_update` raises
`ValueError: max() iterable argument is empty` for a queue that has not
seen a task, and the platform now guards that case. Rebuild:

```bash
docker compose --env-file ../../.env -f docker-compose.platform.yml up -d --build platform
```

### The node joins with the wrong name

The hostname comes from `BHUNTER_TS_HOSTNAME` (default `bhunter`):

```bash
docker compose --env-file ../../.env -f docker-compose.platform.yml up -d --force-recreate tailscale-bhunter
```

### The node appears but the platform does not

The platform shares the sidecar's network namespace, so it is bound to
the same addresses. If the platform container is not `running`, check its
log: it will not start until MongoDB, Redis and the artefact store are
healthy.

---

## 8. Security notes

* The platform is **not** published on the host's public interfaces. It is
  reachable from the tailnet only.
* The session cookie is set with `Secure=false` in the development
  Compose file, because Tailscale serves plain HTTP over the tunnel. Set
  `BHUNTERS_SESSION_COOKIE_SECURE=true` once the platform is served
  over HTTPS.
* The development credentials in the Compose file are development
  credentials. Replace them before the stack is used for anything real.
* The tailnet is an authentication boundary, not a defence against a
  compromised tailnet member. The platform still authenticates every
  request.
