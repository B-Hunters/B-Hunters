# The scope of a scan, and the load it puts on a target

**Date:** 2026-11-18
**Status:** implemented
**Covers:** A1–A4 of the rebaseline, and the resource findings of the
2026-11-18 audit

---

## 1. The problem

Three things came together.

**The fleet ran everything, every time.** The Karton router hands a task to
*every* consumer whose filters match it. A task for `subdomain`/`new`
therefore reached thirteen workers whatever the scan asked for. The native
adapters had always respected the profile's scanner list; the workers did
not. A recon scan ran sqlmap, xray and ffuf against the target as well, at
the same time — and the platform's own rate limit and safe-mode settings
govern only the requests the *platform* makes, not the ones a worker makes
from its own container.

**The scope could not be expressed.** A bug bounty programme names the
assets that are out of scope. The wildcard that covers the domain covers
them too — Rapyd's in-scope entry is `*.rapyd.net`, and its out-of-scope
list names `community.rapyd.net`, `support.rapyd.net`, `docs.rapyd.net`,
`sandbox.rapyd.net` and `ghost.rapyd.net`. The platform had no way to say
"not these". Worse, the API *rejected* a wildcard authorised host, even
though the scope engine has always matched `*.example.com`: the validator
was stricter than the matcher, so the most useful way of expressing a scope
was unreachable.

**Nothing was bounded.** The job that deletes expired events, artefacts and
sessions was written and never called. The screenshot worker wrote the body
of every page, the cookie jar and the network log into the report — the
target's own session, in a database every later scan reads back. And the
base images were not pinned, so a rebuild re-resolved `ubuntu:latest` and
re-downloaded and re-compiled every toolchain: fifty minutes for one image
of seventeen, a build cache of fifteen gigabytes, and a machine that stopped
answering.

---

## 2. The design

### 2.1 The exclusions of a scan

`targets.denied_hosts` names the hosts a scan must not touch, even when a
wildcard covers them. They are enforced in two places, because the workers
are separate containers that discover hosts of their own:

* the **platform** refuses the target outright, and its own adapters never
  request a denied host;
* the **workers** inherit the list with the task and refuse the host before
  they send their first request.

The refusal happens in `update_task_status(host, "Started")` — the point
every worker passes through on its way to the target, and the point before
the tool is invoked.

### 2.2 The workers a scan asked for

`enabled_workers` names the workers the scan wants. It travels with the
task, and a worker that is not on it ends the task without touching the
target — the same way Karton ends a task whose binds are no longer valid.

The platform computes it from the profile's scanner list, through a map
from the scanner names to the worker identities. A scanner name that names
no worker is one of the native adapters, which run inside the platform, and
is ignored.

The two halves of a scan now agree: the native adapters have always
respected the profile, and so do the workers.

### 2.3 The load

* The base images are **pinned by digest**, and the fleet is on one Python
  version. The workers that were on 3.10 could not be built at all:
  `dirsearch` needs a compiler that the slim image does not have.
* The load a worker puts on a target is **the operator's choice**:
  `SQLMAP_PROCESSES`, `DALFOX_WORKERS` and `SSTI_PROCESSES` override the
  defaults.
* The **retention job runs**, once an hour, in the runner.
* The report keeps the **metadata**, not the bodies: the page body, the
  cookie jar, the network log and any `Set-Cookie` header are dropped
  before the record is stored.

---

## 3. What it costs

| Measure | Before | After |
|---|---|---|
| Workers running for a recon scan | 13 | the 3 the profile names |
| Hosts a worker may touch outside the programme's scope | all of them | none |
| Retention | never | hourly |
| Page bodies in the report | every page | none |
| Session cookies in the database | every page | none |
| Rebuild of one worker image | ~50 minutes | a few minutes |
| Reproducibility of a build | the base image moved under it | the base is a digest |

---

## 4. The measurements that produced it

```
$ docker stats --no-stream
bhunter_platform   120.8MiB / 31.24GiB   0.38%
bhunter_lab_juice_shop  176.2MiB / 16GiB 1.08%
$ free -h
Mem:  31Gi  used 2.9Gi  free 25Gi
```

The running fleet was never the problem — it used about a gigabyte of
thirty-one. The build was: the cache reached fifteen gigabytes, every
toolchain was compiled again because the base tag had moved, and the disk
was at eighty-six per cent.

```
$ docker system df
Build Cache     67   29   11.52GB
```

The disk was the constraint, and the unpinned base images were what made
every build a fresh download of the world.
