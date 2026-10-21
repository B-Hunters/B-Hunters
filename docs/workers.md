# The scanner workers: contract, containers and verification

This document covers the 17 scanner workers: how they talk to Karton, how
they are built as containers, how their output is verified, and what was
wrong with them.

---

## 1. The message contract

Every worker is a Karton consumer.  It declares the task headers it binds
to, and it reads a fixed set of payload keys.

### The task headers

| Task type | Stage | Produced by | Consumed by |
|---|---|---|---|
| `domain` | `new` | the CLI producer | `subrecon` |
| `subdomain` | `new` | `subrecon` | `nmap`, `dirsearch`, `paramspider`, `wayback`, `gowitness`, `wapiti`, `xray`, `sqlmap`, `nuclei`, `webtechnology` |
| `url` | `new` | the crawlers | `getjs`, `gospider`, `katana`, `webtechnology` |
| `path` | `new` | `dirsearch` | `getjs`, `gospider`, `katana`, `webtechnology` |
| `paths` | `scan` | the crawlers | `nuclei`, `sqlmap`, `dalfox`, `ssti` |
| `js` | `new` | the crawlers | `jsscanner` |

Karton **forks** a task to every consumer whose filter matches, so all
twelve workers bound to `subdomain`/`new` receive the task.

### The payload keys

| Key | Scope | Meaning |
|---|---|---|
| `data` | per task | the URL or path being processed |
| `subdomain` | per task | the host being processed |
| `source` | per task | which module produced the task |
| `file` | per task | the JavaScript asset URL (`js` tasks) |
| `report_id` | persistent | the report document the worker writes to |
| `scan_id` | persistent | the scan |
| `domain` | persistent | the root domain of the scan |
| `scantype` | persistent | `single` or `multi` |

**The host being processed is `subdomain`, never `domain`.**  `domain` is
the root of the scan and is only there for reporting.  A worker that took
the host from `domain` would process the root domain once per discovered
subdomain in a multi-domain scan.

### The S3 artefact key

A worker that consumes a `paths`/`scan` task downloads its input from the
artefact store:

```
key = f"{source}_{scan_id}_{encode_filename(data)}"
```

The producer uploads the file under **the same key**, using the same
`data` value.  The crawlers send the URL *without* the scheme in the
`data` payload, and the scanners strip the scheme the same way, so the
two agree.  The `encode_filename` helper replaces the characters that a
filesystem rejects and shortens a name that is too long.

---

## 2. Reporting the status

Every worker reports its progress the same way, through the shared
`update_task_status` helper in the base class:

```python
self.update_task_status(subdomain, "Started")
...
self.update_task_status(subdomain, "Finished")   # or "Failed"
```

The helper records the worker's own identity in the domain document's
`status.processing`, `status.finished` and `status.failed` arrays, and
sends a Discord notification.

**Two rules make this work, and both were broken:**

1. **The status key must be the host being processed.**  Reporting
   against a JavaScript asset URL, as `jsscanner` did, matches no domain
   document, so the status is silently lost.
2. **The failure must propagate.**  The helper used to compare the
   status against `"failed"` while the workers pass `"Failed"`, so the
   exception was never raised and a failed task was recorded as
   successfully finished.  Karton now sees the failure, and the task is
   retried or marked as crashed instead of disappearing.

### The identity

Karton's configuration **overrides** a worker's class-level `identity`:

```python
if self.config.has_option("karton", "identity"):
    self.identity = self.config.get("karton", "identity")
```

A shared configuration file that names an identity therefore makes *every*
worker register under the same name, which breaks both the queue routing
and the status records.  The worker configuration deliberately has **no**
`[karton] identity` option, so each worker uses its own.

---

## 3. Checking the contract

The contract is verified statically, so a worker that drifts fails a test
rather than a scan.

```bash
b-hunters contracts --workers /path/to/the/repositories
```

```text
Checked 17 worker repositories
```

and as a test:

```bash
BHUNTERS_WORKER_ROOT=/path/to/the/repositories pytest tests/integration/test_worker_contracts.py -q
```

The verifier reads the worker sources and checks that:

* every worker declares an identity and at least one task filter;
* every payload key a worker reads is written by somebody;
* the host comes from `subdomain`, not from the root `domain`;
* the status is reported against the host being processed;
* every worker reports its status at all;
* no two workers share an identity;
* no worker binds to a task type that nothing produces;
* no worker emits a task type that nobody consumes.

### What it found

| Defect | Worker | Fix |
|---|---|---|
| The status was reported against the asset URL | `jsscanner` | Report against the subdomain |
| The status was never reported | `GetJS`, `Web-Technology` | Report `Started`/`Finished`/`Failed` |
| The status referenced an undefined variable | `Web-Technology` | Use the subdomain; the worker raised a `NameError` on every task |
| The scan ran twice | `Web-Technology` | Run it once |
| The filters depended on an environment variable | `Nuclei` | Always bind to both filters and decide at run time |
| A dead `type: file` key in the payload | `GoSpider`, `Katana`, `ParamSpider`, `Wayback` | Removed |
| The tool was called with a flag that no longer exists | `Web-Technology` | Use the tool's JSON output |

---

## 4. Building the workers

Every worker is a container.  The images are built from the worker
repositories, and they install `b-hunters` from PyPI:

```dockerfile
RUN pip install --no-cache-dir b-hunters==1.2.0
```

```bash
for worker in nuclei katana dalfox sqlmap nmap gospider getjs jsscanner \
              paramspider ssti subrecon wapiti wayback webtechnology xray dirsearch gowitness; do
  case "$worker" in
    nuclei)      dir=B-Hunters-Nuclei ;;
    katana)      dir=B-Hunters-Katana ;;
    dalfox)      dir=B-Hunters-DalFox ;;
    sqlmap)      dir=B-Hunters-Sqlmap ;;
    nmap)        dir=B-Hunters-NMap ;;
    gospider)    dir=B-Hunters-GoSpider ;;
    getjs)       dir=B-Hunters-GetJS ;;
    jsscanner)   dir=B-Hunters-jsscanner ;;
    paramspider) dir=B-Hunters-ParamSpider ;;
    ssti)        dir=b-hunters-SSTI-Checker ;;
    subrecon)    dir=B-Hunters-Subrecon ;;
    wapiti)      dir=B-Hunters-Wapiti ;;
    wayback)     dir=B-Hunters-Wayback ;;
    webtechnology) dir=B-Hunters-Web-Technology ;;
    xray)        dir=B-Hunters-xray ;;
    dirsearch)   dir=B-Hunters-Dirsearch ;;
    gowitness)   dir=B-Hunters-gowitness ;;
  esac
  docker build -q -t "b-hunters-local/$worker:1.2.0" "repos/$dir"
done
```

### The toolchain problems that had to be fixed

| Worker | Problem | Fix |
|---|---|---|
| `Katana` | `golang:1.21.1` cannot build the current release | `golang:1.26`, the tool pinned to `v1.8.0` |
| `Gowitness` | the same Go version problem | `golang:1.26-bookworm` |
| `GetJS` | the module path has upper case letters, which the Go proxy rejects, and the release predates Go modules | Build from a pinned clone with the module initialised in the build |
| `Web-Technology` | the tool was rewritten in Go, so `pip install` no longer works, and the worker still used the old flags and text format | Build the binary from a pinned commit and read its JSON output |

---

## 5. Verifying a worker's output

`verify_workers.py` starts each worker against the live stack, sends it
the task type it binds to, and checks three things:

1. the worker reported its status under **its own identity**;
2. the status ended in `finished` or `failed` rather than disappearing;
3. the worker wrote something into the report field it is responsible for.

The path scanners are given their input the same way a real scan gives it
to them: the harness uploads the URL list to the artefact store under the
key the worker downloads it from.

```bash
python verify_workers.py nmap nuclei dalfox sqlmap
```

```
worker           status       reported   output
nmap             ok           finished   {"Ports": 1}
nuclei           ok           finished   {"Vulns": 0}
dalfox           ok           finished   {"Vulns": 0}
sqlmap           ok           finished   {"Vulns": 0}
```

A `Vulns: 0` result is a correct result: the tool ran and found nothing
on the target.  The point of the check is that the worker **ran** and
**reported**, not that it found something.
