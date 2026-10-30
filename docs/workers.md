# The scanner workers: contract, containers and verification

This document covers the 17 scanner workers: how they talk to Karton, how
they are built as containers, how their output is verified, and what was
wrong with them.

`gospider` was in the fleet until it was retired: the project has not
been committed to since April 2024, and `katana` is its successor and is
already here.  `ffuf` replaced it — it mutates a value in a request,
which is what an object-level authorisation flaw needs, and the other
tools only enumerate names and paths.

---

## 1. The message contract

Every worker is a Karton consumer.  It declares the task headers it binds
to, and it reads a fixed set of payload keys.

### The task headers

| Task type | Stage | Produced by | Consumed by |
|---|---|---|---|
| `domain` | `new` | the CLI producer | `subrecon` |
| `subdomain` | `new` | `subrecon` | `nmap`, `dirsearch`, `paramspider`, `wayback`, `gowitness`, `wapiti`, `xray`, `sqlmap`, `nuclei`, `webtechnology` |
| `url` | `new` | the crawlers | `getjs`, `katana`, `webtechnology` |
| `path` | `new` | `dirsearch` | `getjs`, `katana`, `webtechnology` |
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
| A dead `type: file` key in the payload | `Katana`, `ParamSpider`, `Wayback` | Removed |
| The tool was called with a flag that no longer exists | `Web-Technology` | Use the tool's JSON output |

---

## 4. Building the workers

Every worker is a container.  The images are built from the worker
repositories, and they install `b-hunters` from PyPI:

```dockerfile
RUN pip install --no-cache-dir b-hunters==1.2.0
```

```bash
for worker in nuclei katana dalfox sqlmap nmap ffuf getjs jsscanner \
              paramspider ssti subrecon wapiti wayback webtechnology xray dirsearch gowitness; do
  case "$worker" in
    nuclei)      dir=B-Hunters-Nuclei ;;
    katana)      dir=B-Hunters-Katana ;;
    dalfox)      dir=B-Hunters-DalFox ;;
    sqlmap)      dir=B-Hunters-Sqlmap ;;
    nmap)        dir=B-Hunters-NMap ;;
    ffuf)        dir=B-Hunters-Ffuf ;;
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

---

## 6. The service inventory

### 6.1 What it answers

*What is running on this URL, which version is it, and which signal said
so?*  The inventory is stored per URL, so a scan accumulates a picture of
the estate instead of a list of unconnected observations.

### 6.2 The signals

The research on fingerprinting is consistent about which signals actually
work, so the platform combines the ones that carry information:

| Signal | What it identifies | Source |
|---|---|---|
| Banner grabbing | the web server and its version | `Server`, `X-Powered-By`, `Via`, `X-AspNet-Version`, `X-Runtime-Version` |
| Cookie analysis | the runtime | `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`, `laravel_session`, `Django`, `Rails` |
| Cookie *values* | exposed features | `env=graphiql:disable` means the GraphQL IDE is enabled |
| Meta tag analysis | the CMS and its version | `<meta name="generator" content="WordPress 6.4.2">` |
| Body markers | the framework | `/wp-content/`, `__next_data__`, `ng-version`, `csrfmiddlewaretoken`, `__viewstate` |
| Known path probing | the stack | `/wp-login.php`, `/elmah.axd`, `/server-status`, `/actuator` |
| Favicon hashing | the product | the MurmurHash3 of the base64-encoded favicon |
| TLS certificate | the appliance | the issuer: WebLogic, ISa2Go, BIG-IP, Barracuda |
| Header policy | the configuration | `Access-Control-Allow-Origin: *` is a permissive CORS policy |

Each identified service carries a **name**, a **version**, a **category**,
the **signal that identified it** and a **confidence**.  A version read
out of a banner is reported with a higher confidence than one inferred
from a body marker.

### 6.3 The tools it compares against

| Tool | Licence | What it is good at | Where it fits here |
|---|---|---|---|
| **Wappalyzer** | GPL-3.0 | 2,500+ signatures, the de-facto dataset | already used by the `webtechnology` worker (`wappy`), and merged into the same inventory |
| **httpx** | MIT | `-tech-detect` (Wappalyzer data on headers and body), the favicon hash, JARM, TLS, CDN detection | the same signals, in-process |
| **WhatWeb** | GPL-2.0 | 1,800+ plugins, the deepest version data | a good complement for a deployment that can run it |
| **wappscan** | GPL-3.0 | eight combined techniques in one binary | the technique list this module follows |
| **nmap NSE** | NPSL | service and operating system fingerprinting | already in the stack as the `nmap` worker; its banners are merged into the inventory |

The platform does not replace the workers: the `webtechnology` worker
supplies the Wappalyzer fingerprints and the `nmap` worker supplies the
service banners, and the native adapter supplies everything the workers
cannot see — the GraphQL IDE cookie, the CORS policy, the response
headers of the redirect that carries the session cookie.

### 6.4 The MurmurHash3

The favicon hash is the hash the search engines index, and the details
matter:

* it is MurmurHash3 **x86_32** with a seed of zero;
* the favicon is hashed **after base64 encoding**, and the encoding
  **includes the line breaks** — hashing the raw bytes gives a different
  value, which makes the lookup silently fail.

The implementation is verified against the five canonical MurmurHash3
test vectors, and against the published favicon hashes of live sites:

```
gitlab.com    1265477436   MATCH
paypal.com     309020573   MATCH
```

### 6.5 Precision: the false positives that were removed

The first version of the known-path probe treated "the path answered 200"
as proof of the stack.  A single-page application answers 200 with the
same document for **every** path, so the probe reported WordPress,
Joomla, Drupal and TYPO3 on an application that is none of them.

The probe now compares the response against the baseline response of the
site root — the body length and a hash of the body — and only reports a
stack when the document is genuinely different.  A fingerprint that names
a stack that is not there is worse than no fingerprint, because it sends
the operator after a vulnerability that does not exist.

There is a test for it:

```python
def test_a_plain_response_identifies_nothing() -> None:
    """A response with no stack signals must not produce a finding."""
```

### 6.6 Where the inventory lives

| Where | What |
|---|---|
| `platform_services` | one document per scan and URL, with the services, the headers, the cookies, the favicon hash and the certificate |
| `GET /api/v1/scans/{id}/services` | the inventory and its summary |
| the *Services* tab of the scan page | the inventory, per URL and aggregated |

The fingerprinting adapter is registered as `service_fingerprint` and is
part of the standard scan profile, so every scan produces the inventory
without any configuration.
