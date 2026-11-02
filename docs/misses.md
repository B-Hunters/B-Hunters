# What was missed, and why

A verification run over the three laboratory applications, scored with
the platform's own manifests and its own matching rules:

```bash
python tools/report_misses.py
```

Thirteen test cases were missed. They are not thirteen defects in the
platform: **nine of them are applications the platform never scanned**,
and the four that are real misses all have the same cause.

---

## The applications that were not scanned (9)

| Application | Cases | Why |
|---|---|---|
| **crAPI** | 5 — BOLA, JWT claims not validated, mass assignment, API discovery, missing headers | The image is not reachable from this registry, so there was nothing to scan |
| **Mutillidae** | 4 — reflected XSS, SQL injection, SSTI, missing headers | The same |

These are not misses of detection. They are misses of *coverage*, and
the platform says so: the applications have manifests and no running
container. Pulling the images is the fix, and it is a different piece of
work from anything the platform does.

---

## The four real misses

### 1. `juice-sqli` — the SQL injection in the product search

**Expected:** `GET /rest/products/search?q=` concatenates its argument
into a SQL query.

**It is there.** Probed by hand during this investigation:

```
GET /rest/products/search?q=ip
  -> {"status":"success","data":[...]}
GET /rest/products/search?q=a'
  -> <title>Error: SQLITE_ERROR: near "'%'": syntax error</title>
```

**sqlmap would have found it.** Given that URL, with the flags the
worker now uses, sqlmap reports it in fifty seconds:

```
[03:47:21] GET parameter 'q' appears to be 'AND boolean-based blind' injectable
[03:47:22] GET parameter 'q' is 'SQLite >= 3.9 AND error-based' injectable
[03:48:06] GET parameter 'q' appears to be 'SQLite > 2.0 AND time-based blind' injectable
```

**Why it was missed.** The scanner that was supposed to test it never
got the URL, and it never will: the crawler hands the scanners a
*deduplicated, parameterised* subset of what it found, and that subset
does not contain the search endpoint.

The crawler's link list for the laboratory holds 67 links. Put through
the scanner's own pipeline — `grep "="`, `uro --filter hasparams`,
`qsreplace FUZZ` — it collapses to **one** URL:

```
http://172.25.0.13:3000/socket.io/?EIO=FUZZ&sid=FUZZ&t=FUZZ&transport=FUZZ
```

The REST routes of a single-page application are in its JavaScript
bundle, not in the links a crawler follows. The crawler found the
websocket endpoint; the API surface is the `javascript` role's
business, and nothing hands the two together.

**The second cause.** The URL list is also uploaded to the object
store, and **Karton's garbage collector deletes it within a minute**:
a probe object was uploaded and gone within sixty seconds, and no
object has survived in the bucket since the 29th of October. The
scanners that need the list are the ones that consume the crawler's
task, and they arrive after it has been deleted.

Which is visible in the results: of the workers, **nuclei** and
**wapiti** — the two that scan the target directly — produced
findings; **sqlmap**, **dalfox** and **ssti** — the three that consume
the crawler's URL list — produced none at all, in any scan, since the
middle of October. The new **ffuf** worker produced its own inventory
because it does not need the list.

### 2. `juice-js-api` — the JavaScript bundle's API surface

**Expected:** the shipped bundle is 1.2 MB and contains the whole API
route surface.

**What happened:** the `javascript` role ran and completed, and raised
a *note* — the bundle contains Angular template interpolation — rather
than a finding of the class the benchmark expects. The API routes were
in the bundle the whole time; nobody turned them into a finding.

This is the same seam as the first miss: the bundle is read by one role
and the routes are never handed to the scanner that could test them.

### 3. `juice-challenge-catalogue` — the challenge catalogue without a session

**Expected:** `GET /api/Challenges` is served without a session and
names the challenges, including `passwordHashLeakChallenge`.

**What happened:** the platform reported *an* unauthenticated disclosure
on the target ("Additional unauthenticated static/served paths"), but
not this one. The evidence the benchmark looks for — the challenge
names — was not in any finding.

### 4. `webgoat-route-discovery` — the application and its login page

**Expected:** the application and its login page are reachable.

**What happened:** the platform found the WebGoat surface — the
Spring Boot actuator endpoints, the missing headers, the WebSocket
upgrade — and reported them, but nothing of the class
`route_discovery`. The reachability itself was never stated as a
finding.

---

## The defect that hid all of it

The participation table reports what each worker did. It reads Karton's
**consumed** counter, and that counter moves when a task is *handed
over*. A worker that took a task, could not do the job, and finished
with nothing to show for it is reported as:

```
B-Hunters-SQLMap        ran, found nothing
```

That is true, and it is not enough. For two days and nine hours — from
the 30th of October at 21:29 until the fleet was restarted — every
worker in the fleet was reported as having run in every scan, and
**no scanner had done anything at all**: the crawler's list had been
deleted from the object store since the 29th of October, so the three
scanners that need it had nothing to test.

A report that says "ran, found nothing" is indistinguishable from a
report that says "ran, and there was nothing there". The second is a
result; the first is a question. The participation table has to answer
it.

---

## What is worth doing about it

1. **Hand the JavaScript bundle's routes to the scanners.** The
   `javascript` role already reads the bundle. Its routes should reach
   sqlmap, dalfox and nuclei the way the crawler's links do — otherwise
   the API surface of every single-page application is untested.
2. **Stop relying on the object store for the URL list.** It is deleted
   within a minute by the garbage collector. The database already holds
   the same list and it is durable; the scanners should read it from
   there.
3. **Say what a worker could not do.** A worker that consumed a task
   and produced nothing is not a worker that found nothing.
4. **Pull the crAPI and Mutillidae images**, or drop their manifests,
   so the score does not count applications that were never scanned.
