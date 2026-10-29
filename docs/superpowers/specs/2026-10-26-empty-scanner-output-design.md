# Design: why the scanner workers look empty, and what to change

Date: 2026-10-26
Status: approved (the operator pre-approved this design and asked for it to be
executed without further confirmation)

## The problem

A scan of DVGA produces findings from the native adapters and from some of
the worker containers, while five workers - `dalfox`, `sqlmap`,
`ssti-checker`, `paramspider` and (on some targets) `nuclei` - show nothing.
The console reports "ran, found nothing" for them, and the operator cannot
tell a true negative from a broken worker.

Three different problems are folded into that one symptom. They need
different fixes, and only one of them is a real defect.

### P1 - visibility (not a defect, but the reason it looks like one)

`dalfox`, `sqlmap` and `ssti` test **URLs that carry parameters**: they
filter the crawled list for a query string before they start. `paramspider`
looks for parameterised URLs in the first place. So on a target whose pages
carry no query string, they have nothing to test.

Measured, not assumed:

* **DVGA** - 128 URLs crawled. The six with a query string all belong to
  youtube.com, not to the target. The three scanners filter them out
  correctly, and are left with nothing.
* **Juice Shop** - an Angular application whose HTML carries no links. A
  crawler without a JavaScript engine finds nothing: `paramspider` reports
  0 URLs, and its `/sitemap.xml` is the single-page application rather than
  a sitemap. The crawler that does run a browser (`katana`) finds the
  application's 31 URLs, of which the only parameterised ones are the
  `socket.io` handshake URLs.
* **`nuclei`** needs no parameters at all and works: on Juice Shop it
  reported `[prometheus-metrics] [http] [medium] /metrics`.

So the empty results are mostly correct. The console does not say so.

### P2 - correlation by host instead of by scan (a real defect)

`checklinksexist()` in the shared base class records the URLs a scanner has
already checked in the legacy `scans` document, under
`ScanLinks.<worker identity>`. It finds that document with
`find_one({"Domain": subdomain})` - by **host**. A host can have several
scan documents, and `find_one` returns an arbitrary one of them.

The consequence: a second scan of the same host reads the *first* scan's
bookkeeping and treats those URLs as already checked, so it never tests
them. The laboratory is scanned repeatedly - DVGA is scanned on every run -
so this starves exactly the four scanners that need the list. The
bookkeeping must be per scan, not per host.

### P3 - a worker is only handed what one crawler found (a harness artefact)

The crawlers publish `paths/scan` tasks; the router delivers one copy to
each scanner, so a scanner receives the list of *every* crawler in a normal
concurrent scan. When one worker is tested alone, it receives whatever list
was addressed to it at that moment - and it may be the empty one. "Empty"
is therefore not evidence about the worker.

## What was considered

### A. Visibility only

Show, per scanner, how many candidate URLs it was given and how many of
them carried parameters. No behaviour change.

*Pros:* small, no risk, answers the operator's question directly.
*Cons:* leaves P2 in place, so a repeated scan still starves the scanners.

### B. Visibility, scan-keyed correlation, harness parity (recommended)

Fix P1, P2 and P3 together.

*Pros:* fixes the one real defect, makes the empty results explainable, and
makes the per-worker harness trustworthy.
*Cons:* the correlation fix touches the shared base class and the four
worker repositories that install the published package.

### C. Invent parameterised candidates for the scanners

Derive candidate URLs for the path scanners from the JavaScript assets or
by guessing parameter names, so they always have something to test.

*Rejected.* A scanner that tests URLs nobody linked is testing the
scanner's imagination; the results would be noise dressed up as coverage.
The GraphQL surface of DVGA is already covered by the native GraphQL
adapter, which reported five findings on it.

## The design

### 1. The bookkeeping is per scan, not per host

`checklinksexist()` uses the scan the task belongs to. The workers already
carry it: the platform publishes `scan_id` persistently, and the workers
read it into `self.scanid`.

```
scanid = self.scanid  (when the task carries one)
         the domain document's Scanid  (when it does not)
```

The domain document is then looked up by that scan id, not by host. A
second scan of the same host starts with an empty record and tests the
URLs again.

The change lives in `b_hunters/bhunter.py` (the source of the published
package) and is repeated in the four worker repositories that install the
published `b-hunters==1.2.0` and therefore do not see it until a release:
`B-Hunters-DalFox`, `B-Hunters-Sqlmap`, `b-hunters-SSTI-Checker`,
`B-Hunters-Nuclei`.

### 2. The console says how many candidates a scanner had

`GET /api/v1/scans/{id}/scanners` reports, per worker, the number of
candidate URLs the crawlers produced for the target and how many of them
carry parameters. A scanner that had nothing to test says so:

> ran, found nothing - 0 of 31 candidate URLs carried parameters

The counts come from the `links` collection of the report: the URLs the
crawlers stored, split by whether they carry a query string. Third-party
URLs are excluded, because the scanners filter them out too.

The console's *Scanners* tab shows the count in the status column and the
totals in the card header.

### 3. The per-worker harness gives a worker what a concurrent scan gives it

`dev/check_workers_one_by_one.py` publishes **every** task addressed to
the worker under test, not the ones that happen to be pending at that
moment, and records the candidate list it was given. The harness therefore
answers the same question a concurrent scan answers, and its result is
comparable with the console's.

### 4. What does not change

* The scanners keep testing only the target's own URLs.
* The native adapters keep their responsibility for the GraphQL surface.
* The console keeps the three states: **found**, **ran, found nothing**,
  **did not run**.

## Testing

| Test | What it proves |
|---|---|
| `tests/unit/test_checklinksexist.py` | the bookkeeping is keyed by the scan, not the host: a second scan of the same host gets the URLs back |
| `tests/unit/test_worker_output.py` | the candidate counts are right, and third-party URLs are not counted |
| the per-worker harness on DVGA | the four path scanners report "ran, found nothing - 0 of N candidate URLs carried parameters" instead of a bare empty |
| the per-worker harness on Juice Shop | `nuclei` reports its `prometheus-metrics` finding again |
| the full test suite | nothing else broke |

## Risks

* **The correlation fix changes what the scanners do on a repeated scan.**
  That is the point: they will now test URLs they skipped. A scan of a
  busy target will take longer.
* **The workers that pin the published package need the change repeated in
  their own repositories.** Until `b-hunters` is released with the fix,
  the two copies can drift. The comments in both places say so.
