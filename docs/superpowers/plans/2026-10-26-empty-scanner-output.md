# Empty Scanner Output — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the platform show why a scanner worker found nothing, and make
the scanners test the URLs of the scan they belong to instead of inheriting
the bookkeeping of an earlier scan of the same host.

**Architecture:** Two independent changes. (1) `checklinksexist()` in the
shared base class keys its "already checked" record by the **scan** the task
carries instead of by the **host**; the four worker repositories that install
the published `b-hunters==1.2.0` repeat the fix locally. (2) The platform's
scanners endpoint reports, per worker, how many candidate URLs the crawlers
produced and how many of them carried parameters, so an empty result explains
itself; the console renders it.

**Tech Stack:** Python 3.12, FastAPI, MongoDB (pymongo), Karton, pytest, ruff,
vanilla JavaScript console (no build step).

## Global Constraints

- The platform's MongoDB is the `b-hunters` database; the workers' MongoDB is
  the same instance. The platform Mongo is **not** published on the host.
- The workers install `b-hunters==1.2.0` from PyPI. A change to the shared base
  class is only live for the platform until a release carries it; the worker
  repositories must repeat it locally, with a comment saying so.
- The legacy `scans` document's `_id` is the `scan_id` the platform publishes
  persistently; `domains.Scanid` holds the same value as a string.
- A scanner may only test the **target's own** URLs: `is_on_target()` decides.
- Every change needs a test; `ruff check b_hunters tests` and
  `ruff format --check b_hunters tests` must stay clean.
- The test suite is run from `repos/B-Hunters` with
  `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"`.
- Nothing is committed or pushed without the operator asking.

---

### Task 1: Key the scanner bookkeeping by scan, not by host

**Files:**
- Modify: `b_hunters/bhunter.py` (`checklinksexist`)
- Test: `tests/unit/test_checklinksexist.py`

**Interfaces:**
- Consumes: `self.scanid` - the legacy `scans` document id, set by the workers
  from `task.payload_persistent["scan_id"]`. `self.identity` - the worker's
  identity, used as the key of the record.
- Produces: `checklinksexist(subdomain, links) -> list[str]` - the links of
  this scan that this worker has not checked yet.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_checklinksexist.py`:

```python
"""The bookkeeping of the scanners is per scan, not per host.

``checklinksexist`` records the URLs a scanner has already checked in the
legacy ``scans`` document.  It used to find that document by host, and a
host can have several scans: a second scan of the same host read the first
scan's record and treated those URLs as checked, so it never tested them.
"""

from __future__ import annotations

from typing import Any

import pytest

from b_hunters.bhunter import BHunters


class _Collection:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents

    def find_one(self, query: dict[str, Any]) -> Any:
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None

    def update_one(self, query: dict[str, Any], update: dict[str, Any]) -> Any:
        document = self.find_one(query)
        if document is not None:
            for key, value in update.get("$push", {}).items():
                bucket, _, field = key.partition(".")
                document.setdefault(bucket, {}).setdefault(field, []).extend(
                    value.get("$each", [])
                )
        return None


class _Database:
    def __init__(self, scans: list[dict[str, Any]], domains: list[dict[str, Any]]) -> None:
        self._collections = {"scans": _Collection(scans), "domains": _Collection(domains)}

    def __getitem__(self, name: str) -> Any:
        return self._collections[name]


class _Worker(BHunters):
    """The base class without its Karton and Mongo plumbing."""

    def __init__(self, database: Any, scanid: str = "") -> None:
        self.db = database
        self.scanid = scanid

    def process(self, task: Any) -> None:  # noqa: D102 - abstract method
        raise NotImplementedError


def _worker(scanid: str, scans: list[dict[str, Any]]) -> _Worker:
    from bson import ObjectId

    worker = _Worker(
        _Database(scans, [{"Domain": "172.25.0.15:5013", "Scanid": scanid}]),
        scanid,
    )
    worker.identity = "B-Hunters-DalFox"
    return worker


def test_a_second_scan_of_the_same_host_gets_the_urls_again() -> None:
    from bson import ObjectId

    first = ObjectId()
    second = ObjectId()
    scans = [
        {"_id": first, "Domain": "172.25.0.15:5013"},
        {"_id": second, "Domain": "172.25.0.15:5013"},
    ]
    url = "http://172.25.0.15:5013/graphql"

    first_worker = _worker(str(first), scans)
    assert first_worker.checklinksexist("172.25.0.15:5013", [url]) == [url]

    second_worker = _worker(str(second), scans)
    assert second_worker.checklinksexist("172.25.0.15:5013", [url]) == [url], (
        "the second scan of a host has to test the URL again"
    )


def test_within_one_scan_a_url_is_checked_once() -> None:
    from bson import ObjectId

    scan = ObjectId()
    scans = [{"_id": scan, "Domain": "172.25.0.15:5013"}]
    url = "http://172.25.0.15:5013/graphql"

    worker = _worker(str(scan), scans)
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == [url]
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == []


def test_a_link_of_another_host_is_never_checked() -> None:
    from bson import ObjectId

    scan = ObjectId()
    scans = [{"_id": scan, "Domain": "172.25.0.15:5013"}]
    worker = _worker(str(scan), scans)

    assert worker.checklinksexist(
        "172.25.0.15:5013", ["https://www.youtube.com/watch?v=1"]
    ) == []


def test_a_worker_without_a_scan_id_falls_back_to_the_domain_document() -> None:
    from bson import ObjectId

    scan = ObjectId()
    scans = [{"_id": scan, "Domain": "172.25.0.15:5013"}]
    worker = _Worker(
        _Database(scans, [{"Domain": "172.25.0.15:5013", "Scanid": str(scan)}]), ""
    )
    worker.identity = "B-Hunters-DalFox"

    url = "http://172.25.0.15:5013/graphql"
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == [url]
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/unit/test_checklinksexist.py -q`
Expected: FAIL - `test_a_second_scan_of_the_same_host_gets_the_urls_again` fails,
because the second worker reads the first scan's record.

- [ ] **Step 3: Write the minimal implementation**

In `b_hunters/bhunter.py`, replace the body of `checklinksexist` with:

```python
    def checklinksexist(self,subdomain,links):
        missing_links=[]
        if links =="":
            return []
        if isinstance(links,str):
            links=links.splitlines()

        # Only the target itself is scanned.  A link to a third-party host
        # is not a finding of the target, and probing it spends the
        # scanner's budget on somebody else's website.
        links = [link for link in links if self.is_on_target(subdomain, link)]
        if not links:
            return []

        self.waitformongo()
        collection=self.db["domains"]

        # The record of what has been checked belongs to the scan, not to
        # the host.  A host can have several scans - the laboratory is
        # scanned again and again - and a host-keyed record makes the
        # second scan skip the URLs it has never tested.
        scanid = getattr(self,"scanid","") or ""
        if not scanid:
            existing_document = collection.find_one({"Domain": subdomain})
            if existing_document is None:
                self.log.error("No document found for the specified domain.")
                return []
            scanid = existing_document["Scanid"]

        collection=self.db["scans"]
        existing_document = collection.find_one({"_id": ObjectId(scanid)})
        if existing_document is None:
            self.log.error(f"No scan document found for the scan id {scanid}.")
            return []
        existing_links = existing_document.get("ScanLinks", {}).get(self.identity, [])
        missing_links = [link for link in links if link not in existing_links]
        if missing_links:
            collection.update_one({"_id": ObjectId(scanid)}, {"$push": {f"ScanLinks.{self.identity}": {"$each": missing_links}}})
        return missing_links
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/unit/test_checklinksexist.py -q`
Expected: PASS - 4 passed.

- [ ] **Step 5: Run the whole suite and the linter**

Run: `pytest tests/ -q` and `ruff check b_hunters tests` and
`ruff format --check b_hunters tests`
Expected: all tests pass, no lint findings.

- [ ] **Step 6: Commit**

```bash
git add b_hunters/bhunter.py tests/unit/test_checklinksexist.py
git commit -m "fix: key the scanner bookkeeping by scan, not by host"
```

---

### Task 2: Repeat the fix in the four worker repositories

The workers install `b-hunters==1.2.0` from PyPI, so they do not see the
change until a release carries it. Each of the four repositories that call
`checklinksexist` gets a local copy.

**Files:**
- Modify: `repos/B-Hunters-DalFox/dalfox/dalfox.py`
- Modify: `repos/B-Hunters-Sqlmap/sqlmapm/sqlmapm.py`
- Modify: `repos/b-hunters-SSTI-Checker/sstichecker/sstichecker.py`
- Modify: `repos/B-Hunters-Nuclei/nucleim/nucleim.py`

**Interfaces:**
- Consumes: `self.scanid` (the legacy `scans` document id), `self.identity`,
  `self.db`, `self.waitformongo()`, `self.is_on_target(subdomain, link)`.
- Produces: `checklinksexist(subdomain, links) -> list[str]` - the same
  contract as the base class.

- [ ] **Step 1: Add the local method to the four workers**

In each of the four files, add this method to the worker class (next to the
existing `url_list` method), and add the `is_on_target` helper it uses (the
four workers already have it):

```python
    def checklinksexist(self, subdomain, links):
        """The links of this scanner that this scan has not checked yet.

        The shared base class in the published ``b-hunters`` package keys
        its record by host, and a host can have several scans: the second
        scan of a host reads the first scan's record and skips the URLs it
        has never tested.  The lookup is repeated here until a release of
        the package carries the fix.
        """
        missing_links = []
        if links == "":
            return []
        if isinstance(links, str):
            links = links.splitlines()

        links = [link for link in links if is_on_target(subdomain, link)]
        if not links:
            return []

        self.waitformongo()
        scanid = getattr(self, "scanid", "") or ""
        if not scanid:
            document = self.db["domains"].find_one({"Domain": subdomain})
            if document is None:
                self.log.error("No document found for the specified domain.")
                return []
            scanid = document["Scanid"]

        document = self.db["scans"].find_one({"_id": ObjectId(scanid)})
        if document is None:
            self.log.error(f"No scan document found for the scan id {scanid}.")
            return []
        existing = document.get("ScanLinks", {}).get(self.identity, [])
        missing_links = [link for link in links if link not in existing]
        if missing_links:
            self.db["scans"].update_one(
                {"_id": ObjectId(scanid)},
                {"$push": {f"ScanLinks.{self.identity}": {"$each": missing_links}}},
            )
        return missing_links
```

Check that each file imports `ObjectId` (`from bson.objectid import ObjectId`);
add the import where it is missing.

- [ ] **Step 2: Check the four files parse**

Run: `for f in ../B-Hunters-DalFox/dalfox/dalfox.py ../B-Hunters-Sqlmap/sqlmapm/sqlmapm.py ../b-hunters-SSTI-Checker/sstichecker/sstichecker.py ../B-Hunters-Nuclei/nucleim/nucleim.py; do python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f" && echo "ok $f"; done`
Expected: four `ok` lines.

- [ ] **Step 3: Rebuild the four images**

Run, from `repos/B-Hunters`:

```bash
docker build -q -t b-hunters-local/dalfox:1.2.0 ../B-Hunters-DalFox
docker build -q -t b-hunters-local/sqlmap:1.2.0 ../B-Hunters-Sqlmap
docker build -q -t b-hunters-local/ssti:1.2.0 ../b-hunters-SSTI-Checker
docker build -q -t b-hunters-local/nuclei:1.2.0 ../B-Hunters-Nuclei
```

Expected: four image ids.

- [ ] **Step 4: Recreate the four containers**

A rebuilt image does not change a running container; `start` alone is not
enough.

Run: `docker compose --env-file /home/sniper/pentest/.env -f docker-compose.platform.yml up -d worker-dalfox worker-sqlmap worker-ssti worker-nuclei`
Expected: four containers recreated and started.

- [ ] **Step 5: Commit the four repositories**

In each of the four repositories:

```bash
git add -A
git commit -m "fix: key the scanner bookkeeping by scan, not by host"
```

---

### Task 3: Say how many candidates a scanner had

**Files:**
- Modify: `b_hunters/platform/scanners/worker_output.py`
- Modify: `b_hunters/platform/api/routers/scans.py`
- Modify: `b_hunters/web/app.js`
- Test: `tests/unit/test_worker_output.py`

**Interfaces:**
- Consumes: the `links` collection of the report; `count_items()`,
  `is_on_target()` (both in `worker_output.py`).
- Produces: `scanner_report(...) -> dict` gains
  `"summary": {"crawled_urls": int, "urls_with_parameters": int}` and every
  worker gains `"candidates": int` - the number of candidate URLs that
  carried parameters, which is what a path scanner can test.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_worker_output.py`:

```python
"""How many candidates a scanner had.

The path scanners test the URLs that carry parameters.  A target whose
pages carry none leaves them with nothing, and the console has to say so
rather than show an empty result.
"""

from __future__ import annotations

from typing import Any

from b_hunters.platform.scanners import worker_output


class _Collection:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents

    def find(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            document
            for document in self.documents
            if all(document.get(key) == value for key, value in query.items())
        ]

    def find_one(self, query: dict[str, Any]) -> Any:
        found = self.find(query)
        return found[0] if found else None


class _Database:
    def __init__(self, links: list[dict[str, Any]]) -> None:
        self._collections = {"links": _Collection(links)}

    def collection(self, name: str) -> Any:
        return self._collections[name]


def test_the_candidates_are_the_urls_that_carry_parameters() -> None:
    links = [
        {
            "report_id": "r",
            "source": "B-Hunters-Katana",
            "Links": [
                "http://172.25.0.15:5013/graphql?query=1",
                "http://172.25.0.15:5013/audit",
                "https://www.youtube.com/watch?v=1",
            ],
        }
    ]
    database = _Database(links)

    report = {"_id": "r"}
    produced = worker_output.produced(database, report)

    assert worker_output.candidates(database, report) == {
        "crawled_urls": 3,
        "urls_with_parameters": 1,
    }


def test_a_target_without_parameters_leaves_nothing_to_test() -> None:
    links = [
        {
            "report_id": "r",
            "source": "B-Hunters-Katana",
            "Links": ["http://172.25.0.15:5013/audit", "http://172.25.0.15:5013/"],
        }
    ]
    database = _Database(links)

    counts = worker_output.candidates(database, {"_id": "r"})

    assert counts["crawled_urls"] == 2
    assert counts["urls_with_parameters"] == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/unit/test_worker_output.py -q`
Expected: FAIL - `worker_output.candidates` does not exist.

- [ ] **Step 3: Write the minimal implementation**

In `b_hunters/platform/scanners/worker_output.py`, add:

```python
def candidates(database: Any, report: dict[str, Any]) -> dict[str, int]:
    """What the crawlers found, and how much of it a scanner can test.

    A path scanner tests the URLs that carry parameters.  The third-party
    URLs are left out, because the scanners filter them out too.
    """
    crawled = 0
    with_parameters = 0
    for link in database.collection("links").find({"report_id": report.get("_id")}):
        for url in link.get("Links") or []:
            crawled += 1
            if "?" in str(url):
                with_parameters += 1
    return {"crawled_urls": crawled, "urls_with_parameters": with_parameters}
```

and use it in `scanner_report`:

```python
    counts = candidates(database, report) if report else {"crawled_urls": 0, "urls_with_parameters": 0}
```

replace the counting block that is already in `scanner_report` with a call to
`candidates()`, add `"candidates": counts["urls_with_parameters"]` to every
worker entry, and set `"summary": counts` in the returned dictionary.

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/unit/test_worker_output.py -q`
Expected: PASS - 2 passed.

- [ ] **Step 5: Show the count in the console**

In `b_hunters/web/app.js`, change the status cell of `renderScanners`:

```javascript
      <td><span class="badge ${states[worker.status] || 'bg-secondary'}">${escape(worker.status)}</span>${worker.candidates ? `<div class="faint small">${worker.candidates} candidate URL(s) carried parameters</div>` : ''}</td>
```

and extend the header line with the totals:

```javascript
  const summary = data.summary || {};
  const crawled = summary.crawled_urls ?? 0;
  const parameterised = summary.urls_with_parameters ?? 0;
```

with `${crawled} URL(s) crawled, ${parameterised} of them carry parameters`
appended to the `<span class="desc">`.

- [ ] **Step 6: Run the suite, the linter and the JavaScript check**

Run: `pytest tests/ -q`, `ruff check b_hunters tests`,
`ruff format --check b_hunters tests`, `node --check b_hunters/web/app.js`
Expected: all pass.

- [ ] **Step 7: Rebuild the platform**

Run: `docker compose --env-file /home/sniper/pentest/.env -f docker-compose.platform.yml up -d --build platform`
Expected: the platform container is recreated and healthy.

- [ ] **Step 8: Commit**

```bash
git add b_hunters/platform/scanners/worker_output.py b_hunters/platform/api/routers/scans.py b_hunters/web/app.js tests/unit/test_worker_output.py
git commit -m "feat: say how many candidates a scanner had"
```

---

### Task 4: Give a worker what a concurrent scan gives it, and verify

**Files:**
- Modify: `dev/check_workers_one_by_one.py`
- Modify: `STATUS.md`

**Interfaces:**
- Consumes: the tasks the Karton router prepared, each with a `receiver`
  header.
- Produces: a per-worker result that says what the worker was given.

- [ ] **Step 1: Publish every task addressed to the worker**

In `dev/check_workers_one_by_one.py`, the scanner loop already filters the
tasks by `receiver`. Change the filter to collect **all** the tasks the
worker is addressed to, including the ones that were produced later:

```python
        mine = [
            task for task in helper({})["tasks"]
            if task["headers"].get("receiver") == identity
            and task["headers"].get("type") in task_kinds
        ]
```

keep the filter, but publish the tasks in a loop over every kind, and
record the candidate URLs the worker received in the result:

```python
        received = 0
        for kind in task_kinds:
            for task in mine:
                if task["headers"].get("type") != kind:
                    continue
                helper({
                    "publish": {
                        "header": task["headers"],
                        "persistent": task["persistent"],
                        "data": task["payload"],
                    }
                })
                received += 1
```

and add `"received": received` to the result dictionary and to the summary
line.

- [ ] **Step 2: Run the per-worker check on DVGA**

Run: `python3 dev/check_workers_one_by_one.py worker-dalfox worker-sqlmap worker-ssti worker-nuclei worker-paramspider`
Expected: every worker reports the tasks it consumed, and the path scanners
report "ran, found nothing" with the candidate count of 0.

- [ ] **Step 3: Run the per-worker check on Juice Shop**

Start the laboratory application first:

```bash
docker compose --env-file /home/sniper/pentest/.env -f docker-compose.platform.yml --profile juiceshop up -d lab-juice-shop
```

then run:

```bash
python3 dev/check_workers_one_by_one.py http://172.25.0.13:3000 worker-nuclei worker-dalfox
```

Expected: `nuclei` reports its `prometheus-metrics` finding again, and
`dalfox` reports what it was given.

- [ ] **Step 4: Record the findings**

In `STATUS.md`, under "What the path scanners need", record the measured
result of the two runs: the candidate count per target, and the `nuclei`
finding on Juice Shop.

- [ ] **Step 5: Commit**

```bash
git add dev/check_workers_one_by_one.py STATUS.md
git commit -m "docs: record what the path scanners had to test"
```
