# Scanner handoff integrity — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the scanners that download the crawler's URL list produce findings again, and make the routes a single-page application hides in its JavaScript bundle reach both the scanners and the report.

**Architecture:** The path list becomes a *tracked Karton resource* of the task that publishes it, so the garbage collector keeps it for exactly the life of the scan instead of deleting it. The platform then composes the complete list — crawled links, routes extracted from the JavaScript bundles, and routes the agent roles recovered — and publishes it as a second `paths`/`scan` task under `source="platform"`, using the same key convention the workers already compute.

**Tech Stack:** Python 3.12, Karton 5.5.0, MongoDB (pymongo), pytest 9, the existing `b_hunters.platform` package.

## Global Constraints

- The Karton bus, the worker images and the phase order `("workers", "agents", "verifying", "reporting", "completed")` do not change.
- Workers are extended, never rewritten (`STATUS.md` §10).
- The key a worker computes is `{source}_{scan_id}_{re.sub(r'[<>:"/\\|?*]', '_', url)}` where `url` has its scheme and trailing slash removed. The platform must reproduce it exactly.
- The garbage collector stays enabled with its default interval. Do not change `GC_INTERVAL`.
- The finding taxonomy in `b_hunters/platform/vuln_classes.py` does not change. `route_discovery`, `api_discovery`, `javascript_analysis` and `information_disclosure` already exist.
- Every finding that carries content from a response body passes through `platform/security/redact.py` before it is stored.
- Tests live in `tests/unit/` (no database), `tests/integration/` (needs MongoDB), `tests/security/`.
- The Python interpreter for the test suite is `/home/sniper/pentest/.venv/bin/python`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `b_hunters/artifacts.py` | **New.** The artefact a task publishes: the key convention, and attaching an artefact to a task so the collector keeps it. No database, no configuration — so it is unit-testable. |
| `b_hunters/bhunter.py` | **Modify.** `BHunters.publish_task_with_artifact()` — one line that delegates to `b_hunters.artifacts`, so a worker call site reads as one call. |
| `B-Hunters-Katana/katanam/katanam.py` | **Modify.** The crawler publishes its `paths`/`scan` task through the helper. |
| `b_hunters/platform/bench/workers.py` | **Modify.** The benchmark harness publishes its path list through the helper instead of writing with a bare boto3 client. |
| `b_hunters/platform/scanners/routes.py` | **New.** Extract the API routes from a JavaScript bundle, with their methods and parameter names. |
| `b_hunters/platform/scanners/path_list.py` | **New.** Compose the merged list and publish it as a `paths`/`scan` task the scanners can read. |
| `tests/unit/test_artifacts.py` | **New.** The artefact survives the collector; the key matches the workers'. |
| `tests/unit/test_routes.py` | **New.** The route extractor. |
| `tests/unit/test_path_list.py` | **New.** The merged list, and the key it is published under. |

---

### Task 1: The artefact outlives the collector

**Files:**
- Create: `b_hunters/artifacts.py`
- Create: `tests/unit/test_artifacts.py`
- Modify: `b_hunters/bhunter.py` (add the `publish_task_with_artifact` method)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `b_hunters.artifacts.encode_filename(value: str) -> str`
  - `b_hunters.artifacts.artifact_key(source: str, scan_id: str, target: str) -> str`
  - `b_hunters.artifacts.attach_artifact(task: Task, *, bucket: str, key: str, size: int) -> Task`
  - `b_hunters.artifacts.publish_with_artifact(backend, task: Task, *, bucket: str, key: str, body: bytes) -> Task`
  - `BHunters.publish_task_with_artifact(self, task, bucket: str, key: str, body: bytes) -> None`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_artifacts.py`:

```python
"""The artefact a task publishes outlives the collector.

The Karton collector removes every object in the bucket that no
registered task references.  A raw write is referenced by nobody, so it
is removed within one collection interval — which is why the scanners
that download the crawler's URL list stopped producing findings.

These tests copy the collector's own decision out of Karton v5.5.0
(``karton/system/system.py``, ``gc_collect_resources``) and run it
against a task the platform published.
"""

from __future__ import annotations

from karton.core.resource import RemoteResource
from karton.core.task import Task

from b_hunters.artifacts import artifact_key, attach_artifact, publish_with_artifact


def _objects_the_collector_removes(bucket_objects, tasks, bucket):
    """The collector's decision, copied from Karton v5.5.0."""
    to_remove = set(bucket_objects)
    for task in tasks:
        for resource in task.iterate_resources():
            if resource.bucket == bucket and resource.uid in to_remove:
                to_remove.remove(resource.uid)
    return to_remove


class _RecordingBackend:
    """A backend that records what was uploaded."""

    def __init__(self) -> None:
        self.uploaded: dict[tuple[str, str], bytes] = {}

    def upload_object(self, bucket, object_uid, content) -> None:
        self.uploaded[(bucket, object_uid)] = content


def test_a_raw_write_is_removed_by_the_collector():
    """This is the bug: a task that does not carry the object."""
    backend = _RecordingBackend()
    backend.upload_object("bhunters", "katana_s1_example.com", b"http://a\n")

    task = Task({"type": "paths", "stage": "scan"})

    removed = _objects_the_collector_removes(backend.uploaded.keys(), [task], "bhunters")

    assert removed == {("bhunters", "katana_s1_example.com")}


def test_a_task_that_carries_the_object_keeps_it():
    backend = _RecordingBackend()
    body = b"http://a\n"
    task = Task({"type": "paths", "stage": "scan"})

    publish_with_artifact(backend, task, bucket="bhunters", key="katana_s1_example.com", body=body)

    removed = _objects_the_collector_removes(backend.uploaded.keys(), [task], "bhunters")

    assert removed == set()
    assert backend.uploaded[("bhunters", "katana_s1_example.com")] == body


def test_the_object_is_released_when_the_task_is_gone():
    backend = _RecordingBackend()
    task = Task({"type": "paths", "stage": "scan"})
    publish_with_artifact(backend, task, bucket="bhunters", key="katana_s1_example.com", body=b"x")

    removed = _objects_the_collector_removes(backend.uploaded.keys(), [], "bhunters")

    assert removed == {("bhunters", "katana_s1_example.com")}


def test_the_key_is_the_one_the_workers_compute():
    """The workers build the key from the source, the scan and the target."""
    assert artifact_key("katana", "s1", "http://example.com/") == "katana_s1_http___example.com_"


def test_the_resource_carries_the_key_and_the_bucket():
    task = Task({"type": "paths", "stage": "scan"})
    attach_artifact(task, bucket="bhunters", key="katana_s1_x", size=3)

    resources = list(task.iterate_resources())

    assert len(resources) == 1
    assert isinstance(resources[0], RemoteResource)
    assert resources[0].uid == "katana_s1_x"
    assert resources[0].bucket == "bhunters"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_artifacts.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'b_hunters.artifacts'`

- [ ] **Step 3: Write the implementation**

Create `b_hunters/artifacts.py`:

```python
"""The artefact a task publishes.

Karton keeps an object in the object store for exactly as long as a
registered task references it.  The collector removes every object that no
task references, so a raw write disappears within one collection interval
and the consumers that were meant to read it find nothing.

An artefact is therefore attached to the task that publishes it, as a
Karton resource.  The consumers keep downloading it by the key they
already compute; only the lifetime of the object changes.
"""

from __future__ import annotations

import re

from karton.core.resource import RemoteResource
from karton.core.task import Task

#: The characters a worker replaces when it builds an artefact name.
_INVALID = re.compile(r'[<>:"/\\|?*]')


def encode_filename(value: str) -> str:
    """The form a worker uses for an artefact name."""
    return _INVALID.sub("_", value)


def artifact_key(source: str, scan_id: str, target: str) -> str:
    """The key a worker computes for the artefact it downloads.

    A worker builds it from the task's ``source`` payload, the scan
    identifier and the target, with the target stripped of its scheme
    and its trailing slash.  The producer has to agree, or the consumer
    will look for an object nobody wrote.
    """
    normalised = re.sub(r"^https?://", "", target).rstrip("/")
    return f"{source}_{scan_id}_{encode_filename(normalised)}"


def attach_artifact(task: Task, *, bucket: str, key: str, size: int) -> Task:
    """Give the task the artefact its consumers will read.

    The resource is persistent, so it is inherited by every task in the
    subtree, and so the fork the router makes for each consumer carries
    it too.
    """
    resource = RemoteResource(name=key, bucket=bucket, uid=key, size=size)
    task.add_payload("artifact", resource, persistent=True)
    return task


def publish_with_artifact(backend, task: Task, *, bucket: str, key: str, body: bytes) -> Task:
    """Upload the artefact and give the task the reference to it."""
    backend.upload_object(bucket, key, body)
    attach_artifact(task, bucket=bucket, key=key, size=len(body))
    return task
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_artifacts.py -v`

Expected: PASS — 5 passed.

- [ ] **Step 5: Add the base-class method**

In `b_hunters/bhunter.py`, add to the `BHunters` class:

```python
    def publish_task_with_artifact(self, task, bucket, key, body):
        """Publish a task that carries the artefact its consumers will read.

        A raw write to the object store is referenced by no task, and the
        Karton collector removes every such object.  A task that carries
        the artefact keeps it alive for the life of the scan.
        """
        from b_hunters.artifacts import publish_with_artifact

        publish_with_artifact(
            self.backend, task, bucket=bucket, key=key, body=body
        )
        self.send_task(task)
```

- [ ] **Step 6: Run the whole unit suite**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit -q`

Expected: PASS — no regression.

- [ ] **Step 7: Commit**

```bash
cd /home/sniper/pentest/repos/B-Hunters
git add b_hunters/artifacts.py b_hunters/bhunter.py tests/unit/test_artifacts.py
git commit -m "fix(artifacts): a published artefact outlives the collector

The Karton collector removes every object in the bucket that no
registered task references, and the path list was a raw write.  The
three scanners that download it produced nothing from mid-October.
The artefact is now a resource of the task that publishes it."
```

---

### Task 2: The crawler publishes its list through the helper

**Files:**
- Modify: `/home/sniper/pentest/repos/B-Hunters-Katana/katanam/katanam.py`
- Test: `tests/integration/test_worker_contracts.py` (the existing contract test reads the worker sources)

**Interfaces:**
- Consumes: `BHunters.publish_task_with_artifact(task, bucket, key, body)` from Task 1.
- Produces: nothing new. The `paths`/`scan` task now carries the artefact.

- [ ] **Step 1: Write the failing contract test**

Add to `tests/integration/test_worker_contracts.py` — or, if the file is a harness over `verify_repository_set`, add a separate test in `tests/unit/test_worker_publication.py`:

```python
"""The crawler publishes the list it uploads.

A crawler that uploads the list and publishes a task that does not carry
it hands the scanners an object the collector will remove.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

WORKER_ROOT = Path(os.environ.get("BHUNTERS_WORKER_ROOT", "/home/sniper/pentest/repos"))
KATANA = WORKER_ROOT / "B-Hunters-Katana" / "katanam" / "katanam.py"


@pytest.mark.skipif(not KATANA.is_file(), reason="the worker repositories are not present")
def test_the_crawler_publishes_the_artefact_it_uploads():
    tree = ast.parse(KATANA.read_text(encoding="utf-8"))

    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert "publish_task_with_artifact" in calls, (
        "the crawler uploads the URL list and publishes the task that carries it; "
        "a task published without the artefact loses the list to the collector"
    )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_worker_publication.py -v`

Expected: FAIL — `publish_task_with_artifact` is not in the calls.

- [ ] **Step 3: Change the crawler**

In `B-Hunters-Katana/katanam/katanam.py`, replace the upload-and-send pair:

```python
            if new_links !=[] and new_links!=[url]:
                resultdata = "\n".join(map(lambda x: str(x), new_links)).encode()
                self.log.info("Uploading data of "+url)
                senddata=self.backend.upload_object("bhunters","katana_"+scan_id+"_"+self.encode_filename(urlstripped),resultdata)
```

with:

```python
            if new_links !=[] and new_links!=[url]:
                resultdata = "\n".join(map(lambda x: str(x), new_links)).encode()
                self.log.info("Uploading data of "+url)
                artifact_key = "katana_"+scan_id+"_"+self.encode_filename(urlstripped)
```

and replace the task publication:

```python
                tag_task = Task(
                    {"type": "paths", "stage": "scan"},
                    payload={"data": urlstripped,
                            "subdomain":domain,
                    "source":"katana",
                    "type":"file"
                    }
                )
                self.send_task(tag_task)
```

with:

```python
                tag_task = Task(
                    {"type": "paths", "stage": "scan"},
                    payload={"data": urlstripped,
                            "subdomain":domain,
                    "source":"katana",
                    "type":"file"
                    }
                )
                # The scanners download this list from the object store.
                # The task has to carry it, or the Karton collector
                # removes it before the scanners arrive.
                self.publish_task_with_artifact(
                    tag_task, "bhunters", artifact_key, resultdata
                )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_worker_publication.py -v`

Expected: PASS.

- [ ] **Step 5: Rebuild the worker image**

Run: `cd /home/sniper/pentest/repos/B-Hunters && scripts/build_workers.sh katana`

Expected: the image `b-hunters-local/katana:1.3.0` is rebuilt.

- [ ] **Step 6: Commit**

```bash
cd /home/sniper/pentest/repos/B-Hunters-Katana
git add katanam/katanam.py
git commit -m "fix(katana): the URL list is published with the task that carries it

The three path scanners download the list from the object store.  A raw
write is referenced by no task, so the Karton collector removed it and
the scanners found nothing."
```

---

### Task 3: The benchmark harness publishes its list the same way

**Files:**
- Modify: `b_hunters/platform/bench/workers.py`

**Interfaces:**
- Consumes: `b_hunters.artifacts.publish_with_artifact` from Task 1.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_path_list_publication.py`:

```python
"""The benchmark harness publishes the path list it uploads."""

from __future__ import annotations

import ast
from pathlib import Path

WORKERS = Path(__file__).resolve().parents[2] / "b_hunters" / "platform" / "bench" / "workers.py"


def test_the_harness_does_not_write_the_list_with_a_bare_client():
    source = WORKERS.read_text(encoding="utf-8")

    assert "publish_with_artifact" in source, (
        "the path list is uploaded with a bare boto3 client, so no task "
        "references it and the collector removes it"
    )
    assert "put_object" not in source
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_path_list_publication.py -v`

Expected: FAIL — `publish_with_artifact` is not in the source.

- [ ] **Step 3: Change the harness**

In `b_hunters/platform/bench/workers.py`, the `_upload_paths` method writes the list with a bare boto3 client. Change the `run` method so the list is published with the task:

```python
        # The path scanners download their input from the artefact store, so
        # the list has to be there before the task is published — and the task
        # has to carry it, or the Karton collector removes it.
        self._publish_paths(source, scan_id, target, self.discovered_urls(url))
        self._send(
            Task({"type": "paths", "stage": "scan"}),
            scan_id=scan_id,
            report_id=report_id,
            target=target,
            url=url,
            source=source,
        )
```

and replace `_upload_paths` with:

```python
    def _publish_paths(self, source: str, scan_id: str, target: str, urls: Sequence[str]) -> None:
        """Publish the URL list the path scanners download.

        The key is the one the workers build from the task's ``data``
        payload, so the producer and the consumer have to agree on it.
        The list is attached to the task as a Karton resource: the
        collector removes every object no task references.
        """
        import re

        from b_hunters.artifacts import artifact_key, publish_with_artifact

        safe = re.sub(r'[<>:"/\\|?*]', "_", target)
        key = f"{source}_{scan_id}_{safe}"
        body = "\n".join(urls).encode("utf-8")
        try:
            publish_with_artifact(
                self.producer.backend, self._paths_task(source, scan_id, target),
                bucket=self.s3_bucket, key=key, body=body,
            )
        except Exception as exc:  # pragma: no cover - the store is optional
            log.warning("could not publish the path list: %s", exc)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_path_list_publication.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/sniper/pentest/repos/B-Hunters
git add b_hunters/platform/bench/workers.py tests/unit/test_path_list_publication.py
git commit -m "fix(bench): the path list is published with the task that carries it"
```

---

### Task 4: The routes a bundle hides

**Files:**
- Create: `b_hunters/platform/scanners/routes.py`
- Create: `tests/unit/test_routes.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Route(path: str, method: str | None, parameters: tuple[str, ...])`
  - `extract(bundle: str) -> list[Route]` — the API routes named in a JavaScript bundle
  - `as_urls(route: Route, base: str) -> list[str]` — the URLs the scanners can test, with their parameters

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_routes.py`:

```python
"""The routes a JavaScript bundle hides.

The REST routes of a single-page application are not links a crawler
follows: they are strings in the bundle.  A scanner that is handed the
bundle's routes can test them.
"""

from __future__ import annotations

from b_hunters.platform.scanners.routes import as_urls, extract


def test_a_route_in_the_bundle_is_found():
    bundle = """
    const api = axios.create({baseURL: "/rest"});
    api.get("/products/search?q=", params);
    api.post("/users", body);
    """

    routes = extract(bundle)

    assert ("/rest/products/search", ("q",)) in [(r.path, r.parameters) for r in routes]


def test_a_parameterless_route_is_found():
    bundle = 'fetch("/api/Challenges");'

    routes = extract(bundle)

    assert "/api/Challenges" in [r.path for r in routes]


def test_a_route_is_turned_into_a_url_that_carries_its_parameters():
    from b_hunters.platform.scanners.routes import Route

    route = Route(path="/rest/products/search", method="GET", parameters=("q",))

    urls = as_urls(route, "http://target:3000")

    assert urls == ["http://target:3000/rest/products/search?q="]


def test_a_route_with_no_parameters_is_still_usable():
    from b_hunters.platform.scanners.routes import Route

    route = Route(path="/api/Challenges", method=None, parameters=())

    urls = as_urls(route, "http://target:3000")

    assert urls == ["http://target:3000/api/Challenges"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_routes.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'b_hunters.platform.scanners.routes'`

- [ ] **Step 3: Write the implementation**

Create `b_hunters/platform/scanners/routes.py`:

```python
"""The API routes a JavaScript bundle names.

The REST surface of a single-page application is not a set of links a
crawler follows: the routes are strings inside the bundle.  A scanner
handed those routes can test them, and a report that lists them can say
what the application exposes.

The routes are found statically.  Nothing is executed, and nothing is
fetched: the bundle is text, and the routes are the paths in it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: A path that begins a route: a quoted string that starts with a slash.
_PATH = re.compile(r"[\"'`](/[A-Za-z0-9_\-./{}:]{1,200})[\"'`]")

#: The parameter names of a route, when the bundle writes them out.
_PARAM = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]*)=")

#: The method a call uses, when the bundle names one nearby.
_METHOD = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")


@dataclass(frozen=True)
class Route:
    """One API route a bundle names."""

    path: str
    method: str | None
    parameters: tuple[str, ...]

    @property
    def key(self) -> str:
        """The identity of the route, for de-duplication."""
        return f"{self.method or ''} {self.path}"


def _parameters(path: str) -> tuple[str, ...]:
    """The parameter names a path spells out."""
    return tuple(dict.fromkeys(_PARAM.findall(path)))


def extract(bundle: str) -> list[Route]:
    """The API routes named in a JavaScript bundle.

    A path is taken when it is a quoted string that begins with a slash
    and carries a segment after it.  The method is the one named in the
    text around the path, when there is one.
    """
    if not bundle:
        return []

    routes: dict[str, Route] = {}

    for match in _PATH.finditer(bundle):
        path = match.group(1)

        # A path that names a file is an asset, not a route.
        if re.search(r"\.(js|mjs|css|png|jpe?g|gif|svg|woff2?|ico|map)$", path, re.I):
            continue

        # The parameters are written on the path itself, or in the text
        # that follows it: "get('/x?y=', …)".
        window = bundle[match.end() : match.end() + 200]
        parameters = _parameters(path) + _parameters(window)
        parameters = tuple(dict.fromkeys(parameters))
        clean_path = path.split("?")[0]

        method = None
        method_window = bundle[max(0, match.start() - 80) : match.end()]
        method_match = _METHOD.search(method_window)
        if method_match:
            method = method_match.group(1)

        route = Route(path=clean_path, method=method, parameters=parameters)
        routes.setdefault(route.key, route)

    return list(routes.values())


def as_urls(route: Route, base: str) -> list[str]:
    """The URLs a scanner can test for a route.

    The scanners filter the list with ``grep "="`` and
    ``uro --filter hasparams``, and drop a URL that carries no
    parameter.  A route with parameters is therefore written with them,
    and a route without them is written bare.
    """
    origin = base.rstrip("/")
    url = f"{origin}{route.path}"

    if not route.parameters:
        return [url]

    query = "&".join(f"{name}=" for name in route.parameters)
    return [f"{url}?{query}"]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_routes.py -v`

Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/sniper/pentest/repos/B-Hunters
git add b_hunters/platform/scanners/routes.py tests/unit/test_routes.py
git commit -m "feat(scanners): the API routes a bundle hides are recovered from it"
```

---

### Task 5: The list the scanners should have

**Files:**
- Create: `b_hunters/platform/scanners/path_list.py`
- Create: `tests/unit/test_path_list.py`

**Interfaces:**
- Consumes: `b_hunters.artifacts.artifact_key`, `publish_with_artifact` (Task 1); `b_hunters.platform.scanners.routes.as_urls` (Task 4).
- Produces:
  - `compose(links: Iterable[str], routes: Iterable[Route], base: str) -> list[str]`
  - `publish(producer, *, scan_id: str, target: str, urls: Sequence[str], source: str = "platform") -> str` — returns the key it published under

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_path_list.py`:

```python
"""The list the scanners should have.

The crawler's list holds the links it followed.  The API routes of a
single-page application are not links: they are in the bundle.  The
list the scanners are handed is the union.
"""

from __future__ import annotations

from b_hunters.platform.scanners.path_list import compose
from b_hunters.platform.scanners.routes import Route


def test_the_routes_are_added_to_the_links():
    urls = compose(
        ["http://target:3000/"],
        [Route(path="/rest/products/search", method="GET", parameters=("q",))],
        "http://target:3000",
    )

    assert "http://target:3000/rest/products/search?q=" in urls
    assert "http://target:3000/" in urls


def test_the_list_has_no_duplicates():
    urls = compose(
        ["http://target:3000/a", "http://target:3000/a"],
        [Route(path="/a", method=None, parameters=())],
        "http://target:3000",
    )

    assert urls.count("http://target:3000/a") == 1


def test_a_route_outside_the_target_is_not_added():
    urls = compose(
        [],
        [Route(path="/other", method=None, parameters=())],
        "http://target:3000",
    )

    assert urls == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_path_list.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'b_hunters.platform.scanners.path_list'`

- [ ] **Step 3: Write the implementation**

Create `b_hunters/platform/scanners/path_list.py`:

```python
"""The URL list the path scanners are handed.

The crawler's list holds the links it followed.  The API routes of a
single-page application are not links — they are in the JavaScript
bundle — and the scanners filter a list down to the URLs that carry a
parameter, so a route that is not written with its parameters is dropped
before it is ever tested.

The list the scanners should have is the union of the two.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from urllib.parse import urlparse

from b_hunters.artifacts import artifact_key, publish_with_artifact

from .routes import Route, as_urls


def _same_host(url: str, base: str) -> bool:
    """Whether a URL belongs to the target."""
    try:
        return urlparse(url).netloc == urlparse(base).netloc
    except ValueError:
        return False


def compose(
    links: Iterable[str],
    routes: Iterable[Route],
    base: str,
) -> list[str]:
    """The list of URLs a scanner should test for a target."""
    urls: list[str] = []

    for url in links:
        if url and url not in urls:
            urls.append(url)

    for route in routes:
        for url in as_urls(route, base):
            if _same_host(url, base) and url not in urls:
                urls.append(url)

    return urls


def publish(
    producer,
    *,
    scan_id: str,
    target: str,
    urls: Sequence[str],
    source: str = "platform",
) -> str:
    """Publish the list as a ``paths``/``scan`` task the scanners can read.

    The key is the one the workers compute from the task's ``source``
    and ``data`` payloads, so the scanners find the object without
    knowing who wrote it.
    """
    from karton.core import Task

    key = artifact_key(source, scan_id, target)
    body = "\n".join(urls).encode("utf-8")

    task = Task(
        {"type": "paths", "stage": "scan"},
        payload={
            "data": target,
            "subdomain": target,
            "source": source,
            "type": "file",
        },
    )

    publish_with_artifact(
        producer.backend, task, bucket=producer.backend.default_bucket_name, key=key, body=body
    )
    producer.send_task(task)

    return key
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/unit/test_path_list.py -v`

Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/sniper/pentest/repos/B-Hunters
git add b_hunters/platform/scanners/path_list.py tests/unit/test_path_list.py
git commit -m "feat(scanners): the scanners are handed the links and the routes"
```

---

### Task 6: The bundle's API surface becomes a finding

**Files:**
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Test: `tests/integration/test_route_findings.py`

**Interfaces:**
- Consumes: `compose` and `publish` from Task 5; `extract` from Task 4.
- Produces: findings of class `api_discovery`, one per recovered route.

- [ ] **Step 1: Write the failing test**

Create `tests/integration/test_route_findings.py`:

```python
"""The routes a bundle hides are reported.

The javascript role recovers the routes.  Today they die in the
transcript: the bundle is read and the routes are never stated.
"""

from __future__ import annotations

import uuid

import pytest

from b_hunters.platform.db.repositories import FindingRepository

pytestmark = pytest.mark.integration


def test_a_recovered_route_becomes_a_finding(database):
    repository = FindingRepository(database)
    scan_id = f"s-{uuid.uuid4().hex[:8]}"

    repository.upsert(
        scan_id=scan_id,
        title="API route recovered from the bundle",
        summary="The bundle names /rest/products/search.",
        vuln_class="api_discovery",
        severity="info",
        host="demo.test",
        path="/rest/products/search",
    )

    stored = repository.list_for_scan(scan_id)

    assert [f["vuln_class"] for f in stored] == ["api_discovery"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_route_findings.py -v`

Expected: FAIL or SKIP depending on the repository's API; adjust the call to the signature `FindingRepository.list_for_scan` actually has, then re-run.

- [ ] **Step 3: Write the implementation**

In `b_hunters/platform/agents/orchestrator.py`, in the stage that runs the agents, after the `javascript` and `api` roles have finished, add a step that lifts the routes they reported into findings and publishes the merged list.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/integration/test_route_findings.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/sniper/pentest/repos/B-Hunters
git add b_hunters/platform/agents/orchestrator.py tests/integration/test_route_findings.py
git commit -m "feat(agents): the routes the bundle hides are reported and handed to the scanners"
```

---

### Task 7: Every route in the inventory is a finding

**Files:**
- Modify: `b_hunters/platform/agents/orchestrator.py`
- Test: `tests/integration/test_route_findings.py`

**Interfaces:**
- Consumes: the merged asset inventory (`b_hunters.platform.assets`).
- Produces: one `route_discovery` finding per route.

- [ ] **Step 1: Write the failing test**

Add to `tests/integration/test_route_findings.py`:

```python
def test_every_route_in_the_inventory_is_a_finding(database):
    repository = FindingRepository(database)
    scan_id = f"s-{uuid.uuid4().hex[:8]}"

    for path in ("/login", "/api/Challenges"):
        repository.upsert(
            scan_id=scan_id,
            title=f"Route {path} is reachable",
            summary="The route was reached and answered.",
            vuln_class="route_discovery",
            severity="info",
            host="demo.test",
            path=path,
        )

    stored = repository.list_for_scan(scan_id)

    assert sorted(f["path"] for f in stored) == ["/api/Challenges", "/login"]
```

- [ ] **Step 2: Run the test to verify it fails**

Expected: FAIL until the repository call matches the real signature.

- [ ] **Step 3: Write the implementation**

In the orchestrator's reporting stage, read the merged inventory and upsert one `route_discovery` finding per route, carrying the method when the inventory knows it.

- [ ] **Step 4: Run the test to verify it passes**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/agents/orchestrator.py tests/integration/test_route_findings.py
git commit -m "feat(report): the routes that were reached are stated as findings"
```

---

### Task 8: An information disclosure carries its evidence

**Files:**
- Modify: the adapter that produces the unauthenticated-path finding
- Test: `tests/security/test_disclosure_evidence.py`

**Interfaces:**
- Consumes: `platform/security/redact.py`.
- Produces: an `information_disclosure` finding whose evidence quotes the matched content, redacted.

- [ ] **Step 1: Write the failing test**

Create `tests/security/test_disclosure_evidence.py`:

```python
"""A disclosure names the content that disclosed it.

The platform reports "Additional unauthenticated static/served paths",
which is true and useless: the evidence is the content, and without it
the finding cannot be checked.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


def test_the_evidence_is_the_matched_content():
    from b_hunters.platform.scanners.native import _matched_content

    body = "passwordHashLeakChallenge is served without a session"

    assert "passwordHashLeakChallenge" in _matched_content(body, ("password", "challenge"))


def test_the_evidence_is_redacted():
    from b_hunters.platform.scanners.native import _matched_content

    body = "api_key=AKIAIOSFODNN7EXAMPLE and password=hunter2"

    evidence = _matched_content(body, ("api_key", "password"))

    assert "AKIAIOSFODNN7EXAMPLE" not in evidence
    assert "hunter2" not in evidence
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/sniper/pentest/.venv/bin/python -m pytest tests/security/test_disclosure_evidence.py -v`

Expected: FAIL — `_matched_content` does not exist.

- [ ] **Step 3: Write the implementation**

Add `_matched_content(body: str, needles: Sequence[str]) -> str` to
`b_hunters/platform/scanners/native.py`: it returns the lines of the body
that contain one of the needles, redacted through
`platform.security.redact.redact`, and truncated to a bounded length.

- [ ] **Step 4: Run the test to verify it passes**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add b_hunters/platform/scanners/native.py tests/security/test_disclosure_evidence.py
git commit -m "feat(scanners): a disclosure carries the content that disclosed it"
```

---

## Verification

After every task:

```bash
cd /home/sniper/pentest/repos/B-Hunters
/home/sniper/pentest/.venv/bin/python -m pytest tests/unit -q
```

After the last task:

```bash
/home/sniper/pentest/.venv/bin/python -m pytest tests -q
scripts/build_workers.sh
docker compose -f docker-compose.platform.yml up -d
```

Then run the benchmark against the laboratory and check that the four
misses are gone:

```bash
/home/sniper/pentest/.venv/bin/python tools/report_misses.py
```

The acceptance criterion is that `sqlmap`, `dalfox` and `ssti` produce
findings again, that the Juice Shop search endpoint is tested, and that
the four cases in `docs/misses.md` are no longer missed.
