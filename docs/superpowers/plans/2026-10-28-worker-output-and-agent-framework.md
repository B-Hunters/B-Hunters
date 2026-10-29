# Saved Worker Output and Agent Framework — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Save the scanner workers' output as platform data that the dashboard shows and the agents can scan further, and move the agent runtime onto PydanticAI with the tools the roles need.

**Architecture:** Two independent pieces plus the tools they need. (1) A `platform_worker_output` collection holds what the workers produced; the orchestrator fills it when the worker phase ends, the API and a new agent tool read it, and the console offers to scan it. (2) The agent loop becomes a PydanticAI agent: the gateway's tools are bridged into framework tools, the budgets become `UsageLimits`, the conclusion becomes a validated Pydantic model, and the provider stays the transport. (3) The analysis roles get `http_request` and the artefact roles get `run_command` - with the shell made scope-aware so that widening it does not open a way around the scope enforcer.

**Tech Stack:** Python 3.12, FastAPI, MongoDB (pymongo), Karton, PydanticAI 2.x (`pydantic-ai-slim[openai]`), pytest, ruff, vanilla JavaScript console.

## Global Constraints

- The platform's MongoDB is the `b-hunters` database; the workers' MongoDB is the same instance. The platform Mongo is **not** published on the host.
- The workers install `b-hunters==1.2.0` from PyPI and do **not** use the platform's agent framework; the dependency goes into the platform extra only.
- The tool gateway owns the capability check, the scope check and the audit. A bridged tool must go through the gateway, not around it.
- `http_request` is scope-checked; a shell command is not, so the shell must check the hosts it names itself.
- Every change needs a test; `ruff check b_hunters tests` and `ruff format --check b_hunters tests` must stay clean.
- The test suite is run from `repos/B-Hunters` with
  `BHUNTERS_TEST_MONGO_URI="mongodb://bhunter:bhunter_dev_pw@127.0.0.1:27017/?authSource=admin"`.
- Nothing is committed or pushed without the operator asking.

---

### Task 1: The worker's output becomes platform data

**Files:**
- Create: `b_hunters/platform/db/worker_output_repository.py`
- Modify: `b_hunters/platform/db/repositories.py` (the `Services` container)
- Modify: `b_hunters/platform/agents/orchestrator.py` (ingest after the worker phase)
- Modify: `b_hunters/platform/api/routers/scans.py` (the endpoint)
- Test: `tests/unit/test_worker_output_repository.py`

**Interfaces:**
- Consumes: `b_hunters.platform.scanners.worker_output.produced(database, report)` - the
  function that already knows what each worker wrote.
- Produces:
  - `WorkerOutputRepository(db)` with
    `replace_for_scan(scan_id: str, rows: list[dict[str, Any]]) -> int`,
    `list_for_scan(scan_id: str, *, worker: str = "", kind: str = "", limit: int = 500) -> list[dict[str, Any]]`,
    `counts_for_scan(scan_id: str) -> dict[str, int]`.
  - `GET /api/v1/scans/{scan_id}/worker-output` returning
    `{"scan_id": ..., "items": [...], "count": N}`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_worker_output_repository.py`:

```python
"""The output of the scanner workers is saved per scan."""

from __future__ import annotations

from typing import Any

import pytest
from bson import ObjectId

from b_hunters.platform.db.worker_output_repository import WorkerOutputRepository


class _Collection:
    def __init__(self) -> None:
        self.documents: list[dict[str, Any]] = []

    def delete_many(self, query: dict[str, Any]) -> Any:
        self.documents = [
            document
            for document in self.documents
            if not all(document.get(key) == value for key, value in query.items())
        ]
        return None

    def insert_many(self, documents: list[dict[str, Any]]) -> Any:
        self.documents.extend(documents)
        return None

    def find(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            document
            for document in self.documents
            if all(document.get(key) == value for key, value in query.items())
        ]


class _Database:
    def __init__(self) -> None:
        self.collections = {"platform_worker_output": _Collection()}

    def collection(self, name: str) -> Any:
        return self.collections.setdefault(name, _Collection())


def test_the_output_is_saved_and_read_back() -> None:
    repository = WorkerOutputRepository(_Database())
    written = repository.replace_for_scan(
        "scan-1",
        [
            {"worker": "B-Hunters-Katana", "kind": "url", "value": "http://a/x"},
            {"worker": "B-Hunters-dirsearch", "kind": "path", "value": "/admin"},
        ],
    )
    assert written == 2
    items = repository.list_for_scan("scan-1")
    assert [item["value"] for item in items] == ["http://a/x", "/admin"]


def test_the_output_is_filtered_by_worker_and_kind() -> None:
    repository = WorkerOutputRepository(_Database())
    repository.replace_for_scan(
        "scan-1",
        [
            {"worker": "B-Hunters-Katana", "kind": "url", "value": "http://a/x"},
            {"worker": "B-Hunters-dirsearch", "kind": "path", "value": "/admin"},
        ],
    )
    assert len(repository.list_for_scan("scan-1", worker="B-Hunters-Katana")) == 1
    assert len(repository.list_for_scan("scan-1", kind="path")) == 1
    assert repository.list_for_scan("scan-2") == []


def test_a_second_ingestion_replaces_the_first() -> None:
    repository = WorkerOutputRepository(_Database())
    repository.replace_for_scan(
        "scan-1", [{"worker": "W", "kind": "url", "value": "http://a/x"}]
    )
    repository.replace_for_scan(
        "scan-1", [{"worker": "W", "kind": "url", "value": "http://a/y"}]
    )
    items = repository.list_for_scan("scan-1")
    assert [item["value"] for item in items] == ["http://a/y"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/unit/test_worker_output_repository.py -q`
Expected: FAIL - `ModuleNotFoundError: No module named 'b_hunters.platform.db.worker_output_repository'`

- [ ] **Step 3: Write the implementation**

Create `b_hunters/platform/db/worker_output_repository.py`:

```python
"""What the scanner workers produced, saved per scan.

The workers write into the legacy documents: the ``reports`` document, the
``links`` collection, the ``js`` collection.  The platform keeps its own
copy of what each of them produced, so that the output can be queried
through the API, shown in the console and handed to an agent that wants to
scan further.
"""

from __future__ import annotations

import time
from typing import Any


class WorkerOutputRepository:
    """The output of the scanner workers, per scan."""

    def __init__(self, db: Any) -> None:
        self._db = db

    @property
    def _col(self) -> Any:
        return self._db.collection("platform_worker_output")

    def replace_for_scan(self, scan_id: str, rows: list[dict[str, Any]]) -> int:
        """Save what the workers produced for a scan, replacing what was there."""
        self._col.delete_many({"scan_id": scan_id})
        documents = [
            {
                "scan_id": scan_id,
                "worker": str(row.get("worker", "")),
                "kind": str(row.get("kind", "")),
                "value": str(row.get("value", "")),
                "source": str(row.get("source", "")),
                "created_at": time.time(),
            }
            for row in rows
            if str(row.get("value", "")).strip()
        ]
        if documents:
            self._col.insert_many(documents)
        return len(documents)

    def list_for_scan(
        self, scan_id: str, *, worker: str = "", kind: str = "", limit: int = 500
    ) -> list[dict[str, Any]]:
        """The items the workers produced, filtered by worker and kind."""
        query: dict[str, Any] = {"scan_id": scan_id}
        if worker:
            query["worker"] = worker
        if kind:
            query["kind"] = kind
        return list(self._col.find(query))[: max(1, limit)]

    def counts_for_scan(self, scan_id: str) -> dict[str, int]:
        """How many items each worker produced."""
        counts: dict[str, int] = {}
        for item in self.list_for_scan(scan_id, limit=10000):
            worker = str(item.get("worker", ""))
            counts[worker] = counts.get(worker, 0) + 1
        return counts
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/unit/test_worker_output_repository.py -q`
Expected: PASS - 3 passed.

- [ ] **Step 5: Wire the repository into the services and the orchestrator**

In `b_hunters/platform/api/deps.py`, add to the `Services` container:

```python
        self.worker_output = WorkerOutputRepository(self.db)
```

with the import `from ..db.worker_output_repository import WorkerOutputRepository`.

In `b_hunters/platform/agents/orchestrator.py`, next to `_record_participation`,
add:

```python
    def _ingest_worker_output(self, context: ScanContext) -> None:
        """Save what the scanner workers produced.

        The workers write into the legacy documents.  The platform keeps a
        copy of the same items, so that they can be queried, shown and
        handed to an agent that wants to scan further.
        """
        from ..scanners import worker_output

        report_id, report = worker_output.report_for_scan(self.db, context.scan_id)
        if not report:
            return
        produced = worker_output.produced(self.db, report)
        rows: list[dict[str, Any]] = []
        for identity, items in produced.items():
            for item in items:
                for value in _values_of(item):
                    rows.append(
                        {
                            "worker": identity,
                            "kind": _kind_of(item["field"]),
                            "value": value,
                            "source": report_id,
                        }
                    )
        self.worker_output.replace_for_scan(context.scan_id, rows)
```

with the two helpers:

```python
def _kind_of(field: str) -> str:
    """The kind of item a worker wrote."""
    if field.startswith("secrets in"):
        return "secret"
    if field == "links":
        return "url"
    if field.startswith("Paths"):
        return "path"
    if field.startswith("Ports"):
        return "port"
    if field.startswith("Technology"):
        return "technology"
    if field.startswith("Screenshot") or field.startswith("data."):
        return "screenshot"
    if field.startswith("Vulns"):
        return "finding"
    return "item"


def _values_of(item: dict[str, Any]) -> list[str]:
    """The individual values of one written item."""
    preview = str(item.get("preview", ""))
    values = [
        line.strip()
        for line in preview.splitlines()
        if line.strip() and not line.strip().startswith(("key:", "value:", "- "))
    ]
    return values or ([preview.strip()] if preview.strip() else [])
```

Call `_ingest_worker_output(context)` right after `self._record_participation(context, before)`
in the worker phase.

- [ ] **Step 6: Add the endpoint**

In `b_hunters/platform/api/routers/scans.py`:

```python
@router.get("/{scan_id}/worker-output")
async def scan_worker_output(
    scan_id: str,
    worker: str = "",
    kind: str = "",
    limit: int = 500,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """What the scanner workers produced, saved per scan.

    The console lists it and offers to scan it again; an agent reads it
    with the `list_worker_output` tool.
    """
    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")
    items = services.worker_output.list_for_scan(
        scan_id, worker=worker, kind=kind, limit=limit
    )
    return {
        "scan_id": scan_id,
        "items": items,
        "count": len(items),
        "counts": services.worker_output.counts_for_scan(scan_id),
    }
```

- [ ] **Step 7: Run the suite and the linter**

Run: `pytest tests/ -q`, `ruff check b_hunters tests`, `ruff format --check b_hunters tests`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add b_hunters/platform/db/worker_output_repository.py b_hunters/platform/db/repositories.py b_hunters/platform/api/deps.py b_hunters/platform/agents/orchestrator.py b_hunters/platform/api/routers/scans.py tests/unit/test_worker_output_repository.py
git commit -m "feat: save the scanner workers' output as platform data"
```

---

### Task 2: The console shows the saved output and can scan it again

**Files:**
- Modify: `b_hunters/web/app.js`
- Test: `tests/unit/test_console_worker_output.py` (the console's JavaScript is checked
  with `node --check`; the test asserts that the served console asks for the
  endpoint and offers the action)

**Interfaces:**
- Consumes: `GET /api/v1/scans/{id}/worker-output`.
- Produces: the *Scanners* tab lists the saved items and a **Scan these URLs**
  button that creates a follow-up scan with those URLs as targets.

- [ ] **Step 1: Add the list and the action to the Scanners tab**

In `b_hunters/web/app.js`, inside `renderScanTab`, add:

```javascript
  if (tab === 'scanners') {
    const data = await api(`/scans/${scanId}/scanners`);
    const output = await api(`/scans/${scanId}/worker-output?limit=200`);
    body.innerHTML = renderScanners(data, output);
    el('scan-these').addEventListener('click', () => scanTheseUrls(scanId, output));
    return;
  }
```

and the two helpers:

```javascript
function renderScanners(data, output) {
  // ... the existing table ...
  const items = (output && output.items) || [];
  const urls = items.filter((item) => item.kind === 'url').map((item) => item.value);
  return `${table}
    <div class="card"><div class="card-head"><h2>What the scanners found</h2>
      <span class="desc">${items.length} item(s) saved</span></div>
      <div class="card-body">
        ${urls.length ? `<button class="btn" id="scan-these">Scan these ${urls.length} URL(s)</button>
          <div class="hint">A follow-up scan with these URLs as its targets: the native adapters and the agents work on the surface the crawler found.</div>` : '<div class="hint">No URLs were crawled.</div>'}
        <div class="table-scroll"><table><thead><tr><th>Worker</th><th>Kind</th><th>Value</th></tr></thead><tbody>
          ${items.slice(0, 200).map((item) => `<tr>
            <td class="mono small">${escape(item.worker)}</td>
            <td class="small">${escape(item.kind)}</td>
            <td class="mono small">${escape(item.value)}</td></tr>`).join('')}
        </tbody></table></div>
      </div></div>`;
}

async function scanTheseUrls(scanId, output) {
  const items = (output && output.items) || [];
  const urls = items.filter((item) => item.kind === 'url').map((item) => item.value);
  if (!urls.length) return;
  const host = new URL(urls[0]).hostname;
  const created = await api('/scans', {
    method: 'POST',
    body: JSON.stringify({
      name: `follow-up scan of ${host}`,
      targets: { urls, authorized_hosts: [host] },
      test_environment: true,
    }),
  });
  location.hash = `#/scans/${created.scan_id}`;
}
```

- [ ] **Step 2: Check the console parses and the suite passes**

Run: `node --check b_hunters/web/app.js`, `pytest tests/ -q`
Expected: both pass.

- [ ] **Step 3: Commit**

```bash
git add b_hunters/web/app.js
git commit -m "feat: show the saved scanner output and offer to scan it again"
```

---

### Task 3: The agent runtime moves onto PydanticAI

**Files:**
- Modify: `requirements.txt` (the platform extra)
- Create: `b_hunters/platform/agents/framework.py`
- Modify: `b_hunters/platform/agents/runtime.py`
- Test: `tests/unit/test_framework_tools.py`, `tests/unit/test_framework_conclusion.py`

**Interfaces:**
- Consumes: `AgentRole` (from `roles.py`), `ToolRegistry.for_role(role, allowed)`,
  `ToolContext` (from `gateway.py`), `ProviderConfig` (from `provider.py`).
- Produces:
  - `build_agent(role, definitions, context, *, model, output_type, usage_limits)`
    in `agents/framework.py`, returning a framework agent whose tools are the
    gateway's tools and whose run context carries the platform's tool context.
  - `class Conclusion(BaseModel)` - the validated conclusion: `conclusion`,
    `confidence`, `observations`, `uncertainty`, `next_step`, `findings`.

- [ ] **Step 1: Add the dependency**

In `requirements.txt`, in the platform section:

```
pydantic-ai-slim[openai]>=2.60,<3.0
```

- [ ] **Step 2: Write the failing test for the tool bridge**

Create `tests/unit/test_framework_tools.py`:

```python
"""The gateway's tools become framework tools.

The bridge must not lose the schema of a tool - the model sees the same
fields and descriptions - and it must not lose the capability check: a
tool the role may not use stays unusable.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.agents.framework import build_tools
from b_hunters.platform.tools.gateway import ToolContext, ToolDefinition


def _definition(name: str = "echo", capabilities: set[str] | None = None) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description="Echo the text back.",
        parameters={
            "type": "object",
            "properties": {"text": {"type": "string", "description": "What to echo."}},
            "required": ["text"],
            "additionalProperties": False,
        },
        handler=None,
        capabilities=capabilities or {"read"},
    )


def test_the_schema_survives_the_bridge() -> None:
    tools = build_tools([_definition()], ToolContext(scan_id="s", task_id="t", role="r"))
    assert len(tools) == 1
    schema = tools[0].function_schema.json_schema
    assert schema["properties"]["text"]["description"] == "What to echo."


def test_a_tool_the_role_may_not_use_is_not_offered() -> None:
    context = ToolContext(scan_id="s", task_id="t", role="r")
    context.permissions.denied.add("echo")
    tools = build_tools([_definition()], context)
    assert tools == []
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `pytest tests/unit/test_framework_tools.py -q`
Expected: FAIL - `ModuleNotFoundError: No module named 'b_hunters.platform.agents.framework'`

- [ ] **Step 4: Write the framework bridge**

Create `b_hunters/platform/agents/framework.py`:

```python
"""The agent loop, on a framework.

The platform keeps its own orchestrator, its tool gateway and its scope
enforcer; what this module adds is a loop that handles the parts every
tool-calling agent has to get right: the request/response cycle, the tool
calls, the usage accounting, the retries and the structured output.

The gateway's tools are bridged into framework tools.  The bridge keeps
the schema of every tool - the model sees the same fields and
descriptions - and the tool is still called through the gateway, so the
capability check, the scope check and the audit stay where they are.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field
from pydantic_ai import RunContext
from pydantic_ai.tools import Tool

from ..tools.gateway import ToolContext, ToolDefinition


class Conclusion(BaseModel):
    """What an agent concluded."""

    conclusion: str = Field(default="", description="What the agent found, in prose.")
    confidence: float = Field(default=0.0, description="How sure the agent is, from 0 to 1.")
    observations: list[str] = Field(default_factory=list)
    uncertainty: str = Field(default="")
    next_step: str = Field(default="")
    findings: list[str] = Field(default_factory=list)


def _python_type(schema: dict[str, Any]) -> Any:
    """The Python type of a JSON schema property."""
    kind = schema.get("type")
    if kind == "integer":
        return int
    if kind == "number":
        return float
    if kind == "boolean":
        return bool
    if kind == "array":
        return list
    if kind == "object":
        return dict
    return str


def build_tools(
    definitions: list[ToolDefinition], context: ToolContext
) -> list[Tool[Any, Any]]:
    """The gateway's tools as framework tools.

    Each tool becomes a function whose signature is generated from the
    tool's JSON schema, so the framework derives the same schema the
    gateway already published.
    """
    tools: list[Tool[Any, Any]] = []
    for definition in definitions:
        allowed, _ = context.permissions.check(definition.name, definition)
        if not allowed:
            continue
        tools.append(_as_tool(definition, context))
    return tools


def _as_tool(definition: ToolDefinition, context: ToolContext) -> Tool[Any, Any]:
    """One gateway tool as a framework tool."""
    properties = (definition.parameters or {}).get("properties", {}) or {}
    required = set((definition.parameters or {}).get("required", []) or [])

    async def call(ctx: RunContext[Any], **kwargs: Any) -> Any:
        tool_context: ToolContext = ctx.deps
        result = await definition.handler(**kwargs, context=tool_context)
        return json.dumps(result, default=str)

    parameters = [inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY)]
    for name, schema in properties.items():
        if name not in required:
            parameters.append(
                inspect.Parameter(
                    name, inspect.Parameter.KEYWORD_ONLY, default=None,
                    annotation=Optional[_python_type(schema)],
                )
            )
        else:
            parameters.append(
                inspect.Parameter(
                    name, inspect.Parameter.KEYWORD_ONLY,
                    annotation=_python_type(schema),
                )
            )
    call.__signature__ = inspect.Signature(parameters)
    call.__name__ = definition.name
    call.__doc__ = definition.description

    return Tool(
        call,
        takes_ctx=True,
        name=definition.name,
        description=definition.description,
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/unit/test_framework_tools.py -q`
Expected: PASS - 2 passed.

- [ ] **Step 6: Move the loop in `runtime.py` onto the framework**

In `b_hunters/platform/agents/runtime.py`, replace the hand-written loop with
a call to the framework:

```python
from .framework import Conclusion, build_tools

...
        definitions = self.gateway.registry.for_role(self.role.role, ctx.allowed_tools)
        tools = build_tools(definitions, ctx)
        ...
        agent = build_agent(
            self.role,
            tools,
            model=self._model(),
            output_type=Conclusion,
            usage_limits=UsageLimits(
                request_limit=budget.max_rounds,
                tool_calls_limit=budget.max_tool_calls,
                total_tokens_limit=budget.max_tokens,
            ),
        )
        result = await agent.run(prompt, deps=ctx, message_history=history)
```

with `self._model()` building the framework model from the platform's
provider configuration:

```python
    def _model(self) -> Any:
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        config = self.provider_config
        return OpenAIChatModel(
            config.model,
            provider=OpenAIProvider(base_url=config.base_url, api_key=config.api_key),
            settings=ModelSettings(max_tokens=config.max_output_tokens, temperature=0.2),
        )
```

Keep everything else in the runtime: the prompt assembly, the events, the
progress callback, the transcript and the error handling. The budget's wall
clock stays the platform's own check.

- [ ] **Step 7: Run the suite and the linter**

Run: `pytest tests/ -q`, `ruff check b_hunters tests`, `ruff format --check b_hunters tests`
Expected: all pass.

- [ ] **Step 8: Rebuild the platform and run a scan**

Run: `docker compose --env-file /home/sniper/pentest/.env -f docker-compose.platform.yml up -d --build platform`
then: `python3 dev/run_live_scan.py dvga`
Expected: the scan completes and the findings carry verdicts.

- [ ] **Step 9: Commit**

```bash
git add requirements.txt b_hunters/platform/agents/framework.py b_hunters/platform/agents/runtime.py tests/unit/test_framework_tools.py tests/unit/test_framework_conclusion.py
git commit -m "feat: run the agents on a framework"
```

---

### Task 4: The agents get the tools they need, and the shell stays in scope

**Files:**
- Modify: `b_hunters/platform/agents/roles.py`
- Modify: `b_hunters/platform/tools/builtin/shell.py`
- Modify: `b_hunters/platform/tools/builtin/__init__.py` (the new tool)
- Create: `b_hunters/platform/tools/builtin/worker_output.py`
- Test: `tests/unit/test_shell_scope.py`, `tests/unit/test_list_worker_output.py`

**Interfaces:**
- Consumes: `WorkerOutputRepository.list_for_scan`.
- Produces:
  - a new tool `list_worker_output(worker: str = "", kind: str = "", limit: int = 100)`;
  - `http_request` and `run_command` granted to the analysis roles;
  - `check_command` refusing a command that names a host outside the scan.

- [ ] **Step 1: Write the failing test for the scope check**

Create `tests/unit/test_shell_scope.py`:

```python
"""The sandbox may not leave the scope.

`python3` and `node` can open a socket to any host, which would be a way
around the scope enforcer that `http_request` goes through.  A command
that names a host outside the scan is refused.
"""

from __future__ import annotations

import pytest

from b_hunters.platform.tools.builtin.shell import check_command


def test_a_command_that_stays_in_the_workspace_is_allowed() -> None:
    parts = check_command(
        "grep -r secret .", allowlist=("grep",), deny_patterns=(), hosts=("172.25.0.15",)
    )
    assert parts[0] == "grep"


def test_a_command_that_names_an_out_of_scope_host_is_refused() -> None:
    with pytest.raises(Exception):
        check_command(
            "curl http://10.0.0.1/",
            allowlist=("curl",),
            deny_patterns=(),
            hosts=("172.25.0.15",),
        )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/unit/test_shell_scope.py -q`
Expected: FAIL - `check_command() got an unexpected keyword argument 'hosts'`

- [ ] **Step 3: Implement the scope check**

In `b_hunters/platform/tools/builtin/shell.py`:

```python
#: A host-like token in a command line.
_HOST_RE = re.compile(r"(?<![\w.-])([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)(?::\d+)?", re.I)
_IP_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")


def _hosts_in(command: str) -> set[str]:
    """The hosts a command names."""
    hosts = {match.group(1).lower() for match in _HOST_RE.finditer(command)}
    hosts |= {match.group(1) for match in _IP_RE.finditer(command)}
    return hosts


def check_command(
    command: str,
    *,
    allowlist: Sequence[str],
    deny_patterns: Sequence[str],
    hosts: Sequence[str] = (),
) -> list[str]:
    """Validate a command line against the shell policy.

    A command that names a host outside the scan's scope is refused: the
    shell can reach any host, and the scope is the platform's guarantee
    about what may be touched.
    """
    lowered = command.lower()
    for pattern in deny_patterns:
        if pattern.lower() in lowered:
            raise ToolPermissionError(f"the command contains the denied operation '{pattern.strip()}'")
    allowed_hosts = {host.lower() for host in hosts}
    if allowed_hosts:
        for host in _hosts_in(command):
            if host not in allowed_hosts:
                raise ToolPermissionError(
                    f"the command names '{host}', which is outside the scope of this scan"
                )
    parts = _split_command(command)
    ...
```

and in `run_command`, pass the hosts of the scan:

```python
    scope = getattr(context, "scope", None)
    hosts = tuple(getattr(scope, "authorized_hosts", ()) or ())
    parts = check_command(command, allowlist=allowlist, deny_patterns=deny_patterns, hosts=hosts)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/unit/test_shell_scope.py -q`
Expected: PASS - 2 passed.

- [ ] **Step 5: Add the `list_worker_output` tool**

Create `b_hunters/platform/tools/builtin/worker_output.py`:

```python
"""The output of the scanner workers, for an agent that wants to scan further."""

from __future__ import annotations

from typing import Any

from ..gateway import ToolContext, ToolError


def list_worker_output(
    worker: str = "",
    kind: str = "",
    limit: int = 100,
    *,
    context: ToolContext,
) -> dict[str, Any]:
    """List what the scanner workers produced for this scan.

    The crawlers find the URLs; the scanners test them.  A role that wants
    to test what a crawler found asks for it here.
    """
    repository = context.metadata.get("worker_output_repository")
    if repository is None:
        raise ToolError("the worker output repository is not available in this context")
    items = repository.list_for_scan(context.scan_id, worker=worker, kind=kind, limit=limit)
    return {
        "count": len(items),
        "items": [
            {"worker": item.get("worker", ""), "kind": item.get("kind", ""), "value": item.get("value", "")}
            for item in items
        ],
    }
```

Register it in `builtin/__init__.py`:

```python
    registry.register(
        "list_worker_output",
        "List what the scanner workers produced for this scan: the URLs the "
        "crawlers found, the paths the directory scanner found and the secrets "
        "the script scanner read.",
        LIST_WORKER_OUTPUT_SCHEMA,
        list_worker_output,
        capabilities={CAPABILITY_READ},
        timeout=30.0,
    )
```

with the schema:

```python
LIST_WORKER_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "worker": {"type": "string", "description": "Only the items of this worker."},
        "kind": {"type": "string", "description": "Only the items of this kind: url, path, secret, port, technology, finding."},
        "limit": {"type": "integer", "default": 100, "description": "How many items to return."},
    },
    "additionalProperties": False,
}
```

- [ ] **Step 6: Grant the tools to the roles**

In `b_hunters/platform/agents/roles.py`:

* add `http_request` to the roles that reason about behaviour and lack it;
* add `run_command` and `CAPABILITY_SHELL` to `recon`, `javascript`, `api`,
  `vuln_config` (the roles that work on artefacts), keeping the
  `source_analysis` grant;
* add `list_worker_output` to the roles that reason about the surface.

- [ ] **Step 7: Pass the repository to the tools**

In the orchestrator, where the tool context's metadata is built, add:

```python
            "worker_output_repository": self.worker_output,
```

- [ ] **Step 8: Run the suite, the linter and a scan**

Run: `pytest tests/ -q`, `ruff check b_hunters tests`,
`ruff format --check b_hunters tests`, then a DVGA scan.
Expected: all pass; the scan's roles use the new tools.

- [ ] **Step 9: Commit**

```bash
git add b_hunters/platform/agents/roles.py b_hunters/platform/tools/builtin/shell.py b_hunters/platform/tools/builtin/__init__.py b_hunters/platform/tools/builtin/worker_output.py b_hunters/platform/agents/orchestrator.py tests/unit/test_shell_scope.py tests/unit/test_list_worker_output.py
git commit -m "feat: give the agents the tools they need, and keep the shell in scope"
```
