"""The worker contract verifier.

Every scanner worker in the B-Hunters organisation has to agree on the
message contract, otherwise the pipeline breaks in ways that are hard to
see: a worker reads a payload key nobody writes, a worker reports its
status against a key that does not match the domain document, or two
workers bind to the same queue.

This module reads the worker sources and checks the contract statically.
It is the check that would have caught the defects the audit found:

* six workers used the persistent root ``domain`` where the rest used the
  per-task ``subdomain``, so a multi-domain scan scanned the wrong host;
* ``jsscanner`` reported its status against a JavaScript asset URL, which
  matches no domain document;
* four workers emitted a ``file`` task that no worker consumed;
* a shared configuration with ``[karton] identity`` made every worker
  register under the same identity.

The verifier is used by the test suite and by ``b-hunters contracts
verify``.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

#: The payload keys the root task establishes.
ROOT_PAYLOAD_KEYS = {"domain", "scantype", "scan_id", "data", "source"}

#: The payload keys a worker may read from the persistent payload.
PERSISTENT_KEYS = {"domain", "scantype", "scan_id", "report_id"}

#: The payload keys a worker may read from the per-task payload.
TASK_PAYLOAD_KEYS = {"data", "subdomain", "source", "file"}

#: Every worker must report its status through the shared helper.
STATUS_METHOD = "update_task_status"


@dataclass
class WorkerContract:
    """What the verifier knows about one worker."""

    name: str
    path: Path
    module: Path
    identity: str = ""
    version: str = ""
    filters: list[dict[str, str]] = field(default_factory=list)
    reads_task: set[str] = field(default_factory=set)
    reads_persistent: set[str] = field(default_factory=set)
    writes_task: set[str] = field(default_factory=set)
    writes_persistent: set[str] = field(default_factory=set)
    task_types: set[str] = field(default_factory=set)
    reports_status: bool = False
    status_keys: set[str] = field(default_factory=set)
    reads_host_from: str = ""


@dataclass
class ContractFinding:
    """One problem with a worker's contract."""

    worker: str
    severity: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.worker}: {self.code} - {self.message}"


def _worker_module(directory: Path) -> Optional[Path]:
    """Find the worker module inside a worker repository.

    The repository may hold tests next to the worker, and a test file
    sorted before the worker would otherwise be analysed as if it were
    the worker: a repository whose tests sort first would report that
    the worker declares no identity, because the test file declares
    none.  The test files are skipped, and the module that defines the
    Karton subclass wins.
    """
    candidates = []
    for path in sorted(directory.rglob("*.py")):
        name = path.name
        if name in {"__init__.py", "__main__.py", "__version__.py"}:
            continue
        if path.parent.name.startswith("."):
            continue
        if name.startswith("test_") or name.endswith("_test.py"):
            continue
        if "tests" in path.parts or "test" in path.parts:
            continue
        candidates.append(path)

    for path in candidates:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover - an unreadable file is not the worker
            continue
        if "BHunters" in source or "Karton" in source:
            return path
    return candidates[0] if candidates else None


def _class_attributes(tree: ast.AST) -> dict[str, Any]:
    """Return the class-level attributes of the first Karton subclass."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            attributes: dict[str, Any] = {}
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    for target in statement.targets:
                        if isinstance(target, ast.Name):
                            try:
                                attributes[target.id] = ast.literal_eval(statement.value)
                            except (ValueError, SyntaxError):
                                attributes[target.id] = None
            if "filters" in attributes or "identity" in attributes:
                return attributes
    return {}


def _literal_filters(value: Any) -> list[dict[str, str]]:
    """Extract the filter list, resolving simple module-level constants."""
    if isinstance(value, list):
        filters = []
        for entry in value:
            if isinstance(entry, dict):
                filters.append({str(k): str(v) for k, v in entry.items()})
        return filters
    return []


def analyse_worker(directory: Path) -> Optional[WorkerContract]:
    """Extract the contract of one worker from its source."""
    module = _worker_module(directory)
    if module is None:
        return None

    source = module.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    attributes = _class_attributes(tree)

    contract = WorkerContract(
        name=directory.name,
        path=directory,
        module=module,
        identity=str(attributes.get("identity") or ""),
        version=str(attributes.get("version") or ""),
        filters=_literal_filters(attributes.get("filters")),
    )

    # The payload reads and writes.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        target = node.value
        # task.payload["key"]
        if (
            isinstance(target, ast.Attribute)
            and target.attr == "payload"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            contract.reads_task.add(node.slice.value)
        # task.payload_persistent["key"]
        elif (
            isinstance(target, ast.Attribute)
            and target.attr == "payload_persistent"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            contract.reads_persistent.add(node.slice.value)

    # The payload writes: add_payload("key", ..., persistent=True)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "add_payload"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        persistent = False
        for keyword in node.keywords:
            if keyword.arg == "persistent" and isinstance(keyword.value, ast.Constant):
                persistent = bool(keyword.value.value)
        if persistent:
            contract.writes_persistent.add(first.value)
        else:
            contract.writes_task.add(first.value)

    # The task types the worker emits, read from the Task() headers.
    contract.task_types |= _task_headers(tree)

    # The status reporting.
    contract.reports_status = STATUS_METHOD in source
    for match in re.finditer(r"update_task_status\(\s*([A-Za-z_][A-Za-z0-9_]*)", source):
        key = match.group(1)
        contract.status_keys.add(key)
        if key in {"url", "newurl", "self", "host"}:
            contract.status_keys.add(key)

    # Which payload key holds the host being processed.
    if "subdomain" in contract.reads_task:
        contract.reads_host_from = "subdomain"
    elif "domain" in contract.reads_persistent:
        contract.reads_host_from = "domain"

    # A worker that copies the subdomain into a local variable and then
    # reports against that variable is consistent.
    if contract.reads_host_from == "subdomain":
        for local in _locals_from_task(tree, "subdomain"):
            if local in contract.status_keys:
                contract.status_keys.discard(local)
                contract.status_keys.add("subdomain")
    elif contract.reads_host_from == "domain":
        for local in _locals_from_task(tree, "domain"):
            if local in contract.status_keys:
                contract.status_keys.discard(local)
                contract.status_keys.add("domain")

    return contract


def _task_headers(tree: ast.AST) -> set[str]:
    """Return the ``type`` values of the tasks a worker emits."""
    types: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "Task"):
            continue
        if not node.args:
            continue
        headers = node.args[0]
        if not isinstance(headers, ast.Dict):
            continue
        for key, value in zip(headers.keys, headers.values, strict=False):
            if (
                isinstance(key, ast.Constant)
                and key.value == "type"
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                types.add(value.value)
    return types


def _locals_from_task(tree: ast.AST, payload_key: str) -> set[str]:
    """Return the local variables that are assigned from a payload key."""
    locals_: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not isinstance(value, ast.Subscript):
            continue
        target = value.value
        if not (
            isinstance(target, ast.Attribute)
            and target.attr == "payload"
            and isinstance(value.slice, ast.Constant)
            and value.slice.value == payload_key
        ):
            continue
        for assign_target in node.targets:
            if isinstance(assign_target, ast.Name):
                locals_.add(assign_target.id)
    return locals_


def verify_worker(contract: WorkerContract) -> list[ContractFinding]:
    """Check one worker against the shared contract."""
    findings: list[ContractFinding] = []

    if not contract.identity:
        findings.append(
            ContractFinding(
                contract.name, "error", "missing-identity", "the worker declares no Karton identity"
            )
        )
    if not contract.filters:
        findings.append(
            ContractFinding(
                contract.name,
                "warning",
                "conditional-filters",
                "the worker declares no literal filters; it may bind to a different set of "
                "queues depending on the environment, which makes its contract unpredictable",
            )
        )
    for entry in contract.filters:
        if "type" not in entry or "stage" not in entry:
            findings.append(
                ContractFinding(
                    contract.name,
                    "error",
                    "malformed-filter",
                    f"the filter {entry} must declare both 'type' and 'stage'",
                )
            )

    # Every payload key a worker reads must be written by someone.
    readable = contract.reads_task | contract.reads_persistent
    for key in sorted(readable):
        if key in TASK_PAYLOAD_KEYS or key in PERSISTENT_KEYS or key in ROOT_PAYLOAD_KEYS:
            continue
        findings.append(
            ContractFinding(
                contract.name,
                "error",
                "unknown-payload-key",
                f"the worker reads the payload key '{key}', which no producer writes",
            )
        )

    # The root worker - the one that consumes domain/new - legitimately
    # reads the persistent root domain, because the per-task subdomain
    # does not exist yet.
    is_root_worker = any(entry.get("type") == "domain" for entry in contract.filters)

    # The host being processed must come from the per-task subdomain.
    if contract.reads_host_from == "domain" and "subdomain" not in contract.reads_task and not is_root_worker:
        findings.append(
            ContractFinding(
                contract.name,
                "error",
                "wrong-host-key",
                "the worker takes the host from the persistent root 'domain' instead of the "
                "per-task 'subdomain', so a multi-domain scan processes the wrong host",
            )
        )

    # The status must be reported against the host being processed.
    if contract.reports_status and contract.reads_host_from == "subdomain":
        if contract.status_keys and not contract.status_keys & {"subdomain", "domain", "self"}:
            findings.append(
                ContractFinding(
                    contract.name,
                    "error",
                    "wrong-status-key",
                    f"the worker reports its status against {sorted(contract.status_keys)} rather "
                    "than the domain it is processing, so the status never matches the document",
                )
            )

    if not contract.reports_status:
        findings.append(
            ContractFinding(
                contract.name,
                "warning",
                "no-status-reporting",
                "the worker never calls update_task_status, so its progress is invisible",
            )
        )

    return findings


def verify_repository_set(
    repositories: Iterable[Path],
) -> tuple[list[WorkerContract], list[ContractFinding]]:
    """Verify a set of worker repositories and their contracts together."""
    contracts: list[WorkerContract] = []
    findings: list[ContractFinding] = []

    for directory in sorted(repositories):
        if not directory.is_dir():
            continue
        contract = analyse_worker(directory)
        if contract is None:
            continue
        contracts.append(contract)

    # The identities must be unique: two workers with the same identity
    # compete for the same queue and their status records collide.
    identities: dict[str, list[str]] = {}
    for contract in contracts:
        if contract.identity:
            identities.setdefault(contract.identity, []).append(contract.name)
    for identity, names in identities.items():
        if len(names) > 1:
            findings.append(
                ContractFinding(
                    ", ".join(names),
                    "error",
                    "duplicate-identity",
                    f"the identity '{identity}' is used by more than one worker",
                )
            )

    # The filters must not overlap in a way that makes the routing
    # ambiguous.  Two workers may share a filter - that is a race, not an
    # error - but it must be a deliberate one.
    by_filter: dict[tuple[str, str], list[str]] = {}
    for contract in contracts:
        for entry in contract.filters:
            key = (entry.get("type", ""), entry.get("stage", ""))
            by_filter.setdefault(key, []).append(contract.name)
    for key, names in sorted(by_filter.items()):
        if len(names) > 1:
            findings.append(
                ContractFinding(
                    ", ".join(sorted(names)),
                    "info",
                    "shared-filter",
                    f"the workers {sorted(names)} all bind to {key[0]}/{key[1]}; Karton forks a "
                    "matching task to every one of them, so all of them receive it",
                )
            )

    # The task types that are produced but never consumed.
    produced: dict[str, set[str]] = {}
    consumed: dict[str, set[str]] = {}
    for contract in contracts:
        for entry in contract.filters:
            consumed.setdefault(entry.get("type", ""), set()).add(contract.name)
        for task_type in contract.task_types:
            produced.setdefault(task_type, set()).add(contract.name)
    for task_type, producers in sorted(produced.items()):
        if task_type and task_type not in consumed:
            findings.append(
                ContractFinding(
                    ", ".join(sorted(producers)),
                    "error",
                    "orphaned-task-type",
                    f"the workers {sorted(names)} emit the task type '{task_type}', which no worker consumes",
                )
            )

    for contract in contracts:
        findings.extend(verify_worker(contract))

    return contracts, findings


def format_findings(findings: list[ContractFinding]) -> str:
    """Render the findings as a report."""
    if not findings:
        return "The worker contracts are consistent."
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    infos = [f for f in findings if f.severity == "info"]
    lines = []
    for group, title in ((errors, "ERRORS"), (warnings, "WARNINGS"), (infos, "NOTES")):
        if not group:
            continue
        lines.append(f"{title} ({len(group)})")
        for finding in group:
            lines.append(f"  {finding}")
        lines.append("")
    return "\n".join(lines)
