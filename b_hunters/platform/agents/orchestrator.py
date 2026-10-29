"""The scan orchestrator.

The orchestrator owns the scan lifecycle:

1. Build a plan from the authorised scope and the scan profile.
2. Dispatch the deterministic scanner work (the existing B-Hunters Karton
   workers) and the agent work.
3. Run agent tasks respecting their dependencies, with bounded concurrency.
4. Feed candidate findings to the adjudicator, which reconciles them and
   records a verdict for each.
5. Watch for stalls, budget exhaustion and cancellation, and stop cleanly.

The orchestrator never contacts a target itself - it only dispatches work
and records what happened.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..db.client import Database
from ..db.repositories import (
    AgentStateRepository,
    EventRepository,
    FindingRepository,
    MessageRepository,
    ScanRepository,
    ServiceRepository,
    TaskRepository,
    ToolCallRepository,
    compute_fingerprint,
)
from ..db.worker_output_repository import WorkerOutputRepository
from ..scanners.base import ScanRequest, ScanResult
from ..scanners.karton_bridge import (
    KartonWorkerBridge,
    WorkerResults,
    finding_for_platform,
)
from ..scanners.registry import AdapterRegistry
from ..security.scope import ScopeEnforcer, ScopePolicy, build_policy_from_scan
from ..settings import Settings, get_settings
from ..tools.gateway import ToolContext, ToolGateway, ToolPermissions, ToolRegistry
from .collaboration import CollaborationState
from .provider import Provider
from .roles import AgentRole, builtin_roles
from .runtime import AgentRuntime, AgentRuntimeConfig, parse_findings
from .schemas import (
    AgentMessage,
    AgentTask,
    Budget,
    CandidateFinding,
)

log = logging.getLogger(__name__)

#: Roles that propose findings.
HYPOTHESIS_ROLES = (
    "recon",
    "javascript",
    "api",
    "authn",
    "access_control",
    "vuln_injection",
    "vuln_xss",
    "vuln_ssrf",
    "vuln_config",
    "source_analysis",
)

#: Roles that verify findings.  The independent verifier is **not** part
#: of the default plan: it re-checks every candidate finding, which costs
#: a request each, and the adjudicator judges the findings anyway.  A
#: scan that asks for the role by name still gets it - the roles of a
#: scan are overridable - so nothing is lost by leaving it out.
VERIFICATION_ROLES = ("verifier",)

#: Roles that report.
REPORTING_ROLES = ("adjudicator",)

#: The phases of a scan.  The phase a scan records is the phase it is
#: *about to run*: a scan that reached ``agents`` has done its workers
#: and continues with the agents.  ``completed`` means there is nothing
#: left to do.
SCAN_PHASES = ("workers", "agents", "verifying", "reporting", "completed")

#: The share of the scan's duration the worker phase may use.  The agent
#: roles run after it and need the rest: the workers are the slow part of
#: a scan, and a request budget they have spent leaves the agents unable
#: to reach the target they are supposed to reason about.
WORKER_PHASE_SHARE = 0.5

#: The share the agent phase gets.
AGENT_PHASE_SHARE = 0.5


#: How many candidate findings the verification role judges.  It re-checks
#: each one it is given, and re-checking costs a request per candidate:
#: judging all of them leaves it no budget to record the verdicts.
VERIFIER_CANDIDATE_LIMIT = 12


#: The rounds a judging role needs per finding it must judge.  A judge
#: spends roughly one round reading a finding and one recording the
#: verdict.  The number of findings is only known once the workers and
#: the hypothesis roles have run - which is before the judge runs - so
#: the judge's budget is scaled with it.  With a fixed budget the
#: adjudicator ran out of rounds after half of the findings and left
#: the rest unverified.
JUDGING_ROUNDS_PER_FINDING = 2

#: The extra rounds a judging role gets on top of the ones it needs.
JUDGING_ROUND_MARGIN = 4

#: The most rounds a judging role may take.  At roughly twenty thousand
#: tokens a round this keeps the run inside the per-task token budget.
MAX_JUDGING_ROUNDS = 60

#: The tokens a judging round is assumed to cost, used to size the
#: token budget of a judging role against its rounds.
TOKENS_PER_JUDGING_ROUND = 25000


def _kind_of(field: str) -> str:
    """The kind of item a worker wrote."""
    lowered = field.lower()
    if lowered.startswith("secrets in"):
        return "secret"
    if lowered == "links":
        return "url"
    if lowered.startswith("paths"):
        return "path"
    if lowered.startswith("ports"):
        return "port"
    if lowered.startswith("technology"):
        return "technology"
    if lowered.startswith("screenshot") or lowered.startswith("data."):
        return "screenshot"
    if lowered.startswith("vulns"):
        return "finding"
    return "item"


def _values_of(item: dict[str, Any]) -> list[str]:
    """The individual values of one written item.

    A worker writes a list of URLs or a list of paths as one entry; the
    platform keeps the items apart, so that a scan of them can be made.
    """
    preview = str(item.get("preview", ""))
    values = [
        line.strip()
        for line in preview.splitlines()
        if line.strip() and not line.strip().startswith(("key:", "value:", "- "))
    ]
    return values or ([preview.strip()] if preview.strip() else [])


def agent_roles_for(profile: ScanProfile, *, verification_enabled: bool) -> list[str]:
    """The agent roles a scan runs.

    The independent verifier is opt-in.  It re-checks every candidate
    finding, which costs a request each, and the adjudicator judges the
    findings anyway - so the verifier is left out unless it is asked for.
    A scan that names the role in its own role list still gets it.
    """
    roles = list(profile.agent_roles)
    if verification_enabled:
        for role in VERIFICATION_ROLES:
            if role not in roles:
                roles.append(role)
    return roles


def _by_severity(candidates: Sequence[CandidateFinding]) -> list[CandidateFinding]:
    """The candidates, the most severe first."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        candidates,
        key=lambda c: (order.get(str(c.severity).lower(), 5), -float(c.confidence or 0)),
    )


def _confidence_of(value: Any) -> float:
    """The confidence of a stored finding, as a number."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.5


@dataclass
class _StageState:
    """What the stages of a scan achieved so far.

    The state is shared by the stages of one run: a task of a later
    stage depends on the tasks of an earlier one, and the dependency is
    only satisfied when the task before it finished.
    """

    #: The tasks that finished successfully.
    completed: set[str] = field(default_factory=set)
    #: The tasks that failed or were cancelled.
    failed: set[str] = field(default_factory=set)


@dataclass
class ScanProfile:
    """A named bundle of agents, scanners and limits."""

    name: str
    description: str = ""
    agent_roles: list[str] = field(default_factory=list)
    scanners: list[str] = field(default_factory=list)
    max_concurrency: int = 4
    max_duration_seconds: int = 3600
    max_requests_per_second: float = 10.0
    request_timeout: float = 20.0
    safe_mode: bool = True
    allow_state_changing: bool = False

    @classmethod
    def default(cls) -> ScanProfile:
        return cls(
            name="standard",
            description="Discovery, analysis, verification and reporting across all agent roles.",
            agent_roles=list(HYPOTHESIS_ROLES) + list(REPORTING_ROLES),
            scanners=[
                "subrecon",
                "nmap",
                "gowitness",
                "dirsearch",
                "paramspider",
                "webtechnology",
                "gospider",
                "katana",
                "getjs",
                "jsscanner",
                "nuclei",
                "service_fingerprint",
                "security_headers",
                "tls_configuration",
                "secret_scan",
                "openapi_discovery",
                "graphql_analysis",
            ],
            max_concurrency=4,
        )

    @classmethod
    def reconnaissance_only(cls) -> ScanProfile:
        profile = cls.default()
        profile.name = "recon"
        profile.description = "Discovery only - no active vulnerability testing."
        profile.agent_roles = ["recon", "javascript", "api"]
        profile.scanners = [
            "subrecon",
            "nmap",
            "webtechnology",
            "gospider",
            "katana",
            "getjs",
            "jsscanner",
            "openapi_discovery",
            "graphql_analysis",
        ]
        return profile

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanProfile:
        """Build a profile from stored data.

        A stored profile usually carries only the fields that differ from
        the named default, so the defaults are applied first and the stored
        values are layered on top.  Without this, a profile stored as
        ``{"name": "standard"}`` would silently lose its scanner and agent
        lists and produce an empty scan.
        """
        data = data or {}
        name = str(data.get("name") or "standard")
        if name == "recon":
            profile = cls.reconnaissance_only()
        else:
            profile = cls.default()
        profile.name = name
        known = set(cls.__dataclass_fields__)
        for key, value in data.items():
            if key in known and value not in (None, "", [], 0):
                setattr(profile, key, value)
        return profile


@dataclass
class ScanContext:
    """Everything an orchestrator run needs."""

    scan_id: str
    name: str
    targets: list[str]
    authorized_hosts: list[str]
    excluded_paths: list[str] = field(default_factory=list)
    profile: ScanProfile = field(default_factory=ScanProfile.default)
    test_accounts: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    schema_artifacts: list[str] = field(default_factory=list)
    safe_mode: bool = True
    allow_private_network: bool = False
    allow_state_changing: bool = False
    max_duration_seconds: int = 3600
    max_requests_per_second: float = 10.0
    request_timeout: float = 20.0
    workspace_root: str = ""
    options: dict[str, Any] = field(default_factory=dict)

    def scope_policy(self) -> ScopePolicy:
        return build_policy_from_scan(
            authorized_hosts=self.authorized_hosts,
            excluded_paths=self.excluded_paths,
            allow_private_network=self.allow_private_network,
            allow_http=True,
            allow_state_changing=self.allow_state_changing,
            max_requests_per_second=self.max_requests_per_second,
            max_concurrency=self.profile.max_concurrency,
            max_duration_seconds=self.max_duration_seconds,
            timeout=self.request_timeout,
        )


class ScanOrchestrator:
    """Runs one scan from start to finish."""

    def __init__(
        self,
        *,
        database: Database,
        settings: Settings | None = None,
        provider_factory: Optional[Callable[[str], Provider]] = None,
        tool_registry: Optional[ToolRegistry] = None,
        scanner_registry: Optional[AdapterRegistry] = None,
        worker_bridge: Optional[KartonWorkerBridge] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.db = database
        self.scans = ScanRepository(database)
        self.events = EventRepository(database)
        self.tasks = TaskRepository(database)
        self.agents = AgentStateRepository(database)
        self.messages = MessageRepository(database)
        self.findings = FindingRepository(database)
        self.tool_calls = ToolCallRepository(database)
        self.services = ServiceRepository(database)
        self.worker_output = WorkerOutputRepository(database)
        self.provider_factory = provider_factory
        self.tool_registry = tool_registry or ToolRegistry()
        self.scanner_registry = scanner_registry or AdapterRegistry()
        #: The bridge to the real Karton scanner workers.  ``None`` when the
        #: worker stack is not reachable; the scan then runs the native
        #: adapters and the agents only.
        self.worker_bridge = worker_bridge
        self.gateway = ToolGateway(
            self.tool_registry,
            audit=self._audit_tool_call,
        )
        self._cancelled_scans: set[str] = set()

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------
    def _emit(self, scan_id: str, kind: str, payload: dict[str, Any], actor: str = "") -> None:
        try:
            self.events.append(scan_id=scan_id, kind=kind, payload=payload, actor=actor)
        except Exception:  # pragma: no cover - persistence must not break a scan
            log.exception("failed to persist a scan event")

    def _audit_tool_call(self, record: dict[str, Any]) -> None:
        try:
            self.tool_calls.record(record)
        except Exception:  # pragma: no cover
            log.exception("failed to persist a tool call record")

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------
    def cancel(self, scan_id: str) -> None:
        """Request cooperative cancellation of a running scan."""
        self._cancelled_scans.add(scan_id)
        self.scans.set_status(scan_id, "stopping")
        self._emit(scan_id, "scan.stop_requested", {"requested_at": time.time()})
        for task in self.tasks.list_for_scan(scan_id):
            if task.get("status") in {"pending", "ready", "running"}:
                self.tasks.set_status(task["task_id"], "cancelled", error="cancelled by operator")

    def _is_cancelled(self, scan_id: str) -> bool:
        if scan_id in self._cancelled_scans:
            return True
        record = self.scans.get(scan_id)
        return bool(record and record.status in {"stopping", "cancelled"})

    def _is_paused(self, scan_id: str) -> bool:
        record = self.scans.get(scan_id)
        return bool(record and record.status == "paused")

    async def _wait_while_paused(self, scan_id: str) -> None:
        """Block while the operator has paused the scan.

        The pause is a real backend control: no new agent task or scanner
        dispatch starts until the scan is resumed.
        """
        waited = 0.0
        while self._is_paused(scan_id) and not self._is_cancelled(scan_id):
            await asyncio.sleep(0.5)
            waited += 0.5
            if waited > 3600:
                log.warning("scan %s stayed paused for over an hour", scan_id)
                waited = 0.0

    # ------------------------------------------------------------------
    # Plan
    # ------------------------------------------------------------------
    def build_plan(self, context: ScanContext) -> list[AgentTask]:
        """Build the agent task graph for a scan."""
        roles = dict(builtin_roles())
        enabled = set(context.profile.agent_roles)
        tasks: list[AgentTask] = []

        def add(role_id: str, title: str, objective: str, depends_on: list[str], target: str = "") -> str:
            role = roles.get(role_id)
            if role is None or role_id not in enabled:
                return ""
            task = AgentTask(
                task_id=f"{context.scan_id}:{role_id}",
                scan_id=context.scan_id,
                role=role_id,
                title=title,
                objective=objective,
                target=target,
                depends_on=list(depends_on),
                budget=Budget(
                    max_tokens=self._agent_budget(
                        role,
                        "max_tokens",
                        120000,
                        self.settings.agent_max_tokens_per_task,
                    ),
                    max_tool_calls=self._agent_budget(
                        role,
                        "max_tool_calls",
                        40,
                        self.settings.agent_max_tool_calls_per_task,
                    ),
                    max_rounds=self._agent_budget(
                        role,
                        "max_rounds",
                        6,
                        self.settings.agent_max_rounds,
                    ),
                    max_wall_clock_seconds=min(
                        int((role.budget or {}).get("max_wall_clock_seconds", 900)),
                        int(self.settings.agent_wall_clock_seconds),
                    ),
                ),
            )
            tasks.append(task)
            return task.task_id

        hypothesis_ids: list[str] = []
        for role_id in HYPOTHESIS_ROLES:
            if role_id not in enabled:
                continue
            role = roles[role_id]
            task_id = add(
                role_id,
                f"{role.title}",
                f"{role.objective} Target scope: {', '.join(context.authorized_hosts)}.",
                [],
                target=", ".join(context.targets[:3]),
            )
            if task_id:
                hypothesis_ids.append(task_id)

        verification_ids: list[str] = []
        for role_id in VERIFICATION_ROLES:
            if role_id not in enabled:
                continue
            role = roles[role_id]
            task_id = add(
                role_id,
                f"{role.title}",
                role.objective,
                list(hypothesis_ids),
            )
            if task_id:
                verification_ids.append(task_id)

        for role_id in REPORTING_ROLES:
            if role_id not in enabled:
                continue
            role = roles[role_id]
            add(role_id, f"{role.title}", role.objective, list(verification_ids or hypothesis_ids))

        return tasks

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    async def run(self, context: ScanContext) -> dict[str, Any]:
        """Execute the scan, or the part of it that is left.

        The scan records the phase it reached.  A scan that is picked up
        again - because the runner that was working on it died - starts
        at that phase: the stages before it are not run a second time,
        and the agent tasks that already succeeded are not run again.
        """
        started = time.monotonic()
        self.scans.set_status(context.scan_id, "running")
        self._emit(context.scan_id, "scan.started", {"profile": context.profile.name})

        scope = ScopeEnforcer(context.scope_policy())
        plan = self.build_plan(context)

        # Persist the plan as tasks, keeping the plan's task identifiers so
        # that the dependency graph, the agent runs and the persisted task
        # records all refer to the same task.  A task that already
        # succeeded keeps its result and is not run again.
        for agent_task in plan:
            self.tasks.upsert(
                scan_id=context.scan_id,
                task_id=agent_task.task_id,
                title=agent_task.title,
                kind="agent",
                agent_role=agent_task.role,
                depends_on=agent_task.depends_on,
                budget=agent_task.budget.to_dict(),
                input={"objective": agent_task.objective, "target": agent_task.target},
            )

        record = self.scans.get(context.scan_id)
        phase = record.phase if record is not None else "pending"
        stages = self._stages_from(phase)
        state = _StageState()

        try:
            await self._wait_while_paused(context.scan_id)
            # The agents get their own request budget.  The worker phase
            # runs first and the scope enforcer's duration budget covers
            # the whole scan, so a budget the workers have spent leaves the
            # agents unable to make a single request - they would reason
            # about a target they cannot reach.
            agent_scope: Optional[ScopeEnforcer] = None
            tokens_spent = 0
            for stage in stages:
                if self._is_cancelled(context.scan_id):
                    break
                if stage == "workers":
                    await self._dispatch_scanners(context, scope)
                    await self._dispatch_workers(context, scope)
                    self._write_coverage(context)
                    self.scans.set_phase(context.scan_id, self._phase_after(stage))
                    continue
                if agent_scope is None:
                    agent_scope = ScopeEnforcer(self._phase_policy(context, AGENT_PHASE_SHARE))
                tokens_spent = await self._run_agent_tasks(
                    context,
                    self._tasks_for_stage(plan, stage),
                    agent_scope,
                    state,
                    spent=tokens_spent,
                )
                self.scans.set_phase(context.scan_id, self._phase_after(stage))
        except asyncio.CancelledError:
            self.scans.set_status(context.scan_id, "cancelled")
            self._emit(context.scan_id, "scan.cancelled", {"at": time.time()})
            raise
        except Exception as exc:
            log.exception("scan %s failed", context.scan_id)
            self.scans.set_status(context.scan_id, "failed", error=str(exc))
            self._emit(context.scan_id, "scan.failed", {"error": str(exc)})
            return {"status": "failed", "error": str(exc)}

        if self._is_cancelled(context.scan_id):
            self.scans.set_status(context.scan_id, "cancelled")
            self._emit(context.scan_id, "scan.cancelled", {"at": time.time()})
            return {"status": "cancelled"}

        duration = round(time.monotonic() - started, 2)
        self.scans.set_stats(
            context.scan_id,
            {
                "duration_seconds": duration,
                "findings": self.findings.count(context.scan_id),
                "scope_violations": scope.violation_count(),
            },
        )
        self.scans.set_status(context.scan_id, "completed")
        self._emit(
            context.scan_id,
            "scan.completed",
            {"duration_seconds": duration, "findings": self.findings.count(context.scan_id)},
        )
        return {"status": "completed", "duration_seconds": duration}

    async def _dispatch_scanners(self, context: ScanContext, scope: ScopeEnforcer) -> None:
        """Run the native (in-process) scanner adapters for this scan.

        The Karton-dispatched workers are started separately by the Karton
        producer; the native adapters run here so that their results are
        persisted by the same code path as the agent findings.
        """
        native_names = {
            name
            for name in context.profile.scanners
            if (spec := self.scanner_registry.spec(name)) is not None and spec.kind == "native"
        }
        if not native_names:
            return

        semaphore = asyncio.Semaphore(max(1, context.profile.max_concurrency))

        async def run_one(name: str) -> None:
            adapter = self.scanner_registry.get(name)
            if adapter is None:
                return
            async with semaphore:
                if self._is_cancelled(context.scan_id):
                    return
                self.agents.upsert(
                    scan_id=context.scan_id,
                    role=f"scanner:{name}",
                    status="running",
                    conclusion=f"running {name}",
                )
                request = ScanRequest(
                    scan_id=context.scan_id,
                    targets=list(context.targets),
                    options=dict(context.options),
                    scope=scope,
                    seeds=list(context.artifacts) + list(context.schema_artifacts),
                    test_accounts=list(context.test_accounts),
                )
                result: ScanResult = await adapter.execute(request)
                self._persist_scanner_result(context, name, result)
                self.agents.upsert(
                    scan_id=context.scan_id,
                    role=f"scanner:{name}",
                    status="idle",
                    conclusion=(
                        f"{len(result.items)} item(s), {len(result.error) and 'with errors' or 'no errors'}"
                    ),
                )

        await asyncio.gather(*(run_one(name) for name in sorted(native_names)))

    @staticmethod
    def _phase_policy(context: ScanContext, share: float) -> ScopePolicy:
        """A scope policy with the duration budget of one phase."""
        policy = context.scope_policy()
        return ScopePolicy(
            authorized_hosts=policy.authorized_hosts,
            excluded_paths=policy.excluded_paths,
            authorized_ports=policy.authorized_ports,
            denied_hosts=policy.denied_hosts,
            allow_private_network=policy.allow_private_network,
            allow_http=policy.allow_http,
            allow_state_changing=policy.allow_state_changing,
            safe_methods=policy.safe_methods,
            max_requests_per_second=policy.max_requests_per_second,
            max_concurrency=policy.max_concurrency,
            max_response_bytes=policy.max_response_bytes,
            max_redirects=policy.max_redirects,
            timeout=policy.timeout,
            max_duration_seconds=max(30, int(policy.max_duration_seconds * share)),
        )

    @staticmethod
    def _agent_budget(role: Any, key: str, default: int, override: int) -> int:
        """The budget of one agent task.

        The role carries a default, and the deployment can raise it.  The
        override is a floor and not a replacement: a reasoning model needs
        more of the token budget than a plain one - it spends a large part
        of every turn on reasoning, and the prompt grows with every tool
        result - so the deployment's value wins where the role asks for
        less.  A role that asks for *more* keeps it: the role knows the
        work better than the deployment does.
        """
        role_value = int((role.budget or {}).get(key, default))
        if override:
            return max(role_value, int(override))
        return role_value

    def _budget_for_task(self, context: ScanContext, role: Any, task: AgentTask) -> Budget:
        """The budget of one agent task, scaled for a role that judges findings.

        A judge needs about two rounds per finding - one to read it, one
        to record the verdict - and it only knows how many findings there
        are once the workers and the hypothesis roles have run, which is
        before the judge runs.  With a fixed budget the adjudicator ran
        out of rounds after it had judged half of the findings and left
        the rest unverified, so the budget of a judging role is sized
        against the findings that are still waiting for a verdict.
        """
        budget = task.budget
        if role.stage not in {"verification", "reporting"}:
            return budget
        try:
            pending = len(
                self.findings.list(
                    context.scan_id,
                    verification_status=("unverified",),
                    limit=2000,
                )
            )
        except Exception:  # pragma: no cover - the budget must never break a scan
            log.exception("failed to count the findings waiting for a verdict")
            return budget
        if pending <= 0:
            return budget
        rounds = min(
            MAX_JUDGING_ROUNDS,
            max(budget.max_rounds, pending * JUDGING_ROUNDS_PER_FINDING + JUDGING_ROUND_MARGIN),
        )
        calls = max(budget.max_tool_calls, pending * JUDGING_ROUNDS_PER_FINDING + JUDGING_ROUND_MARGIN)
        tokens = max(budget.max_tokens, rounds * TOKENS_PER_JUDGING_ROUND)
        return Budget(
            max_tokens=tokens,
            max_tool_calls=calls,
            max_rounds=rounds,
            max_wall_clock_seconds=budget.max_wall_clock_seconds,
            max_tasks=budget.max_tasks,
        )

    async def _dispatch_workers(self, context: ScanContext, scope: ScopeEnforcer) -> None:
        """Run the real Karton scanner workers for this scan.

        The workers are separate containers that reach the target from
        their own network namespace, so the platform does not make the
        request itself: it publishes the task and reads back what the
        workers wrote into the report document.  Only targets the scan
        scope already covers are handed to them.
        """
        if self.worker_bridge is None:
            return

        targets = [url for url in context.targets if self._is_in_scope(context, scope, url)]
        skipped = len(context.targets) - len(targets)
        if skipped:
            self._emit(
                context.scan_id,
                "worker.skipped",
                {"count": skipped, "reason": "the target is not covered by the scan scope"},
            )
        if not targets:
            return

        self._emit(
            context.scan_id,
            "workers.dispatched",
            {"targets": targets, "count": len(targets)},
        )

        started = time.monotonic()
        budget = max(10.0, float(context.max_duration_seconds) * WORKER_PHASE_SHARE)
        try:
            results = await asyncio.to_thread(self._run_workers, context, targets, budget)
        except Exception as exc:
            log.exception("the scanner workers failed for scan %s", context.scan_id)
            self._emit(context.scan_id, "worker.error", {"error": str(exc)})
            return

        for target, outcome in results:
            if not outcome.consumed:
                self._emit(
                    context.scan_id,
                    "worker.error",
                    {
                        "target": target.domain,
                        "error": "no scanner worker consumed the task",
                    },
                )
                continue
            self._persist_worker_results(context, target, outcome)
            self._emit(
                context.scan_id,
                "workers.completed",
                {
                    "target": target.domain,
                    "report_id": outcome.report_id,
                    "findings": len(outcome.findings),
                    "services": len(outcome.services),
                },
            )

        self._emit(
            context.scan_id,
            "workers.finished",
            {"duration_seconds": round(time.monotonic() - started, 2)},
        )

    def _run_workers(self, context: ScanContext, targets: list[str], budget: float) -> list:
        """Publish the targets and collect the results.  Runs in a thread.

        Every target is published before the first one is collected, and
        the results are collected concurrently.  The workers are separate
        containers and they scan in parallel, so waiting for one target
        before publishing the next one - or collecting the targets one
        after the other - would spend the whole budget on the first
        target and leave the others with nothing.
        """
        deadline = time.monotonic() + budget
        before = self.worker_bridge.consumed_tasks()
        # The counters are kept across every scan, so the ones from before
        # this scan are what tell the console which workers took part in
        # *this* scan while it is still running.
        self.scans.update(context.scan_id, {"workers_before": before})
        prepared = []
        for url in targets:
            if self._is_cancelled(context.scan_id):
                break
            target = self.worker_bridge.prepare(
                url=url,
                description=context.name,
                platform_scan_id=context.scan_id,
            )
            try:
                root_uid = self.worker_bridge.dispatch(target)
            except Exception as exc:
                log.warning("could not publish the task for %s: %s", target.domain, exc)
                continue
            prepared.append((target, root_uid))

        if not prepared:
            return []

        def collect_one(item):
            target, root_uid = item
            try:
                return target, self.worker_bridge.collect(target, root_uid=root_uid, deadline=deadline)
            except Exception as exc:
                log.warning("could not collect the results for %s: %s", target.domain, exc)
                return target, WorkerResults()

        with ThreadPoolExecutor(max_workers=len(prepared)) as pool:
            futures = [pool.submit(collect_one, item) for item in prepared]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=max(1.0, deadline - time.monotonic())))
                except Exception as exc:
                    log.warning("the worker results could not be collected: %s", exc)

        self._record_participation(context, before)
        self._ingest_worker_output(context)
        return outcomes

    def _ingest_worker_output(self, context: ScanContext) -> None:
        """Save what the scanner workers produced.

        The workers write into the legacy documents.  The platform keeps a
        copy of the same items, so that they can be queried through the
        API, shown in the console and handed to an agent that wants to
        scan further.
        """
        from ..scanners import worker_output

        try:
            report_id, report = worker_output.report_for_scan(self.db, context.scan_id)
        except Exception as exc:  # pragma: no cover - the database may be down
            log.warning("the worker output could not be read: %s", exc)
            return
        if not report:
            return
        produced = worker_output.produced(self.db, report)
        rows: list[dict[str, Any]] = []
        for identity, items in produced.items():
            for item in items:
                for value in item.get("values") or _values_of(item):
                    rows.append(
                        {
                            "worker": identity,
                            "kind": _kind_of(str(item.get("field", ""))),
                            "value": value,
                            "source": report_id,
                        }
                    )
        saved = self.worker_output.replace_for_scan(context.scan_id, rows)
        log.info("saved %s item(s) of worker output for %s", saved, context.scan_id)

    def _record_participation(self, context: ScanContext, before: dict[str, int]) -> None:
        """Record which workers took part in this scan.

        A worker that found nothing writes nothing anywhere, so without this
        there is no way to tell "ran and found nothing" from "never ran".
        Karton counts the tasks every service consumed, so the difference
        between the counters before and after the scan is who took part.
        """
        after = self.worker_bridge.consumed_tasks()
        participation = {
            identity: count - before.get(identity, 0)
            for identity, count in after.items()
            if count - before.get(identity, 0) > 0
        }
        if participation:
            self.scans.update(context.scan_id, {"workers": participation})

    def _persist_worker_results(self, context: ScanContext, target: Any, outcome: Any) -> None:
        """Turn the worker output into platform findings and services."""
        for finding in outcome.findings:
            mapped = finding_for_platform(finding, target)
            self.findings.upsert(
                scan_id=context.scan_id,
                title=mapped["title"],
                summary=mapped["summary"],
                vuln_class=mapped["vuln_class"],
                severity=mapped["severity"],
                host=mapped["host"],
                path=mapped["path"],
                parameter=mapped["parameter"],
                cwe=mapped["cwe"],
                confidence=mapped["confidence"],
                detected_by=mapped["detected_by"],
                detection_source=mapped["detection_source"],
                affected_url=mapped["affected_url"],
                evidence=mapped["evidence"],
                remediation=mapped["remediation"],
                extra_key=mapped["extra_key"],
            )

        for service in outcome.services:
            self.services.record(
                scan_id=context.scan_id,
                url=target.url,
                host=target.domain,
                status_code=0,
                title="",
                server="",
                services=[service],
                headers={},
                cookies=[],
                favicon_hash=0,
                tls={},
                detector=str(service.get("source") or "worker"),
            )

    @staticmethod
    def _is_in_scope(context: ScanContext, scope: ScopeEnforcer, url: str) -> bool:
        """Return ``True`` when the scan scope covers the target."""
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        return scope.policy.matches_host(host)

    def _persist_scanner_result(self, context: ScanContext, name: str, result: ScanResult) -> None:
        """Turn adapter output into findings and assets."""
        self._emit(
            context.scan_id,
            "scanner.completed",
            {
                "scanner": name,
                "ok": result.ok,
                "error": result.error,
                "items": len(result.items),
                "duration_ms": result.duration_ms,
            },
        )
        if not result.ok and result.error:
            self._emit(context.scan_id, "scanner.error", {"scanner": name, "error": result.error})

        for item in result.items:
            if not isinstance(item, dict):
                continue

            # The service inventory is stored per URL, not as findings.
            if result.kind == "service":
                self.services.record(
                    scan_id=context.scan_id,
                    url=str(item.get("url", "")),
                    host=str(item.get("host", "")),
                    status_code=int(item.get("status_code", 0)),
                    title=str(item.get("title", "")),
                    server=str(item.get("server", "")),
                    services=list(item.get("services", [])),
                    headers=dict(item.get("headers", {})),
                    cookies=list(item.get("cookies", [])),
                    favicon_hash=int(item.get("favicon_hash", 0)),
                    tls=dict(item.get("tls", {})),
                    detector=name,
                )
                self._emit(
                    context.scan_id,
                    "services.identified",
                    {
                        "scanner": name,
                        "url": item.get("url", ""),
                        "services": [
                            {
                                "name": service.get("name"),
                                "version": service.get("version"),
                                "category": service.get("category"),
                                "confidence": service.get("confidence"),
                                "source": service.get("source"),
                            }
                            for service in item.get("services", [])
                        ],
                    },
                )
                continue

            findings = item.get("findings")
            if isinstance(findings, list):
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    self.findings.upsert(
                        scan_id=context.scan_id,
                        title=finding.get("title", "scanner finding"),
                        summary=finding.get("summary", ""),
                        vuln_class=finding.get("vuln_class", "unknown"),
                        severity=finding.get("severity", "info"),
                        host=finding.get("host", ""),
                        path=finding.get("path", ""),
                        parameter=finding.get("parameter", ""),
                        cwe=finding.get("cwe", ""),
                        confidence=float(finding.get("confidence", 0.5)),
                        detected_by=[name],
                        detection_source=name,
                        affected_url=finding.get("affected_url", ""),
                        evidence=finding.get("evidence", []) or [],
                        remediation=finding.get("remediation", ""),
                        extra_key=finding.get("extra_key", ""),
                    )

    async def _run_agent_tasks(
        self,
        context: ScanContext,
        tasks: Sequence[AgentTask],
        scope: ScopeEnforcer,
        state: _StageState,
        spent: int = 0,
    ) -> int:
        """Execute the agent tasks of one stage.

        A task that already succeeded is not run again: its work is
        done, its findings are persisted and its result is kept.  The
        candidates of the stage are the findings that are already
        stored, so a resumed stage continues with the work that is
        left.

        Returns the tokens the scan has spent so far.
        """
        roles = builtin_roles()
        pending = {task.task_id: task for task in tasks}
        completed = state.completed
        failed = state.failed
        #: The tokens the finished roles have spent.
        tokens_spent = spent
        collaboration = CollaborationState()
        candidates: list[CandidateFinding] = self._candidates_from_findings(context.scan_id)
        #: The tasks of this stage.  A dependency that belongs to an
        #: earlier stage is satisfied already: the stage that ran it is
        #: over.
        stage_ids = set(pending)

        while pending:
            if self._is_cancelled(context.scan_id):
                return tokens_spent

            ready = [
                task
                for task in pending.values()
                if all(dep in completed or dep in failed or dep not in stage_ids for dep in task.depends_on)
            ]
            if not ready:
                # Every remaining task depends on something that failed:
                # mark them blocked rather than looping forever.
                for task in pending.values():
                    self.tasks.set_status(
                        task.task_id, "blocked", error="a dependency failed or was cancelled"
                    )
                    self._emit(
                        context.scan_id,
                        "task.blocked",
                        {"task_id": task.task_id, "role": task.role},
                    )
                break

            ready.sort(key=lambda t: (-len(t.depends_on), t.role))
            batch = ready[: max(1, context.profile.max_concurrency)]

            # The scan has a token budget of its own.  It was never
            # enforced, so a scan could spend whatever the roles wanted;
            # when it is spent, the roles that have not started are
            # stopped rather than started and cut off.
            if tokens_spent >= self.settings.agent_max_tokens_per_scan > 0:
                for task in list(pending.values()):
                    self.tasks.set_status(
                        task.task_id,
                        "blocked",
                        error=(
                            "the scan ran out of its token budget "
                            f"({tokens_spent} of {self.settings.agent_max_tokens_per_scan})"
                        ),
                    )
                    pending.pop(task.task_id, None)
                break

            # A task that already succeeded is not run again: the work it
            # did is done and its findings are already persisted.
            todo: list[AgentTask] = []
            for task in batch:
                pending.pop(task.task_id, None)
                stored = self.tasks.get(task.task_id)
                if stored is not None and stored.get("status") == "succeeded":
                    completed.add(task.task_id)
                    self._emit(
                        context.scan_id,
                        "task.skipped",
                        {
                            "task_id": task.task_id,
                            "role": task.role,
                            "reason": "the task already succeeded",
                        },
                    )
                    continue
                todo.append(task)
            if not todo:
                continue

            results = await asyncio.gather(
                *(
                    self._run_agent_task(context, task, scope, roles, collaboration, candidates)
                    for task in todo
                ),
                return_exceptions=True,
            )

            for task, result in zip(todo, results, strict=False):
                if isinstance(result, BaseException):
                    failed.add(task.task_id)
                    log.error(
                        "the agent task %s failed: %s",
                        task.task_id,
                        result,
                        exc_info=(type(result), result, result.__traceback__),
                    )
                    self.tasks.set_status(task.task_id, "failed", error=str(result))
                    continue

                run = result
                tokens_spent += int(getattr(run, "tokens_used", 0) or 0)
                # The task status must reflect what the agent actually
                # achieved: a run that failed or ran out of budget is not a
                # successful task.
                if run.status == "succeeded":
                    self.tasks.set_status(task.task_id, "succeeded", result=run.to_dict())
                    completed.add(task.task_id)
                else:
                    failed.add(task.task_id)
                    self.tasks.set_status(
                        task.task_id,
                        "failed",
                        error=run.error or f"the agent run ended with status '{run.status}'",
                        result=run.to_dict(),
                    )
                self._emit(
                    context.scan_id,
                    "agent.completed",
                    {
                        "task_id": task.task_id,
                        "role": run.role,
                        "status": run.status,
                        "conclusion": run.conclusion,
                        "tokens_used": run.tokens_used,
                        "tool_calls_used": run.tool_calls_used,
                        "duration_seconds": run.duration_seconds,
                    },
                )
                for finding in run.findings:
                    try:
                        candidates.append(CandidateFinding.from_dict(finding))
                    except (TypeError, ValueError):
                        continue

        # --- verification ------------------------------------------------
        # The verification role is part of the plan and runs with the
        # candidate findings as its input, so its verdicts can be applied
        # to them.

        self._emit(
            context.scan_id,
            "collaboration.summary",
            collaboration.summary(),
        )
        return tokens_spent

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------
    @staticmethod
    def _stages_from(phase: str) -> list[str]:
        """The stages of a scan that still have to run.

        The recorded phase is the phase the scan is *about to run*, so
        the stages before it are done.
        """
        start = SCAN_PHASES.index(phase) if phase in SCAN_PHASES else 0
        return [stage for stage in SCAN_PHASES[:-1] if SCAN_PHASES.index(stage) >= start]

    @staticmethod
    def _phase_after(stage: str) -> str:
        """The phase a scan is in after the given stage."""
        return {
            "workers": "agents",
            "agents": "verifying",
            "verifying": "reporting",
            "reporting": "completed",
        }.get(stage, "completed")

    @staticmethod
    def _tasks_for_stage(plan: Sequence[AgentTask], stage: str) -> list[AgentTask]:
        """The tasks of the plan that belong to a stage."""
        roles = {
            "agents": HYPOTHESIS_ROLES,
            "verifying": VERIFICATION_ROLES,
            "reporting": REPORTING_ROLES,
        }.get(stage, ())
        return [task for task in plan if task.role in roles]

    def _candidates_from_findings(self, scan_id: str) -> list[CandidateFinding]:
        """The findings of a scan, as the candidates of the stage.

        A resumed stage finds its candidates from the findings that are
        already stored: the work of the earlier stages is not done
        again, but its result is still there.
        """
        try:
            rows = self.findings.list(scan_id, limit=2000)
        except Exception:  # pragma: no cover - the database may be down
            log.exception("failed to list the findings of the scan %s", scan_id)
            return []
        candidates: list[CandidateFinding] = []
        for row in rows:
            vuln_class = str(row.get("vuln_class", "") or "")
            if not vuln_class:
                continue
            candidates.append(
                CandidateFinding(
                    title=str(row.get("title", "")),
                    summary=str(row.get("summary", "")),
                    vuln_class=vuln_class,
                    severity=str(row.get("severity", "info")),
                    host=str(row.get("host", "")),
                    path=str(row.get("path", "")),
                    parameter=str(row.get("parameter", "")),
                    confidence=_confidence_of(row.get("confidence")),
                    evidence=list(row.get("evidence", []) or []),
                )
            )
        return candidates

    def _write_coverage(self, context: ScanContext) -> None:
        """Record what the scan covered.

        The summary says how much of the target the scan reached, so
        that a report can say what was looked at and what was not.
        """
        try:
            rows = self.services.list_for_scan(context.scan_id)
        except Exception:  # pragma: no cover - the database may be down
            log.exception("failed to list the services of the scan %s", context.scan_id)
            return
        hosts = {str(row.get("host", "")) for row in rows if row.get("host")}
        tasks = self.tasks.list_for_scan(context.scan_id)
        self.scans.set_coverage(
            context.scan_id,
            {
                "hosts": len(hosts),
                "urls": len(rows),
                "worker_tasks_succeeded": sum(
                    1 for task in tasks if task.get("kind") == "worker" and task.get("status") == "succeeded"
                ),
                "worker_tasks_failed": sum(
                    1 for task in tasks if task.get("kind") == "worker" and task.get("status") == "failed"
                ),
                "authenticated": False,
            },
        )

    def _pending_verdicts(self, scan_id: str) -> list[dict[str, Any]]:
        """The findings of a scan that wait for a verdict.

        Each one is given with the evidence that supports it, so that the
        judge can reach a verdict without looking for the evidence
        anywhere else.
        """
        try:
            findings = self.findings.list(
                scan_id,
                verification_status=("unverified",),
                limit=200,
            )
        except Exception:  # pragma: no cover - the judge must still run
            log.exception("failed to list the findings that wait for a verdict")
            return []
        pending: list[dict[str, Any]] = []
        for finding in findings:
            excerpt = ""
            for entry in finding.get("evidence") or []:
                if isinstance(entry, dict) and entry.get("excerpt"):
                    excerpt = str(entry["excerpt"])[:200]
                    break
            pending.append(
                {
                    "finding_id": finding.get("finding_id", ""),
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", ""),
                    "detected_by": finding.get("detection_source", ""),
                    "evidence": excerpt,
                }
            )
        return pending

    async def _run_agent_task(
        self,
        context: ScanContext,
        task: AgentTask,
        scope: ScopeEnforcer,
        roles: dict[str, AgentRole],
        collaboration: CollaborationState,
        candidates: Sequence[CandidateFinding] = (),
    ) -> Any:
        role = roles.get(task.role)
        if role is None:
            raise RuntimeError(f"unknown agent role '{task.role}'")

        provider = self._make_provider(context)
        if provider is None:
            raise RuntimeError("no model provider is configured; agents cannot run until one is set up")

        workspace = self._workspace_for(context, task.role)
        tool_context = self._make_tool_context(context, task, scope, workspace)
        budget = self._budget_for_task(context, role, task)

        runtime = AgentRuntime(
            provider=provider,
            gateway=self.gateway,
            role=role,
            config=AgentRuntimeConfig(
                max_rounds=budget.max_rounds,
                max_tool_calls=budget.max_tool_calls,
                max_tokens=budget.max_tokens,
                max_wall_clock_seconds=budget.max_wall_clock_seconds,
            ),
            on_message=lambda message: self._persist_message(context, message, collaboration),
            on_tool_call=self._audit_tool_call,
        )

        self.tasks.set_status(task.task_id, "running")
        self.agents.upsert(
            scan_id=context.scan_id,
            role=task.role,
            status="running",
            task_id=task.task_id,
            conclusion=task.title,
        )

        run = await runtime.run(
            scan_id=context.scan_id,
            task_id=task.task_id,
            objective=task.objective,
            target=task.target,
            context=tool_context,
            input_payload={
                "scope": {
                    "authorized_hosts": context.authorized_hosts,
                    "excluded_paths": context.excluded_paths,
                },
                "targets": context.targets,
                "safe_mode": context.safe_mode,
                "test_accounts": [
                    {"username": (account.get("username", "") if isinstance(account, dict) else str(account))}
                    for account in context.test_accounts
                ],
                "artifacts": context.artifacts[:20],
                # The verification role judges the candidates, so it needs
                # them.  It re-checks each one it is given and re-checking
                # costs a request per candidate, so it is given the most
                # severe ones: judging all of them would leave it no
                # budget to record the verdicts.
                "candidate_findings": (
                    [c.to_dict() for c in _by_severity(candidates)[:VERIFIER_CANDIDATE_LIMIT]]
                    if task.role in VERIFICATION_ROLES
                    else []
                ),
                # The judge is given the findings that wait for a verdict,
                # with their evidence.  Without the work list it goes
                # looking for it - in the event log, one call at a time -
                # and reads its budget away without recording a verdict
                # at all.
                "pending_verdicts": (
                    self._pending_verdicts(context.scan_id) if task.role in REPORTING_ROLES else []
                ),
            },
        )

        self.agents.upsert(
            scan_id=context.scan_id,
            role=task.role,
            status="idle" if run.status == "succeeded" else "error",
            task_id=task.task_id,
            # The conclusion is the summary of what the role did, so it is
            # kept whole: a truncated one says nothing.
            conclusion=run.conclusion,
            error=run.error,
            detail={
                "tokens_used": run.tokens_used,
                "tool_calls_used": run.tool_calls_used,
                "rounds": run.rounds,
                "duration_seconds": run.duration_seconds,
            },
        )

        if task.role in VERIFICATION_ROLES:
            self._apply_verdicts(context, candidates, run.findings)

        # Persist any findings the agent proposed.
        for finding in parse_findings(run.findings, role=task.role, task_id=task.task_id):
            self.findings.upsert(
                scan_id=context.scan_id,
                title=finding.title,
                summary=finding.summary,
                vuln_class=finding.vuln_class,
                severity=finding.severity,
                host=finding.host,
                path=finding.path,
                parameter=finding.parameter,
                cwe=finding.cwe,
                confidence=finding.confidence,
                detected_by=[task.role],
                detection_source="agent",
                affected_url=finding.affected_url,
                evidence=finding.evidence,
                remediation=finding.remediation,
                extra_key=finding.extra_key,
            )
        return run

    def _apply_verdicts(
        self,
        context: ScanContext,
        candidates: Sequence[CandidateFinding],
        verdicts: Sequence[Any],
    ) -> None:
        """Record what the verifier decided about each candidate finding.

        The verifier answers with one entry per finding it looked at.  The
        entry carries a title and a verdict, and the finding is matched on
        the title; without a match the order is used, because the verifier
        answers in the order it was given the candidates.
        """
        if not verdicts:
            return
        by_title: dict[str, CandidateFinding] = {}
        for candidate in candidates:
            by_title.setdefault(candidate.title.strip().lower(), candidate)

        for index, verdict in enumerate(verdicts):
            if not isinstance(verdict, dict):
                continue
            title = str(verdict.get("title") or "").strip().lower()
            candidate = by_title.get(title)
            if candidate is None and index < len(candidates):
                candidate = candidates[index]
            if candidate is None:
                continue

            status = str(verdict.get("verification_status") or verdict.get("verdict") or "").strip().lower()
            if status not in {"confirmed", "likely", "rejected", "unverified", "inconclusive"}:
                status = "confirmed" if verdict.get("confirmed") else "unverified"

            finding = self.findings.find_by_fingerprint(
                scan_id=context.scan_id,
                fingerprint=compute_fingerprint(
                    vuln_class=candidate.vuln_class,
                    host=candidate.host,
                    path=candidate.path,
                    parameter=candidate.parameter,
                    extra=candidate.extra_key,
                ),
            )
            if finding is None:
                continue
            self.findings.set_verification(
                finding["finding_id"],
                status=status,
                notes=str(verdict.get("verification_notes") or verdict.get("rationale") or ""),
                verified_by="verifier",
                severity=str(verdict.get("severity") or ""),
                false_positive_reason=str(verdict.get("false_positive_reason") or ""),
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _make_provider(self, context: ScanContext) -> Optional[Provider]:
        if self.provider_factory is None:
            return None
        try:
            return self.provider_factory(context.options.get("provider", ""))
        except Exception:
            log.exception("could not build the model provider")
            return None

    def _workspace_for(self, context: ScanContext, role: str) -> Path:
        root = Path(context.workspace_root or self.settings.agent_workspace_root)
        path = root / context.scan_id / role
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _make_tool_context(
        self, context: ScanContext, task: AgentTask, scope: ScopeEnforcer, workspace: Path
    ) -> ToolContext:
        role = builtin_roles().get(task.role)
        permissions = role.permissions if role else None
        allowed = set(role.tools) if role and role.tools else set()
        return ToolContext(
            scan_id=context.scan_id,
            task_id=task.task_id,
            role=task.role,
            workspace=workspace,
            permissions=permissions or ToolPermissions(),
            scope=scope,
            allowed_tools=allowed,
            metadata={
                "findings_repository": self.findings,
                "events_repository": self.events,
                "scanner_registry": self.scanner_registry,
                # What the scanner workers produced, so that an agent can
                # pick up what the crawlers found.
                "worker_output_repository": self.worker_output,
                "assets": {},
            },
        )

    def _persist_message(
        self, context: ScanContext, message: AgentMessage, collaboration: CollaborationState
    ) -> None:
        collaboration.note_message(message)
        message.scan_id = context.scan_id
        try:
            self.messages.append(message.to_dict())
        except Exception:  # pragma: no cover
            log.exception("failed to persist an agent message")
        self._emit(
            context.scan_id,
            "agent.message",
            {
                "task_id": message.task_id,
                "sender_role": message.sender_role,
                "kind": message.kind.value,
                "target": message.target,
                "hypothesis": message.hypothesis[:800],
                "confidence": message.confidence.value,
                "disposition": message.disposition.value,
                "evidence_count": len(message.evidence),
            },
        )
