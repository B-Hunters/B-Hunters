"""The scan orchestrator.

The orchestrator owns the scan lifecycle:

1. Build a plan from the authorised scope and the scan profile.
2. Dispatch the deterministic scanner work (the existing B-Hunters Karton
   workers) and the agent work.
3. Run agent tasks respecting their dependencies, with bounded concurrency.
4. Feed candidate findings to the independent verifier, then to the
   adjudicator.
5. Watch for stalls, budget exhaustion and cancellation, and stop cleanly.

The orchestrator never contacts a target itself - it only dispatches work
and records what happened.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
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
    TaskRepository,
    ToolCallRepository,
)
from ..scanners.base import ScanRequest, ScanResult
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

#: Roles that verify findings.
VERIFICATION_ROLES = ("verifier",)

#: Roles that report.
REPORTING_ROLES = ("adjudicator",)


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
            agent_roles=list(HYPOTHESIS_ROLES) + list(VERIFICATION_ROLES) + list(REPORTING_ROLES),
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
        self.provider_factory = provider_factory
        self.tool_registry = tool_registry or ToolRegistry()
        self.scanner_registry = scanner_registry or AdapterRegistry()
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
                    max_tokens=int((role.budget or {}).get("max_tokens", 120000)),
                    max_tool_calls=int((role.budget or {}).get("max_tool_calls", 40)),
                    max_rounds=int((role.budget or {}).get("max_rounds", 6)),
                    max_wall_clock_seconds=int((role.budget or {}).get("max_wall_clock_seconds", 900)),
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
        """Execute the scan."""
        started = time.monotonic()
        self.scans.set_status(context.scan_id, "running")
        self._emit(context.scan_id, "scan.started", {"profile": context.profile.name})

        scope = ScopeEnforcer(context.scope_policy())
        plan = self.build_plan(context)

        # Persist the plan as tasks, keeping the plan's task identifiers so
        # that the dependency graph, the agent runs and the persisted task
        # records all refer to the same task.
        for agent_task in plan:
            self.tasks.create(
                scan_id=context.scan_id,
                task_id=agent_task.task_id,
                title=agent_task.title,
                kind="agent",
                agent_role=agent_task.role,
                depends_on=agent_task.depends_on,
                budget=agent_task.budget.to_dict(),
                input={"objective": agent_task.objective, "target": agent_task.target},
            )

        try:
            await self._wait_while_paused(context.scan_id)
            await self._dispatch_scanners(context, scope)
            await self._run_agent_tasks(context, plan, scope)
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
        plan: Sequence[AgentTask],
        scope: ScopeEnforcer,
    ) -> None:
        """Execute the agent task graph with dependency ordering."""
        roles = builtin_roles()
        pending = {task.task_id: task for task in plan}
        completed: set[str] = set()
        failed: set[str] = set()
        collaboration = CollaborationState()
        candidates: list[CandidateFinding] = []

        while pending:
            if self._is_cancelled(context.scan_id):
                return

            ready = [
                task
                for task in pending.values()
                if all(dep in completed or dep in failed for dep in task.depends_on)
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

            results = await asyncio.gather(
                *(self._run_agent_task(context, task, scope, roles, collaboration) for task in batch),
                return_exceptions=True,
            )

            for task, result in zip(batch, results, strict=False):
                pending.pop(task.task_id, None)
                if isinstance(result, BaseException):
                    failed.add(task.task_id)
                    self.tasks.set_status(task.task_id, "failed", error=str(result))
                    continue

                run = result
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
        if not self._is_cancelled(context.scan_id) and candidates:
            await self._run_verification(context, candidates, scope, roles, collaboration)

        self._emit(
            context.scan_id,
            "collaboration.summary",
            collaboration.summary(),
        )

    async def _run_agent_task(
        self,
        context: ScanContext,
        task: AgentTask,
        scope: ScopeEnforcer,
        roles: dict[str, AgentRole],
        collaboration: CollaborationState,
    ) -> Any:
        role = roles.get(task.role)
        if role is None:
            raise RuntimeError(f"unknown agent role '{task.role}'")

        provider = self._make_provider(context)
        if provider is None:
            raise RuntimeError("no model provider is configured; agents cannot run until one is set up")

        workspace = self._workspace_for(context, task.role)
        tool_context = self._make_tool_context(context, task, scope, workspace)

        runtime = AgentRuntime(
            provider=provider,
            gateway=self.gateway,
            role=role,
            config=AgentRuntimeConfig(
                max_rounds=task.budget.max_rounds,
                max_tool_calls=task.budget.max_tool_calls,
                max_tokens=task.budget.max_tokens,
                max_wall_clock_seconds=task.budget.max_wall_clock_seconds,
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
                    {"username": account.get("username", "")} for account in context.test_accounts
                ],
                "artifacts": context.artifacts[:20],
            },
        )

        self.agents.upsert(
            scan_id=context.scan_id,
            role=task.role,
            status="idle" if run.status == "succeeded" else "error",
            task_id=task.task_id,
            conclusion=run.conclusion[:500],
            detail={
                "tokens_used": run.tokens_used,
                "tool_calls_used": run.tool_calls_used,
                "rounds": run.rounds,
                "duration_seconds": run.duration_seconds,
            },
        )

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

    async def _run_verification(
        self,
        context: ScanContext,
        candidates: Sequence[CandidateFinding],
        scope: ScopeEnforcer,
        roles: dict[str, AgentRole],
        collaboration: CollaborationState,
    ) -> None:
        """Have the verifier re-evaluate the candidate findings."""
        role = roles.get("verifier")
        if role is None:
            return
        provider = self._make_provider(context)
        if provider is None:
            return

        workspace = self._workspace_for(context, "verifier")
        task = AgentTask(
            task_id=f"{context.scan_id}:verifier",
            scan_id=context.scan_id,
            role="verifier",
            title=role.title,
            objective=role.objective,
        )
        tool_context = self._make_tool_context(context, task, scope, workspace)

        runtime = AgentRuntime(
            provider=provider,
            gateway=self.gateway,
            role=role,
            config=AgentRuntimeConfig(
                max_rounds=int((role.budget or {}).get("max_rounds", 8)),
                max_tool_calls=int((role.budget or {}).get("max_tool_calls", 60)),
                max_tokens=int((role.budget or {}).get("max_tokens", 180000)),
                max_wall_clock_seconds=int((role.budget or {}).get("max_wall_clock_seconds", 1200)),
            ),
            on_message=lambda message: self._persist_message(context, message, collaboration),
            on_tool_call=self._audit_tool_call,
        )

        self.agents.upsert(scan_id=context.scan_id, role="verifier", status="running", task_id=task.task_id)
        run = await runtime.run(
            scan_id=context.scan_id,
            task_id=task.task_id,
            objective=(
                "Independently verify each candidate finding below. Reproduce what you can, "
                "reject what does not hold up, and mark anything you could not confirm as "
                "unverified or inconclusive."
            ),
            target=",".join(context.authorized_hosts),
            context=tool_context,
            input_payload={
                "candidate_findings": [c.to_dict() for c in candidates][:50],
            },
        )
        self.agents.upsert(
            scan_id=context.scan_id,
            role="verifier",
            status="idle",
            conclusion=run.conclusion[:500],
        )
        self._emit(
            context.scan_id,
            "agent.completed",
            {
                "task_id": task.task_id,
                "role": "verifier",
                "status": run.status,
                "conclusion": run.conclusion,
            },
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
