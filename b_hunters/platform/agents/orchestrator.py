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
from urllib.parse import urljoin, urlsplit

from ..assets import classify, is_external, normalise_url
from ..db.assets import AssetRepository, WorkerRunRepository
from ..db.callbacks import CallbackRepository
from ..db.client import Database
from ..db.notifications import NOTIFICATION_EVENTS, NotificationRepository
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
from ..errors import ErrorLedger, ledger_from_records
from ..scanners.base import ScanRequest, ScanResult
from ..scanners.karton_bridge import (
    KartonWorkerBridge,
    WorkerResults,
    finding_for_platform,
)
from ..scanners.registry import AdapterRegistry
from ..security.scope import ScopeEnforcer, ScopePolicy, build_policy_from_scan
from ..security.secrets import SecretBox
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

#: The order the hypothesis roles start in.
#:
#: A scan has a budget and the roles compete for it.  When twelve roles
#: are planned at once, the budget is gone before the last of them
#: starts, and the ones that never ran are recorded as cut off.  The
#: order decides which work happens: the surface first, then the
#: weaknesses of that surface.
ROLE_PRIORITY = (
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

#: The roles that judge the findings rather than look for them.  They
#: are the ones that give a finding its verdict, and a finding without
#: a verdict is a guess.
JUDGING_ROLES = VERIFICATION_ROLES + REPORTING_ROLES

#: The adapter that crawls the target.  It runs in the second native
#: wave: it seeds itself from the URLs the fingerprinters recorded.
ASSET_CRAWL_ADAPTER = "asset_crawl"

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


def _scope_of(url: str, authorized_hosts: Sequence[str]) -> str:
    """Whether a URL belongs to the target or to another host."""
    return "external" if is_external(url, authorized_hosts) else "first_party"


def _resolve_against_target(value: str, primary_target: str) -> str:
    """Resolve a reference the workers found against the scan's target."""
    text = (value or "").strip()
    if not text or not primary_target:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    if parts.scheme:
        # Only an HTTP URL is an asset.  A mail address or a script is not.
        if parts.scheme not in ("http", "https"):
            return ""
        return normalise_url(text)
    if not primary_target.endswith("/"):
        primary_target = f"{primary_target}/"
    try:
        return normalise_url(urljoin(primary_target, text))
    except ValueError:
        return ""


def _asset_row_of_worker_item(
    item: dict[str, Any],
    primary_target: str,
    authorized_hosts: Sequence[str],
) -> dict[str, Any] | None:
    """The asset one item of the worker output is, if it is one at all.

    A worker writes a list of URLs or a list of paths as one entry.  The
    URLs are URLs; the paths are paths of the target and are resolved
    against it.  Everything else - a secret, a port, a finding - is not an
    asset.
    """
    kind = str(item.get("kind", ""))
    value = str(item.get("value", "")).strip()
    worker = str(item.get("worker", ""))
    if kind not in ("url", "item", "path") or not value:
        return None

    url = _resolve_against_target(value, primary_target)
    if not url:
        return None

    if kind == "path":
        # A path is never fetched, so it has no status.
        return {
            "url": url,
            "kind": classify(url=url),
            "scope": _scope_of(url, authorized_hosts),
            "status_code": 0,
            "source": worker,
        }

    # The JavaScript scanner writes the scripts it read; they are
    # JavaScript whatever their name says.
    asset_kind = "js" if "jsscanner" in worker.lower() else classify(url=url)
    return {
        "url": url,
        "kind": asset_kind,
        "scope": _scope_of(url, authorized_hosts),
        "status_code": 0,
        "source": worker,
    }


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
                "asset_crawl",
                "browser_crawl",
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
            if key in known and value not in (None, ""):
                setattr(profile, key, value)
        return profile

    def to_dict(self) -> dict[str, Any]:
        """The profile as a mapping.

        The scan document holds the profile so that the runner can rebuild
        the scan from it.  A profile that is not stored is not restored:
        the scanner list, the agent roles, the concurrency and the limits
        the operator chose would all be lost, and every scan would run the
        default plan whatever the scan form said.

        A stored list is authoritative even when it is empty: a scan that
        names no agent roles means exactly that, and falling back to the
        default list would run eleven roles the operator did not ask for.
        """
        return {
            "name": self.name,
            "description": self.description,
            "agent_roles": list(self.agent_roles),
            "scanners": list(self.scanners),
            "max_concurrency": self.max_concurrency,
            "max_duration_seconds": self.max_duration_seconds,
            "max_requests_per_second": self.max_requests_per_second,
            "request_timeout": self.request_timeout,
            "safe_mode": self.safe_mode,
            "allow_state_changing": self.allow_state_changing,
        }


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
        #: The key that decrypts the stored credentials.  The API never
        #: decrypts; the runner does, when a scan names an identity.
        self._secret_box = SecretBox.from_settings(self.settings)
        self.scans = ScanRepository(database)
        self.events = EventRepository(database)
        self.tasks = TaskRepository(database)
        self.agents = AgentStateRepository(database)
        self.messages = MessageRepository(database)
        self.findings = FindingRepository(database)
        self.tool_calls = ToolCallRepository(database)
        self.services = ServiceRepository(database)
        self.worker_output = WorkerOutputRepository(database)
        #: The URLs the scan saw.  Every tool that found one writes into
        #: the same row.
        self.assets = AssetRepository(database)
        #: What every worker did in this scan.
        self.worker_runs = WorkerRunRepository(database)
        #: The webhooks the operator asked to be told about.
        self.notifications = NotificationRepository(database)
        #: The out-of-band callback tokens and the hits they received.
        self.callbacks = CallbackRepository(database)
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
        #: The browser the roles of a scan drive.  It is opened once
        #: for the scan and closed when the scan ends.
        self._browser: Any = None
        #: The ledger of the failures of every scan this orchestrator
        #: ran.  It is what decides whether a scan can be called clean.
        self._ledgers: dict[str, ErrorLedger] = {}
        #: The scans whose ledger already carries the failures of an
        #: earlier run, so that a resumed scan is not judged twice.
        self._seeded: set[str] = set()

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------
    def _emit(self, scan_id: str, kind: str, payload: dict[str, Any], actor: str = "") -> None:
        try:
            self.events.append(scan_id=scan_id, kind=kind, payload=payload, actor=actor)
        except Exception:  # pragma: no cover - persistence must not break a scan
            log.exception("failed to persist a scan event")
        self._notify(scan_id, kind, payload)

    def _notify(self, scan_id: str, kind: str, payload: dict[str, Any]) -> None:
        """Tell the webhooks about an event.

        The delivery happens in the background: a webhook that is slow
        must not hold a scan up, and a webhook that is down must not
        break one.
        """
        if kind not in NOTIFICATION_EVENTS:
            return
        body = {"scan_id": scan_id, **payload}
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # pragma: no cover - not in an event loop
            return
        loop.create_task(self._deliver_notifications(kind, body))

    async def _deliver_notifications(self, kind: str, body: dict[str, Any]) -> None:
        """Deliver an event to every notification that wants it."""
        try:
            await asyncio.to_thread(self.notifications.notify, kind, body)
        except Exception:  # pragma: no cover - a webhook that is down
            log.exception("could not deliver the notification for %s", kind)

    def _audit_tool_call(self, record: dict[str, Any]) -> None:
        """Record one tool call.

        A write that fails is reported: a tool that could not record
        itself is visible rather than absent.  The event says which
        tool it was and which task it belonged to.
        """
        scan_id = str(record.get("scan_id", "") or "")
        if str(record.get("status", "")) == "error":
            self._note_failure(scan_id, "tool_call", str(record.get("error", "") or ""))
        stored = False
        try:
            stored = self.tool_calls.record(record)
        except Exception:  # pragma: no cover
            log.exception("failed to persist a tool call record")
        if stored:
            return
        self._emit(
            scan_id,
            "tool.record_failed",
            {
                "tool": str(record.get("tool", "")),
                "task_id": str(record.get("task_id", "")),
                "role": str(record.get("agent_role", "")),
                "error": "the tool call could not be stored",
            },
        )
        self._note_failure(scan_id, "tool_call", "the tool call could not be stored")

    def _note_tool_call(self, record: dict[str, Any]) -> None:
        """Note a tool call the agent runtime made.

        The gateway has already recorded the call and what it
        returned - with the redaction and with the full output.  The
        runtime reports the same call a second time, and storing it
        twice would double every tool call of the transcript and every
        failure of the ledger.
        """

    # ------------------------------------------------------------------
    # The error ledger
    # ------------------------------------------------------------------
    def _note_failure(self, scan_id: str, source: str, detail: str) -> None:
        """Record one failure of a scan in its ledger."""
        if not scan_id:
            return
        self._ledger(scan_id).add(source, detail)

    def _ledger(self, scan_id: str) -> ErrorLedger:
        """The ledger of the failures of a scan."""
        ledger = self._ledgers.get(scan_id)
        if ledger is None:
            ledger = ErrorLedger()
            self._ledgers[scan_id] = ledger
        return ledger

    def _seed_ledger(self, scan_id: str) -> ErrorLedger:
        """The ledger of a scan, with the failures it recorded before.

        A scan that is picked up again keeps the failures of its first
        run: they are read back from the records, so that the verdict
        of the resumed scan covers the whole of it.
        """
        ledger = self._ledger(scan_id)
        if scan_id in self._seeded:
            return ledger
        self._seeded.add(scan_id)
        for entry in self._stored_ledger(scan_id).entries():
            ledger.add(entry["source"], entry["detail"], str(entry.get("status", "") or ""))
        return ledger

    def _stored_ledger(self, scan_id: str) -> ErrorLedger:
        """The ledger of the failures the records of a scan hold."""
        return ledger_from_records(
            tool_calls=self.tool_calls.list_for_scan(scan_id, limit=5000),
            events=self.events.list_after(scan_id, 0, limit=2000),
            tasks=self.tasks.list_for_scan(scan_id),
        )

    def _write_integrity(self, scan_id: str) -> dict[str, Any]:
        """Write the verdict of a scan onto its record.

        The verdict is an artefact of the scan: it says whether every
        failure the scan had a name for.  It is written when the scan
        ends and can be read again afterwards.
        """
        verdict = self._seed_ledger(scan_id).verdict()
        try:
            self.scans.update(scan_id, {"integrity": verdict})
        except Exception:  # pragma: no cover - the database may be down
            log.exception("failed to write the integrity of the scan %s", scan_id)
        return verdict

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
        # The ledger of the scan starts with the failures it recorded
        # before: a scan that is picked up again is judged as a whole.
        self._seed_ledger(context.scan_id)

        # The scan has a deadline.  It is stored on the scan, so a scan
        # that is picked up again knows how much of its time is left,
        # and it is enforced: a role that did not start because the
        # deadline passed is recorded as cut off, never as successful.
        deadline = self._scan_deadline(context)

        scope = ScopeEnforcer(context.scope_policy())
        plan = self.build_plan(context)

        # The browser is opened once for the scan and shared by the
        # roles that use it: opening a Chromium per task would spend
        # the budget of the scan on browsers.
        await self._open_browser(context)

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
                    self._snapshot_worker_connections(context)
                    await self._dispatch_workers(context, scope)
                    self._record_worker_outcomes(context)
                    self._write_coverage(context)
                    self.scans.set_phase(context.scan_id, self._phase_after(stage))
                    continue
                if agent_scope is None:
                    agent_scope = ScopeEnforcer(
                        self._phase_policy(context, 1 - self.settings.worker_phase_share)
                    )
                stage_tasks = self._tasks_for_stage(plan, stage)
                if stage == "agents":
                    stage_tasks = self._admit_roles(context, stage_tasks)
                stage_deadline = deadline
                if stage == "agents" and deadline:
                    # The judging roles run after the hypothesis roles,
                    # and they are what turn a finding into a verdict.
                    # The hypothesis roles therefore stop short of the
                    # deadline, so that the roles that judge have time
                    # to judge.
                    reserve = self._judging_reserve(context, deadline)
                    stage_deadline = max(deadline - reserve, deadline * 0.5)
                tokens_spent = await self._run_agent_tasks(
                    context,
                    stage_tasks,
                    agent_scope,
                    state,
                    spent=tokens_spent,
                    deadline=stage_deadline,
                )
                self.scans.set_phase(context.scan_id, self._phase_after(stage))
        except asyncio.CancelledError:
            await self._close_browser()
            self._write_integrity(context.scan_id)
            self.scans.set_status(context.scan_id, "cancelled")
            self._emit(context.scan_id, "scan.cancelled", {"at": time.time()})
            raise
        except Exception as exc:
            log.exception("scan %s failed", context.scan_id)
            await self._close_browser()
            self._note_failure(context.scan_id, "scan", str(exc))
            self._write_integrity(context.scan_id)
            self.scans.set_status(context.scan_id, "failed", error=str(exc))
            self._emit(context.scan_id, "scan.failed", {"error": str(exc)})
            return {"status": "failed", "error": str(exc)}

        await self._close_browser()

        if self._is_cancelled(context.scan_id):
            self._write_integrity(context.scan_id)
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
        # The verdict of the scan: every failure it had, and whether
        # every one of them had a name.
        self._write_integrity(context.scan_id)
        self.scans.set_status(context.scan_id, "completed")
        counts = self.findings.severity_counts(context.scan_id)
        self._emit(
            context.scan_id,
            "scan.completed",
            {
                "duration_seconds": duration,
                "findings": self.findings.count(context.scan_id),
                "severity_counts": counts,
            },
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

        # The crawler seeds itself from the URLs the fingerprinters
        # recorded, so it must run after them: a crawler that starts
        # with an empty inventory misses everything the fingerprinters
        # found.  Every other adapter runs in the first wave, together.
        first_wave = sorted(name for name in native_names if name != ASSET_CRAWL_ADAPTER)
        second_wave = sorted(name for name in native_names if name == ASSET_CRAWL_ADAPTER)

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

        await asyncio.gather(*(run_one(name) for name in first_wave))
        await asyncio.gather(*(run_one(name) for name in second_wave))

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

        The role carries a default, and the deployment can change it.

        The two budgets behave differently on purpose:

        * the **rounds** are a *cap*.  A role that declares six rounds
          gets six, whatever the deployment says: every role spending
          every round it was given is how a scan pays for twenty-four
          rounds of nothing.  A deployment that wants fewer rounds
          lowers the cap; one that wants more raises it, but only above
          what the role asks for.
        * the **tokens** and the **tool calls** are a *floor*.  A
          reasoning model needs more of both than a plain one: it spends
          a large part of every turn on reasoning, and the prompt grows
          with every tool result - so the deployment's value wins where
          the role asks for less.  A role that asks for *more* keeps it:
          the role knows the work better than the deployment does.
        """
        role_value = int((role.budget or {}).get(key, default))
        if not override:
            return role_value
        if key == "max_rounds":
            return min(role_value, int(override))
        return max(role_value, int(override))

    @staticmethod
    def _role_rank(role: str) -> int:
        """Where a role sits in the order the roles start in."""
        if role in ROLE_PRIORITY:
            return ROLE_PRIORITY.index(role)
        # The judging roles come last: they need the findings the
        # hypothesis roles produce.
        return len(ROLE_PRIORITY)

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

        The asset inventory is folded together when the worker phase is
        over, whether or not a worker stack was reachable: the crawler
        and the fingerprinters found URLs either way.
        """
        try:
            await self._run_karton_workers(context, scope)
        finally:
            try:
                self._merge_assets(context, self._primary_target(context))
            except Exception:  # pragma: no cover - the database may be down
                # The merge is the last thing the worker phase does.  A
                # failure in it must not hide the failure that brought
                # the scan here.
                log.exception("failed to merge the assets of the scan %s", context.scan_id)

    async def _run_karton_workers(self, context: ScanContext, scope: ScopeEnforcer) -> None:
        """Publish the targets to the Karton workers and collect what they found."""
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
        budget = max(10.0, float(context.max_duration_seconds) * self.settings.worker_phase_share)
        try:
            results = await asyncio.to_thread(self._run_workers, context, targets, budget)
        except Exception as exc:
            log.exception("the scanner workers failed for scan %s", context.scan_id)
            self._emit(context.scan_id, "worker.error", {"error": str(exc)})
            self._note_failure(context.scan_id, "worker", str(exc))
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
                self._note_failure(
                    context.scan_id,
                    "worker",
                    "no scanner worker consumed the task",
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
        auth_payload = self._auth_payload(context)
        prepared = []
        for url in targets:
            if self._is_cancelled(context.scan_id):
                break
            target = self.worker_bridge.prepare(
                url=url,
                description=context.name,
                platform_scan_id=context.scan_id,
            )
            # The session of the identity the scan names travels with
            # the task, so that the workers scan the authenticated
            # surface.  It is never written into the report.
            if auth_payload:
                target.auth = dict(auth_payload)
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

    def _auth_payload(self, context: ScanContext) -> dict[str, Any]:
        """The session the scan's identity gives the workers.

        The scan names an identity by its identifier.  The identity
        holds the session encrypted and only the runner decrypts it, so
        the payload is built here and never stored.
        """
        identity_id = str((context.options or {}).get("identity_id", "") or "")
        if not identity_id:
            return {}
        try:
            from ..db.identities import IdentityRepository

            repository = IdentityRepository(self.db, secret_box=self._secret_box)
            payload = repository.auth_payload(identity_id)
            if payload:
                repository.touch(identity_id)
            return payload
        except Exception:
            log.warning("could not read the session of the identity %s", identity_id)
            return {}

    def _merge_assets(self, context: ScanContext, primary_target: str) -> dict[str, int]:
        """Fold what was found into the asset inventory.

        Three sources feed the inventory: the rows the crawler wrote,
        the items the scanner workers produced and the URLs the
        fingerprinters identified.  They are merged by the normalised
        URL, so a URL the crawler and katana both saw is one row that
        names both - not two rows that say the same thing.

        A path a worker found is a URL of the target it was found on, and
        a URL that was never fetched has no status.
        """
        from_workers = 0
        from_services = 0

        try:
            items = self.worker_output.list_for_scan(context.scan_id, limit=5000)
        except Exception:  # pragma: no cover - the database may be down
            log.exception("failed to list the worker output of the scan %s", context.scan_id)
            items = []

        for item in items:
            row = _asset_row_of_worker_item(item, primary_target, context.authorized_hosts)
            if row is None:
                continue
            self.assets.upsert(
                scan_id=context.scan_id,
                url=row["url"],
                kind=row["kind"],
                scope=row["scope"],
                status_code=row["status_code"],
                source=row["source"],
            )
            from_workers += 1

        try:
            services = self.services.list_for_scan(context.scan_id)
        except Exception:  # pragma: no cover - the database may be down
            log.exception("failed to list the services of the scan %s", context.scan_id)
            services = []

        for service in services:
            url = normalise_url(str(service.get("url", "")))
            if not url:
                continue
            self.assets.upsert(
                scan_id=context.scan_id,
                url=url,
                kind=classify(url=url),
                scope=_scope_of(url, context.authorized_hosts),
                status_code=int(service.get("status_code", 0) or 0),
                host=str(service.get("host", "")),
                source="service_fingerprint",
            )
            from_services += 1

        counts = {
            "assets": self.assets.count(context.scan_id),
            "from_workers": from_workers,
            "from_services": from_services,
        }
        self._emit(context.scan_id, "assets.merged", dict(counts))
        return counts

    @staticmethod
    def _primary_target(context: ScanContext) -> str:
        """The target the scan is about."""
        for target in context.targets:
            text = str(target or "").strip()
            if not text:
                continue
            return text if "://" in text else f"https://{text}"
        return ""

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

    def _snapshot_worker_connections(self, context: ScanContext) -> None:
        """Record which workers were online when the scan started.

        The snapshot is taken before the work is dispatched: a worker
        that is online now and gone a minute later must still be
        reported as the worker that was there when the scan began.

        A backend that cannot be reached records nothing.  An
        unreachable backend is not evidence that a worker is absent, so
        nothing is written rather than "not connected" being written for
        every worker.
        """
        if self.worker_bridge is None:
            return
        try:
            identities = self.worker_bridge.online_identities()
        except Exception:  # pragma: no cover - the backend may be down
            log.exception("could not read the online workers of the scan %s", context.scan_id)
            return
        if not identities:
            return
        self.worker_runs.snapshot_connection(context.scan_id, identities)

    def _record_worker_outcomes(self, context: ScanContext) -> None:
        """Record what every worker did in this scan.

        The tasks a worker consumed, the findings it produced and the
        tasks that crashed are what tell a worker that ran and found
        nothing from one that errored.
        """
        if self.worker_bridge is None:
            return
        try:
            outcomes = self.worker_bridge.worker_outcomes(context.scan_id)
        except Exception:  # pragma: no cover - the backend may be down
            log.exception("could not read the worker outcomes of the scan %s", context.scan_id)
            return
        expected = self._expected_worker_versions()
        for outcome in outcomes:
            worker = str(outcome.get("worker", ""))
            if not worker:
                continue
            self.worker_runs.record(
                scan_id=context.scan_id,
                worker=worker,
                tasks=int(outcome.get("tasks", 0) or 0),
                findings=int(outcome.get("findings", 0) or 0),
                crashed_tasks=int(outcome.get("crashed_tasks", 0) or 0),
                # A worker that consumed a task was online.
                connected=True,
                expected_version=expected.get(worker, ""),
            )

    def _expected_worker_versions(self) -> dict[str, str]:
        """The version the platform expects of every worker.

        The workers do not report their version, so this is what the
        platform expects - not what a worker says it is.
        """
        from ..scanners.registry import default_all_adapters

        versions: dict[str, str] = {}
        for spec in default_all_adapters():
            identity = str(getattr(spec, "karton_identity", "") or "")
            if identity:
                versions[identity] = str(spec.version)
        return versions

    def _store_finding(self, scan_id: str, **fields: Any) -> dict[str, Any]:
        """Store one finding and tell the webhooks about the bad ones.

        A critical or a high finding is the thing an operator wants to
        hear about while it is happening, not an hour later when the
        report is read.
        """
        document, _created = self.findings.upsert(scan_id=scan_id, **fields)
        severity = str(fields.get("severity", "") or "").lower()
        if severity in {"critical", "high"}:
            self._emit(
                scan_id,
                f"finding.{severity}",
                {
                    "title": str(fields.get("title", "")),
                    "severity": severity,
                    "vuln_class": str(fields.get("vuln_class", "")),
                    "affected_url": str(fields.get("affected_url", "")),
                },
            )
        return document

    def _persist_worker_results(self, context: ScanContext, target: Any, outcome: Any) -> None:
        """Turn the worker output into platform findings and services."""
        for finding in outcome.findings:
            mapped = finding_for_platform(finding, target)
            self._store_finding(
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
            self._note_failure(context.scan_id, "scanner", result.error)

        for item in result.items:
            if not isinstance(item, dict):
                continue

            # The asset inventory.  The crawler records one row per URL
            # it saw; the row is metadata only.
            if name == ASSET_CRAWL_ADAPTER and result.kind == "url":
                self.assets.upsert(
                    scan_id=context.scan_id,
                    url=str(item.get("value", "")),
                    kind=str(item.get("kind", "other")),
                    scope=str(item.get("scope", "first_party")),
                    status_code=int(item.get("status_code", 0) or 0),
                    content_type=str(item.get("content_type", "")),
                    size_bytes=int(item.get("size_bytes", 0) or 0),
                    depth=int(item.get("depth", 0) or 0),
                    source=name,
                    discovered_from=str(item.get("discovered_from", "")),
                )
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
                    self._store_finding(
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
        deadline: float = 0.0,
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

            # The deadline of the scan.  A task that has not started
            # when it passes is marked as cut off and never runs: a role
            # that did not run is not a role that succeeded.  A task
            # that already succeeded keeps its result - its work was
            # done before the deadline passed.
            if deadline and time.monotonic() >= deadline:
                self._mark_tasks_cut_off(
                    context,
                    [task for task in pending.values() if not self._already_succeeded(task.task_id)],
                    "the scan ran out of its time",
                )
                break

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

            ready.sort(key=lambda t: (-len(t.depends_on), self._role_rank(t.role)))
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
                if self._already_succeeded(task.task_id):
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

            results, cut_off = await self._run_batch(
                context, todo, scope, roles, collaboration, candidates, deadline
            )
            if cut_off:
                # The tasks that had not started are cut off as well.
                self._mark_tasks_cut_off(context, list(pending.values()), "the scan ran out of its time")
                break

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
                    self._note_failure(context.scan_id, "task", str(result))
                    continue

                run = result
                tokens_spent += int(getattr(run, "tokens_used", 0) or 0)
                # The task status must reflect what the agent actually
                # achieved: a run that failed or ran out of budget is not a
                # successful task.
                if run.status == "succeeded":
                    self.tasks.set_status(task.task_id, "succeeded", result=run.to_dict())
                    completed.add(task.task_id)
                elif run.status in ("wall_clock", "cancelled", "no_new_evidence"):
                    # The stop reason is the status of the task: a role
                    # that was cut off is not a failure, and it is not a
                    # success either.
                    failed.add(task.task_id)
                    self.tasks.set_status(
                        task.task_id,
                        run.status,
                        error=run.error or f"the agent run ended with status '{run.status}'",
                        result=run.to_dict(),
                    )
                else:
                    failed.add(task.task_id)
                    reason = run.error or f"the agent run ended with status '{run.status}'"
                    self.tasks.set_status(
                        task.task_id,
                        "failed",
                        error=reason,
                        result=run.to_dict(),
                    )
                    self._note_failure(context.scan_id, "task", reason)
                self._emit(
                    context.scan_id,
                    "agent.completed",
                    {
                        "task_id": task.task_id,
                        "role": run.role,
                        "status": run.status,
                        "stop_reason": run.to_dict().get("stop_reason", ""),
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

    async def _run_batch(
        self,
        context: ScanContext,
        todo: list[AgentTask],
        scope: ScopeEnforcer,
        roles: dict[str, AgentRole],
        collaboration: CollaborationState,
        candidates: Sequence[CandidateFinding],
        deadline: float,
    ) -> tuple[list[Any], bool]:
        """Run the tasks of one batch and stop them at the deadline.

        The deadline is enforced here: a batch that is still running
        when it passes is cancelled, and the tasks of it are recorded as
        cut off rather than as successful.  The second value of the
        result says whether the batch was cut off.
        """
        running = asyncio.gather(
            *(self._run_agent_task(context, task, scope, roles, collaboration, candidates) for task in todo),
            return_exceptions=True,
        )
        if not deadline:
            return list(await running), False
        try:
            results = await asyncio.wait_for(running, timeout=max(0.0, deadline - time.monotonic()))
        except asyncio.TimeoutError:
            self._mark_tasks_cut_off(context, todo, "the scan ran out of its time")
            return [], True
        return list(results), False

    def _mark_tasks_cut_off(
        self,
        context: ScanContext,
        tasks: Sequence[AgentTask],
        reason: str,
    ) -> None:
        """Record the tasks the deadline cut off.

        A task that never started and a task that was cut off
        mid-flight are both recorded as ``wall_clock``: neither of them
        did what it was supposed to do, and neither of them may be
        reported as a success.
        """
        for task in tasks:
            self.tasks.set_status(
                task.task_id,
                "wall_clock",
                error=reason,
                result={
                    "task_id": task.task_id,
                    "role": task.role,
                    "status": "wall_clock",
                    "stop_reason": "wall_clock",
                },
            )
            self._emit(
                context.scan_id,
                "task.wall_clock",
                {"task_id": task.task_id, "role": task.role, "reason": reason},
            )

    def _scan_deadline(self, context: ScanContext) -> float:
        """When the scan has to stop, as a monotonic timestamp.

        The deadline is stored on the scan as an epoch timestamp, so a
        scan that is picked up again knows how much of its time is left.
        A scan that already carries a deadline keeps it: the time it
        was given does not grow because it was interrupted.
        """
        stored = self._stored_deadline(context.scan_id)
        if stored <= 0:
            stored = time.time() + max(1, int(context.max_duration_seconds))
            self.scans.update(context.scan_id, {"deadline_at": stored})
        return time.monotonic() + max(0.0, stored - time.time())

    def _stored_deadline(self, scan_id: str) -> float:
        """The deadline the scan carries, or zero when it carries none."""
        document = self.db.collection("platform_scans").find_one({"scan_id": scan_id}) or {}
        try:
            return float(document.get("deadline_at", 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    def _already_succeeded(self, task_id: str) -> bool:
        """Did this task already do its work?

        A task that succeeded keeps its result: the work it did is done,
        and a deadline that passes afterwards does not undo it.
        """
        stored = self.tasks.get(task_id)
        return bool(stored is not None and stored.get("status") == "succeeded")

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------
    def _admit_roles(self, context: ScanContext, tasks: list[Any]) -> list[Any]:
        """The roles a scan runs, and the ones it cannot afford.

        The roles are admitted in the order of their yield, so the ones
        that run are the ones that find something.  A role that is not
        admitted is recorded as cut off, with the reason, rather than
        being left pending: a scan that says what it did not do is
        worth more than one that looks busy.
        """
        limit = int(self.settings.agent_max_roles or 0)
        if limit <= 0 or len(tasks) <= limit:
            return tasks
        ordered = sorted(tasks, key=lambda task: self._role_rank(getattr(task, "role", "")))
        admitted = ordered[:limit]
        for task in ordered[limit:]:
            self.tasks.set_status(
                task.task_id,
                "wall_clock",
                error=(f"the scan's budget allowed {limit} role(s) and this one was not among them"),
            )
            self._emit(
                context.scan_id,
                "task.wall_clock",
                {"task_id": task.task_id, "role": task.role, "reason": "the budget"},
            )
        return sorted(admitted, key=lambda task: self._role_rank(getattr(task, "role", "")))

    def _judging_reserve(self, context: ScanContext, deadline: float) -> float:
        """The share of the agent budget kept for the judging roles."""
        total = max(0.0, deadline - time.monotonic())
        return total * float(self.settings.agent_judging_budget_share)

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
            on_tool_call=self._note_tool_call,
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
        self._persist_agent_findings(
            context=context,
            role=task.role,
            task_id=task.task_id,
            findings=run.findings,
        )
        return run

    def _persist_agent_findings(
        self,
        *,
        context: ScanContext,
        role: str,
        task_id: str,
        findings: Any,
    ) -> None:
        """Store the findings an agent proposed.

        The judging roles do not propose.  A judge that proposed would
        put the same defect into the report a second time — with no
        verdict, and with no host, so it could neither merge with the
        first nor be dismissed.  They rule on what the other roles
        found, and that is all they do.
        """
        if role in JUDGING_ROLES:
            return

        default_host = self._default_host(context)
        for finding in parse_findings(findings, role=role, task_id=task_id):
            self._store_finding(
                scan_id=context.scan_id,
                title=finding.title,
                summary=finding.summary,
                vuln_class=finding.vuln_class,
                severity=finding.severity,
                # A finding without a host cannot be matched to the
                # target, and cannot merge with the finding the tools
                # reported for the same defect.  The agent was working
                # on one target, so its finding belongs to that target.
                host=finding.host or default_host,
                path=finding.path,
                parameter=finding.parameter,
                cwe=finding.cwe,
                confidence=finding.confidence,
                detected_by=[role],
                detection_source="agent",
                affected_url=finding.affected_url,
                evidence=finding.evidence,
                remediation=finding.remediation,
                extra_key=finding.extra_key,
            )

    @staticmethod
    def _default_host(context: ScanContext) -> str:
        """The host of the target a scan is working on."""
        hosts = list(context.authorized_hosts or ())
        if hosts:
            return hosts[0]
        for target in context.targets or ():
            try:
                host = urlsplit(target).hostname or ""
            except ValueError:
                host = ""
            if host:
                return host
        return ""

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

    async def _open_browser(self, context: ScanContext) -> Any:
        """Open the browser the roles drive.

        It is opened only when a role of the scan actually uses it: a
        browser that is opened for nothing spends the budget of the
        scan on nothing.
        """
        roles = builtin_roles()
        wanted = any(
            "browser" in (roles.get(role).tools if roles.get(role) else [])
            for role in context.profile.agent_roles
        )
        if not wanted:
            return None
        if self._browser is not None:
            return self._browser
        try:
            from ..browser.scope import ScopeBrowser

            workspace = Path(context.workspace_root or self.settings.agent_workspace_root)
            await asyncio.to_thread(workspace.mkdir, parents=True, exist_ok=True)
            browser = ScopeBrowser(
                policy=context.scope_policy(),
                workspace=str(workspace),
            )
            await browser.start()
        except Exception:
            # A scan without a browser is a scan without the browser
            # tool; it is not a scan that cannot run.
            log.exception("could not open the browser for the scan")
            return None
        self._browser = browser
        return browser

    async def _close_browser(self) -> None:
        """Close the browser of the scan."""
        browser = self._browser
        self._browser = None
        if browser is None:
            return
        try:
            await browser.stop()
        except Exception:  # pragma: no cover - a browser that will not close
            log.exception("could not close the browser")

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
                # The URLs the scan saw, so that an agent can list them
                # instead of crawling the target a second time.
                "asset_repository": self.assets,
                # The callback service, so that an agent can confirm a
                # blind finding instead of guessing at it.
                "callbacks_repository": self.callbacks,
                "callback_base_url": self.settings.callback_base_url,
                # The browser the roles drive.  It is opened once for
                # the scan and closed when the scan ends.
                "browser": self._browser,
                "scan_id": context.scan_id,
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
