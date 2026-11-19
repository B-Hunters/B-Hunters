"""Drive the real Karton scanner workers from a platform scan.

A scan started from the console used to stop at the in-process adapters.
The platform never published a Karton task, so the scanner worker
containers stayed bound and idle and the console showed only what the
seven native adapters had found.  This module closes that gap.

It reproduces the task contract the legacy CLI uses, so the workers behave
exactly as they do for a command line scan:

* the platform writes the legacy ``scans`` document, whose ``_id`` is the
  identifier the workers correlate on;
* it publishes a ``domain``/``new`` task.  The discovery worker
  (``subrecon``) consumes it, creates the legacy ``reports`` and
  ``domains`` documents and republishes the work as a ``subdomain``/``new``
  task;
* the crawler (``katana``) uploads the discovered URLs to the artefact
  store and publishes the ``paths``/``scan`` task that the scanners
  consume;
* the workers write their results into the legacy ``reports`` document,
  which this module reads back and turns into platform findings.

Nothing here is invented.  The payload names, the persistent flags and
the correlation keys all come from the worker sources, and the persistent
payloads propagate through the whole task subtree (Karton merges them
into every task a consumer sends), so ``scan_id`` and ``report_id``
reach the scanners without being re-sent.

The platform makes no outbound request of its own here: it writes to
MongoDB and publishes to the Karton queue.  The workers reach the target
from their own containers, exactly as they do for a CLI scan, and only
targets the platform has already validated against the scan scope are
handed to them.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from bson import ObjectId

from ..bench.workers import collect_from_report, services_from_report

log = logging.getLogger(__name__)

#: The scheme every worker strips from a target before it uses the target
#: as the key of the ``domains`` document and of the artefact.
_SCHEME_RE = re.compile(r"^https?://")

#: The vulnerability class a worker report implies, and the severity the
#: platform records for it.  The workers do not report a severity, so it is
#: derived from the class the report field maps onto.
CLASS_SEVERITIES = {
    "sql_injection": "high",
    "xss": "medium",
    "ssti": "high",
    "ssrf": "high",
    "path_traversal": "high",
    "active_vulnerability": "medium",
    "information_disclosure": "low",
    "security_misconfiguration": "low",
}

#: How long a scan waits for the workers before it takes what they have
#: produced so far.
DEFAULT_WAIT_SECONDS = 300

#: How often the report is polled while the workers run.
DEFAULT_POLL_SECONDS = 2.0


def normalize_target(url: str) -> str:
    """The form the workers use for a target.

    Every worker derives its status key and its artefact key from this
    normalisation: the scheme is removed and the trailing slashes are
    dropped.  The ``subdomain`` payload and the ``Domain`` field of the
    ``domains`` document have to agree with it, otherwise the status of a
    worker lands in a document that does not exist and its progress is
    lost.
    """
    return _SCHEME_RE.sub("", url or "").rstrip("/")


def host_of(domain: str) -> str:
    """The host of a normalised target, without the port."""
    return domain.split("/", 1)[0].split(":", 1)[0]


#: The report fields whose name does not say which worker writes them.
#: The findings of a report name the field they came from, and the field
#: is what says which worker found them.
_EXTRA_FIELD_WORKERS = {
    "nmap": "B-Hunters-Nmap",
    "technology": "B-Hunters-web-technology",
}


def identity_from_queue(queue: str) -> str:
    """The worker identity a bound queue belongs to.

    Karton names the queues after the consumer that binds them:
    ``normal:B-Hunters-Nuclei``.  The queue is therefore a second, and
    more complete, record of who is online: a worker whose Redis client
    is called ``redis-py`` is invisible in the client list and visible
    here.
    """
    name = str(queue or "").strip()
    if ":" in name:
        name = name.rsplit(":", 1)[-1]
    return name.strip()


def worker_of_detector(detector: str) -> str:
    """The worker that writes the report field a finding names.

    An empty name means the finding came from nowhere the platform can
    name - it is not counted for any worker.
    """
    name = str(detector or "").strip()
    if not name:
        return ""

    from .worker_output import WORKER_FIELDS

    for path, identity in WORKER_FIELDS:
        if path.rsplit(".", 1)[-1] == name:
            return identity
    return _EXTRA_FIELD_WORKERS.get(name, "")


@dataclass
class WorkerTarget:
    """One target handed to the scanner workers."""

    #: The URL as the operator wrote it.
    url: str
    #: The normalised target: no scheme, no trailing slash.
    domain: str
    #: The identifier of the legacy ``scans`` document.
    legacy_scan_id: str
    #: The identifier of the legacy ``reports`` document, once the
    #: discovery worker has created it.
    report_id: str = ""
    #: The platform scan this target belongs to.  The bridge keeps the
    #: analysis of every target of a scan, so that the crashed tasks can
    #: be counted when the scan asks for them.
    platform_scan_id: str = ""
    #: The session of the identity the scan names: the cookies and the
    #: headers the workers pass to their tools.
    auth: dict[str, Any] = field(default_factory=dict)
    #: The hosts the scan must not touch.  The workers are separate
    #: containers and they discover hosts of their own, so the
    #: exclusions have to travel with the task - otherwise a worker
    #: scans an out-of-scope asset the scan was told to leave alone.
    denied_hosts: tuple[str, ...] = ()
    #: The workers this scan asked for.  The router sends a task to
    #: every consumer whose filters match, so without this a scan that
    #: named three scanners would run all seventeen.
    enabled_workers: tuple[str, ...] = ()


@dataclass
class WorkerResults:
    """What the workers produced for one target."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    report_id: str = ""
    #: ``False`` when no worker produced a report for the target.
    consumed: bool = False


class KartonWorkerBridge:
    """Publish scan targets to the Karton workers and collect the results."""

    def __init__(
        self,
        *,
        producer: Any,
        database: Any,
        wait_seconds: int = DEFAULT_WAIT_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
    ) -> None:
        self.producer = producer
        self.db = database
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds
        #: The analysis trees of the scans this bridge drove, so that the
        #: crashed tasks can be counted after the scan is over.
        self._analyses: dict[str, list[str]] = {}
        #: The task counters as they were before a scan dispatched its
        #: work.  The counters are kept across every scan, so the
        #: difference is what this scan made the workers do.
        self._counters: dict[str, dict[str, int]] = {}
        #: The findings every worker produced, per scan.
        self._findings: dict[str, dict[str, int]] = {}

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------
    def prepare(
        self,
        *,
        url: str,
        description: str = "",
        platform_scan_id: str = "",
        denied_hosts: Sequence[str] = (),
        enabled_workers: Sequence[str] = (),
    ) -> WorkerTarget:
        """Create the legacy scan document for a target.

        The workers look the scan up by the identifier of this document
        (``checklinksexist`` resolves ``domains.Scanid`` through
        ``scans._id``), so it has to exist before the task is published.

        The platform's own scan identifier is recorded on it as well, so
        that the document a worker writes can be joined back to the scan
        that asked for it.  The legacy documents carry no such link.
        """
        domain = normalize_target(url)
        scan_oid = ObjectId()
        self.db.collection("scans").insert_one(
            {
                "_id": scan_oid,
                "Domain": domain,
                "Type": "single",
                "Description": description,
                "Platform_Scan_Id": platform_scan_id,
            }
        )
        if platform_scan_id:
            # The counters are kept across every scan: the ones from
            # before this scan are what tell the console which workers
            # took part in *this* scan.
            self._counters.setdefault(platform_scan_id, self.consumed_tasks())
        return WorkerTarget(
            url=url,
            domain=domain,
            legacy_scan_id=str(scan_oid),
            platform_scan_id=platform_scan_id,
            denied_hosts=tuple(str(h).strip().lower() for h in denied_hosts if str(h).strip()),
            enabled_workers=tuple(str(w).strip() for w in enabled_workers if str(w).strip()),
        )

    def online_identities(self) -> list[str]:
        """The identity of every consumer that is online right now.

        Two sources are read, because neither is complete on its own:

        * the **Redis client names** — Karton names its client after the
          identity, but only some of the Karton versions in the fleet do
          it, so a worker whose client is called ``redis-py`` is
          invisible here;
        * the **bound queues** — a worker that binds on a queue appears
          in it, and the queue name carries the identity
          (``normal:B-Hunters-Nuclei``).  This is what makes a worker
          that consumed no task visible at all.

        A backend that cannot be reached reports nothing: an unreachable
        backend is not evidence that a worker is absent, and the caller
        records nothing rather than recording "not connected".
        """
        identities: set[str] = set()
        try:
            consumers = self.producer.backend.get_online_consumers()
            identities.update(str(name).strip() for name in (consumers or {}))
        except Exception as exc:  # pragma: no cover - the backend may be down
            log.debug("could not read the online consumers: %s", exc)
            return []

        for name, queue in self._queues():
            identity = identity_from_queue(name)
            # A bound queue is not a running worker.  The router knows
            # how many consumers are listening to each identity, and a
            # queue nobody is listening to is a bind left behind by a
            # worker that has stopped.  Counting those as online is
            # what made a scan wait for tasks that nobody would take.
            if identity and queue.online_consumers_count > 0:
                identities.add(identity)
        return sorted(name for name in identities if name)

    def _queues(self) -> list[tuple[str, Any]]:
        """The queues the workers are bound to, with their consumers."""
        try:
            from karton.core.inspect import KartonState

            state = KartonState(self.producer.backend)
            return list(state.queues.items())
        except Exception as exc:  # pragma: no cover - the backend may blip
            log.debug("could not read the bound queues: %s", exc)
            return []

    def worker_outcomes(self, scan_id: str) -> list[dict[str, Any]]:
        """What every worker did in a scan.

        Three facts per worker: the tasks it consumed, the findings it
        produced and the tasks that crashed.  The first comes from the
        counters Karton keeps, the second from the findings that were
        read back and the third from the analysis tree of the scan - the
        tree the bridge keeps the root uid of.
        """
        before = self._counters.get(scan_id, {})
        after = self.consumed_tasks()
        tasks: dict[str, int] = {}
        for identity, count in after.items():
            delta = count - int(before.get(identity, 0))
            if delta > 0:
                tasks[identity] = delta
        crashed = self._crashed_tasks(scan_id)
        findings = self._findings.get(scan_id, {})

        rows: list[dict[str, Any]] = []
        for identity in sorted(set(tasks) | set(crashed) | set(findings)):
            rows.append(
                {
                    "worker": identity,
                    "tasks": tasks.get(identity, 0),
                    "findings": findings.get(identity, 0),
                    "crashed_tasks": crashed.get(identity, 0),
                }
            )
        return rows

    def consumed_tasks(self) -> dict[str, int]:
        """How many tasks each service has consumed, per identity.

        Karton keeps these counters, so they answer "did this worker run"
        for every worker - including the ones that found nothing and
        therefore wrote nothing anywhere.
        """
        try:
            raw = self.producer.backend.redis.hgetall("karton.metrics.consumed")
        except Exception as exc:  # pragma: no cover - the backend may be down
            log.debug("could not read the Karton task counters: %s", exc)
            return {}
        counts: dict[str, int] = {}
        for identity, value in (raw or {}).items():
            name = identity.decode() if isinstance(identity, bytes) else str(identity)
            try:
                counts[name] = int(value)
            except (TypeError, ValueError):
                continue
        return counts

    def dispatch(self, target: WorkerTarget) -> str:
        """Publish the task the discovery worker consumes.

        The payload is the one the legacy CLI publishes: the target is
        carried persistently, so that it survives the whole task subtree,
        and the scan identifier is persistent as well, so that every
        worker in the chain reports into the same scan.

        Returns the identifier of the analysis tree the task roots.  The
        whole chain - the discovery worker, the crawler and every scanner
        - stays inside that tree, so it is what tells the platform when
        the work is finished.
        """
        from karton.core import Task

        task = Task({"type": "domain", "stage": "new"})
        task.add_payload("domain", target.domain, persistent=True)
        task.add_payload("scantype", "single", persistent=True)
        task.add_payload("scan_id", target.legacy_scan_id, persistent=True)
        task.add_payload("data", target.domain)
        task.add_payload("source", "producer")
        if target.denied_hosts:
            # The hosts the scan must not touch.  Persistent, so that the
            # whole subtree inherits them: the discovery worker hands
            # every subdomain it finds to the rest of the fleet, and a
            # worker must refuse the ones that are out of scope.
            task.add_payload("denied_hosts", list(target.denied_hosts), persistent=True)
        if target.enabled_workers:
            # The workers this scan asked for.  Persistent, so that the
            # whole subtree inherits them: the router sends a task to
            # every consumer whose filters match, and a worker that the
            # scan did not ask for must do nothing at all.
            task.add_payload(
                "enabled_workers", list(target.enabled_workers), persistent=True
            )
        if target.auth:
            # The session of the identity the scan names.  The workers
            # read it from the task and pass it to their tools; it is
            # never written into the report.
            task.add_payload("auth", target.auth)
        self.producer.send_task(task)
        root_uid = str(task.root_uid)
        if target.platform_scan_id:
            # The root of the analysis is kept: the tree is what says
            # which tasks crashed, and it can only be read while the
            # root uid is known.
            self._analyses.setdefault(target.platform_scan_id, []).append(root_uid)
        return root_uid

    # ------------------------------------------------------------------
    # Collecting
    # ------------------------------------------------------------------
    def collect(
        self,
        target: WorkerTarget,
        *,
        root_uid: str = "",
        deadline: float | None = None,
        should_stop=None,
        online: set[str] | None = None,
    ) -> WorkerResults:
        """Wait for the workers and read back what they wrote.

        The wait is bounded.  When the deadline passes the report is read
        anyway, so a slow scanner contributes what it found instead of
        being discarded.
        """
        results = WorkerResults()
        if deadline is None:
            deadline = time.monotonic() + self.wait_seconds

        if root_uid:
            self._await_analysis(
                root_uid,
                deadline=deadline,
                should_stop=should_stop,
                online=online,
            )

        report_id = self._await_report_id(target, deadline=deadline)
        if not report_id:
            log.info("no worker produced a report for %s", target.domain)
            return results

        results.report_id = report_id
        results.consumed = True

        # The discovery worker gives every host it finds a report of its
        # own, so the findings of a subdomain live in that report and not
        # in the one of the target.  A platform that reads only the
        # report of the target reads only the findings of the target.
        report_ids = self._report_ids_for_scan(target.legacy_scan_id) or [report_id]
        for one in report_ids:
            document = self._report_document(one)
            if not document:
                continue
            results.findings.extend(collect_from_report(document))
            results.services.extend(services_from_report(document))
        self._count_findings(target.platform_scan_id, results.findings)
        return results

    def _report_ids_for_scan(self, legacy_scan_id: str) -> list[str]:
        """Every report document the scan produced.

        The workers record the report of a host in the ``domains``
        document of that host, and every document of a scan carries the
        scan's identifier, so the reports of a scan are the ones that
        belong to it.
        """
        if not legacy_scan_id:
            return []
        found: list[str] = []
        try:
            cursor = self.db.collection("domains").find(
                {"Scanid": legacy_scan_id}, {"report_id": 1}
            )
        except Exception:  # pragma: no cover - the database may be down
            return []
        for document in cursor:
            report_id = document.get("report_id")
            if not report_id:
                continue
            value = str(report_id)
            if value not in found:
                found.append(value)
        return found

    def _report_document(self, report_id: str) -> dict[str, Any]:
        """The report document with that identifier, or nothing."""
        try:
            return self.db.collection("reports").find_one({"_id": ObjectId(report_id)}) or {}
        except Exception:  # pragma: no cover - a malformed identifier
            return {}

    def _count_findings(self, scan_id: str, findings: list[dict[str, Any]]) -> None:
        """Count the findings every worker produced.

        A finding names the report field it came from, and every field
        belongs to one worker - so the findings of a scan are counted
        per worker here rather than left in a pile.
        """
        if not scan_id:
            return
        counts = self._findings.setdefault(scan_id, {})
        for finding in findings:
            identity = worker_of_detector(str(finding.get("detector", "")))
            if not identity:
                continue
            counts[identity] = counts.get(identity, 0) + 1

    def _crashed_tasks(self, scan_id: str) -> dict[str, int]:
        """How many tasks of the scan crashed, per worker.

        The crashed tasks are read from the analysis tree of the scan:
        the tree holds every task of the scan, and a task that crashed
        names the consumer that took it.
        """
        roots = self._analyses.get(scan_id, [])
        if not roots:
            return {}
        try:
            from karton.core.inspect import KartonState

            state = KartonState(self.producer.backend)
        except Exception as exc:  # pragma: no cover - the backend may be down
            log.debug("could not read the Karton state: %s", exc)
            return {}

        counts: dict[str, int] = {}
        for root_uid in roots:
            try:
                analysis = state.get_analysis(root_uid)
            except Exception as exc:  # pragma: no cover - the backend may blip
                log.debug("could not read the Karton analysis %s: %s", root_uid, exc)
                continue
            for task in analysis.crashed_tasks:
                identity = str(getattr(task, "headers", {}).get("receiver", "") or "")
                if not identity:
                    continue
                counts[identity] = counts.get(identity, 0) + 1
        return counts

    def _await_analysis(
        self,
        root_uid: str,
        *,
        deadline: float,
        should_stop=None,
        online: set[str] | None = None,
    ) -> None:
        """Wait until every task of the analysis tree is finished.

        The tree is the reliable signal.  The ``status`` fields of the
        ``domains`` document are not: the workers update them by host
        alone, so two scans of the same host overwrite each other's
        status.  The analysis tree is rooted in the task the platform
        published, so it describes this scan and no other.

        Two things end the wait early.  A scan that was asked to stop
        does not wait.  And a task that is queued to a consumer nobody
        is listening to will never be taken: the router sends a task to
        every consumer whose filters match it, so a bind left behind by
        a worker that has stopped leaves a task in a queue for good.
        Waiting for it is how the worker phase spent the whole budget of
        a scan and left the agents with none.
        """
        from karton.core.inspect import KartonState
        from karton.core.task import TaskState

        terminal = {TaskState.FINISHED, TaskState.CRASHED}
        while True:
            if should_stop is not None and should_stop():
                log.info("the scan was asked to stop; the workers are not waited for")
                return
            try:
                state = KartonState(self.producer.backend)
                analysis = state.get_analysis(root_uid)
                open_tasks = [task for task in analysis.tasks if task.status not in terminal]
                if not open_tasks:
                    return
                if online is not None:
                    waiting_on_absent = all(
                        str((task.headers or {}).get("receiver") or "") not in online
                        for task in open_tasks
                    )
                    if waiting_on_absent:
                        log.info(
                            "the remaining tasks are queued to workers that are not running"
                        )
                        return
            except Exception as exc:  # pragma: no cover - the backend may blip
                log.debug("could not read the Karton analysis %s: %s", root_uid, exc)
            if time.monotonic() >= deadline:
                return
            time.sleep(self.poll_seconds)

    def _await_report_id(self, target: WorkerTarget, *, deadline: float) -> str:
        """Wait for the discovery worker to create the report document."""
        while True:
            document = self.db.collection("domains").find_one(
                {"Scanid": target.legacy_scan_id, "Domain": target.domain}
            )
            if document and document.get("report_id"):
                return str(document["report_id"])
            if time.monotonic() >= deadline:
                return ""
            time.sleep(self.poll_seconds)


def build_worker_bridge(
    *,
    settings: Any,
    database: Any,
    wait_seconds: Optional[int] = None,
) -> Optional[KartonWorkerBridge]:
    """Build the bridge, or ``None`` when the Karton backend is unreachable.

    A platform without reachable workers is still a working platform: the
    native adapters and the agents run either way, so a missing worker
    stack degrades the scan instead of failing it.
    """
    try:
        from karton.core import Config, Producer

        producer = Producer(
            config=Config(path=settings.karton_config_path),
            identity=settings.karton_identity,
        )
    except Exception as exc:
        log.info("the Karton backend is not reachable: %s", exc)
        return None

    return KartonWorkerBridge(
        producer=producer,
        database=database,
        wait_seconds=wait_seconds if wait_seconds is not None else DEFAULT_WAIT_SECONDS,
    )


def finding_for_platform(finding: dict[str, Any], target: WorkerTarget) -> dict[str, Any]:
    """Map a worker finding onto the platform's finding shape."""
    vuln_class = str(finding.get("vuln_class") or "active_vulnerability")
    location = str(finding.get("location") or "")
    detector = str(finding.get("detector") or "worker")
    host = host_of(target.domain)
    path = ""
    affected_url = target.url
    if location.startswith(("http://", "https://")):
        affected_url = location
        without_scheme = _SCHEME_RE.sub("", location)
        path = "/" + without_scheme.split("/", 1)[1] if "/" in without_scheme else "/"
    elif location:
        path = location if location.startswith("/") else f"/{location}"

    return {
        "title": str(finding.get("title") or "worker finding"),
        "summary": str(finding.get("summary") or ""),
        "vuln_class": vuln_class,
        "severity": CLASS_SEVERITIES.get(vuln_class, "medium"),
        "host": host,
        "path": path,
        "parameter": "",
        "cwe": "",
        "confidence": 0.7,
        "detected_by": [detector],
        "detection_source": detector,
        "affected_url": affected_url,
        "evidence": list(finding.get("evidence") or []),
        "remediation": "",
        # The fingerprint of a finding is built from the class, the host,
        # the path and this key.  Without it two different findings of the
        # same class on the same host would collapse into one, and a worker
        # finding would be merged into an unrelated finding of the native
        # adapters.
        "extra_key": f"worker:{detector}:{location or str(finding.get('title') or '')}"[:240],
    }
