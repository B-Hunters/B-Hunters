"""The worker output page.

Karton forgets a task once it finishes, so the durable record of what a
scanner produced is the document it wrote: the legacy ``reports``
document, the ``links`` collection and the ``js`` collection.

A worker that found nothing writes nothing anywhere, so this page also
reads the task counters the platform recorded for the scan.  Together
they answer the question the output alone cannot: did this scanner run,
and what did it find.
"""

from __future__ import annotations

from typing import Any, Optional

from bson import ObjectId
from flask import Blueprint, render_template

workers_blueprint = Blueprint("workers", __name__)

#: The report fields each worker owns, and the identity it registers under.
WORKER_FIELDS = (
    ("Vulns.Nuclei", "B-Hunters-Nuclei"),
    ("Vulns.SQLMap", "B-Hunters-SQLMap"),
    ("Vulns.dalfox", "B-Hunters-DalFox"),
    ("Vulns.Xray", "B-Hunters-xray"),
    ("Vulns.Wapiti", "B-Hunters-wapiti"),
    ("Vulns.SSTI", "B-Hunters-SSTI-Checker"),
    ("Ports", "B-Hunters-Nmap"),
    ("Technology.wappy", "B-Hunters-web-technology"),
    ("Technology.nmap", "B-Hunters-Nmap"),
    ("Paths", "B-Hunters-dirsearch"),
    ("Paths403", "B-Hunters-dirsearch"),
    ("Screenshot", "B-Hunters-GoWitness"),
    ("Vulns.ffuf", "B-Hunters-Ffuf"),
)

#: The workers that write into the ``links`` collection, and the field
#: their identity is stored under.
LINK_WORKERS = (
    "B-Hunters-Katana",
    "B-Hunters-ParamSpider",
)

#: The workers that write their result into the report's ``data`` document
#: instead of into a field of their own.
DATA_WORKERS = {
    "gowitness": "B-Hunters-GoWitness",
}


def _database() -> Any:
    """The MongoDB database the workers write into."""
    import pymongo
    from karton.core import Config

    config = Config(path="/etc/karton/karton.ini")
    mongo = config["mongo"]
    connection = (
        f"mongodb://{mongo['user']}:{mongo['password']}@"
        f"{mongo['host']}:{mongo['port']}/?authSource=admin"
    )
    client = pymongo.MongoClient(connection, serverSelectionTimeoutMS=5000)
    return client[mongo["db"]]


def _consumed_tasks() -> dict[str, int]:
    """How many tasks each identity has consumed, over every scan.

    The per-scan counters are written when the scan ends, so during a
    scan the page would call a worker that is working right now "did not
    run".  These counters are the live view of the same thing.
    """
    try:
        from karton.dashboard.app import karton

        raw = karton.backend.redis.hgetall("karton.metrics.consumed")
    except Exception:  # pragma: no cover - the backend may be down
        return {}
    counts: dict[str, int] = {}
    for identity, value in (raw or {}).items():
        name = identity.decode() if isinstance(identity, bytes) else str(identity)
        try:
            counts[name] = int(value)
        except (TypeError, ValueError):
            continue
    return counts


def _connected_workers() -> list[str]:
    """The workers connected to the task router right now."""
    try:
        from karton.core.inspect import KartonState

        from karton.dashboard.app import karton

        state = KartonState(karton.backend)
        return sorted(state.queues.keys())
    except Exception:  # pragma: no cover - the backend may be down
        return []


def _dig(document: Any, path: str) -> Any:
    """Read a dotted path out of a document."""
    current = document
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _count(value: Any) -> int:
    """How many items a report field holds."""
    if value is None:
        return 0
    if isinstance(value, str):
        return 1 if value.strip() else 0
    if isinstance(value, (list, tuple, set)):
        # A worker stores its result as a list wrapped in a list, and
        # MongoDB appends the wrapper rather than the items in it.
        if len(value) == 1 and isinstance(value[0], (list, tuple)):
            return _count(value[0])
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 1


#: How much of a worker's output is rendered.  Nothing is dropped
#: silently: the page says when there is more.
PREVIEW_LIMIT = 20000


def _preview(value: Any, limit: int = PREVIEW_LIMIT) -> tuple[str, bool]:
    """A readable rendering of whatever the worker wrote.

    Every item is rendered - a worker that found two hundred links shows
    two hundred links.  Only a very long output is cut, and the caller
    is told that it was.
    """
    if value is None:
        return "", False
    if isinstance(value, str):
        text = value
    elif isinstance(value, dict):
        lines = []
        for key, item in value.items():
            if isinstance(item, (list, tuple)):
                lines.append(f"{key}: {len(item)} item(s)")
                for entry in item:
                    lines.append(f"    {entry}")
            else:
                lines.append(f"{key}: {item}")
        text = "\n".join(lines)
    elif isinstance(value, (list, tuple)):
        text = "\n".join(f"    {entry}" for entry in value)
    else:
        text = str(value)
    if len(text) > limit:
        return text[:limit], True
    return text, False


def _data_preview(payload: dict[str, Any], limit: int = 4000) -> str:
    """A readable rendering of the payload a worker stored under ``data``.

    The workers that write here keep the full result of the probe: the page
    it reached, what it found on it, and why it stopped.
    """
    lines: list[str] = []
    for key in (
        "url",
        "final_url",
        "title",
        "response_code",
        "response_reason",
        "protocol",
        "content_length",
        "file_name",
        "failed",
        "failed_reason",
    ):
        if key in payload and payload[key] not in (None, ""):
            lines.append(f"{key}: {payload[key]}")

    technologies = payload.get("technologies") or []
    if technologies:
        names = [
            str(entry.get("value") if isinstance(entry, dict) else entry)
            for entry in technologies
        ]
        lines.append("technologies: " + ", ".join(names))

    headers = payload.get("headers") or []
    for entry in headers[:12]:
        if isinstance(entry, dict):
            lines.append(f"header: {entry.get('key')}: {entry.get('value')}")
        else:
            lines.append(f"header: {entry}")

    network = payload.get("network") or []
    for entry in network[:12]:
        if isinstance(entry, dict):
            lines.append(
                f"request: {entry.get('status_code')} {entry.get('url')} "
                f"({entry.get('mime_type') or 'unknown type'})"
            )

    if not lines:
        return _preview(payload, limit)[0]
    return "\n".join(lines)[:limit]


def _report_for(database: Any, platform_scan_id: str) -> Optional[dict[str, Any]]:
    """The report document the workers wrote for a platform scan.

    The legacy documents carry no link to the platform scan, so the chain
    is followed: the platform scan names the legacy scan, the legacy scan
    names the domain document, and the domain document names the report.
    """
    for legacy in database["scans"].find({"Platform_Scan_Id": platform_scan_id}):
        for domain in database["domains"].find({"Scanid": str(legacy.get("_id"))}):
            report_id = domain.get("report_id")
            if not report_id:
                continue
            report = database["reports"].find_one({"_id": ObjectId(str(report_id))})
            if report:
                return report
    return None


def _produced(database: Any, report: Optional[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """What each worker wrote, grouped by the worker that wrote it."""
    produced: dict[str, list[dict[str, Any]]] = {}
    if report is None:
        return produced

    def add(identity: str, field: str, value: Any) -> None:
        count = _count(value)
        if not count:
            return
        text, truncated = _preview(value)
        produced.setdefault(identity, []).append(
            {
                "field": field,
                "count": count,
                "preview": text,
                "truncated": truncated,
            }
        )

    for path, identity in WORKER_FIELDS:
        add(identity, path, _dig(report, path))

    for link in database["links"].find({"report_id": report.get("_id")}):
        identity = str(link.get("source", ""))
        if identity in LINK_WORKERS:
            add(identity, "links", link.get("Links") or [])

    javascript = []
    for entry in database["js"].find({"report_id": report.get("_id")}):
        javascript.append(str(entry.get("url", "")))
        # The scanner stores what it found in the document of the file it
        # looked at, so the secrets are shown per file.
        secrets = entry.get("Vulns") or []
        if secrets:
            add("B-Hunters-jsscanner", f"secrets in {entry.get('url', '')}", secrets)
    if javascript:
        add("B-Hunters-jsscanner", "js", javascript)

    data = report.get("data") or {}
    for key, identity in DATA_WORKERS.items():
        payload = data.get(key)
        if not payload:
            continue
        produced.setdefault(identity, []).append(
            {
                "field": f"data.{key}",
                "count": 1,
                "preview": _data_preview(payload),
                "truncated": False,
            }
        )

    return produced


@workers_blueprint.route("/workers", methods=["GET"])
def workers() -> Any:
    """What every worker produced, and which ones took part at all."""
    try:
        database = _database()
    except Exception as exc:  # pragma: no cover - the database may be down
        return render_template("workers.html", error=str(exc), scans=[], connected=[])

    connected = _connected_workers()
    consumed = _consumed_tasks()
    scans = []
    for scan in database["platform_scans"].find({}).sort("created_at", -1).limit(20):
        platform_scan_id = str(scan.get("scan_id", ""))
        participation = {
            str(identity): int(count)
            for identity, count in (scan.get("workers") or {}).items()
        }
        report = _report_for(database, platform_scan_id)
        produced = _produced(database, report)

        workers = []
        for identity in connected or sorted(set(participation) | set(produced)):
            output = produced.get(identity, [])
            workers.append(
                {
                    "worker": identity,
                    "tasks": participation.get(identity, 0),
                    "total_tasks": consumed.get(identity, 0),
                    "ran": identity in participation or bool(output),
                    "items": sum(item["count"] for item in output),
                    "output": output,
                }
            )
        scans.append(
            {
                "scan_id": platform_scan_id,
                "name": scan.get("name", ""),
                "status": scan.get("status", ""),
                "created_at": scan.get("created_at", 0),
                "target": ", ".join((scan.get("definition") or {}).get("targets") or []),
                "workers": workers,
            }
        )

    return render_template("workers.html", error="", scans=scans, connected=connected)
