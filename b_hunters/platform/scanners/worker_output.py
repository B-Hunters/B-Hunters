"""What every scanner worker did, and what it found.

The console scan starts seventeen worker containers at once, so a worker
that finds nothing and a worker that never ran look the same.  This
module separates them.

A worker writes into the legacy documents: the ``reports`` document for
the report fields it owns, the ``links`` collection for the URLs it
crawled, the ``js`` collection for the scripts it looked at, and the
``data`` document for the payload that does not fit anywhere else.  A
worker that found nothing writes nothing anywhere, so the task counters
Karton keeps are what says whether it ran at all.

Three states, not two:

* a worker with a task count and output ran and found something;
* a worker with a task count and no output ran and found nothing;
* a worker without either never received a task.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from bson import ObjectId

from ...bhunter import BHunters

#: The report fields each worker owns, and the identity it registers under.
WORKER_FIELDS: tuple[tuple[str, str], ...] = (
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
)

#: The workers that write into the ``links`` collection.
LINK_WORKERS: tuple[str, ...] = (
    "B-Hunters-Katana",
    "B-Hunters-ParamSpider",
    "B-Hunters-GoSpider",
)

#: The workers that write their result into the report's ``data`` document.
DATA_WORKERS: dict[str, str] = {
    "gowitness": "B-Hunters-GoWitness",
}

#: Every worker of the platform, in the order the console shows them.
WORKER_IDENTITIES: tuple[str, ...] = (
    "B-Hunters-DalFox",
    "B-Hunters-GoSpider",
    "B-Hunters-GoWitness",
    "B-Hunters-Katana",
    "B-Hunters-Nmap",
    "B-Hunters-Nuclei",
    "B-Hunters-ParamSpider",
    "B-Hunters-SQLMap",
    "B-Hunters-SSTI-Checker",
    "B-Hunters-dirsearch",
    "B-Hunters-getjs",
    "B-Hunters-jsscanner",
    "B-Hunters-subrecon",
    "B-Hunters-wapiti",
    "B-Hunters-wayback",
    "B-Hunters-web-technology",
    "B-Hunters-xray",
)


def count_items(value: Any) -> int:
    """How many items a report field holds.

    Two shapes need care.  MongoDB's ``$push`` appends an array as a
    single element, so a worker with no result leaves ``[[]]`` behind;
    and an empty string is no result, not one.
    """
    if value is None:
        return 0
    if isinstance(value, str):
        return 1 if value.strip() else 0
    if isinstance(value, (list, tuple, set)):
        if len(value) == 1 and isinstance(value[0], (list, tuple)):
            return count_items(value[0])
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 1


def values_of(value: Any) -> list[str]:
    """The individual items of a written value.

    A worker writes a list of URLs or a list of paths as one entry.  The
    platform keeps the items apart, so that they can be listed and scanned
    again.
    """
    if isinstance(value, dict):
        # A finding is one thing the worker wrote, however many fields it
        # has.  Splitting it into its fields would turn one finding into
        # dozens of rows that say nothing.
        return [json.dumps(value, default=str)[:2000]]
    if isinstance(value, (list, tuple)):
        # MongoDB's ``$push`` appends an array as a single element, so a
        # worker with no result leaves ``[[]]`` behind.
        if len(value) == 1 and isinstance(value[0], (list, tuple)):
            return values_of(value[0])
        items: list[str] = []
        for entry in value:
            items.extend(values_of(entry))
        return items
    text = str(value).strip()
    return [text] if text else []


def dig(document: Any, path: str) -> Any:
    """Read a dotted path out of a document."""
    current = document
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


#: How much of a worker's output is rendered.  Nothing is dropped
#: silently: the console says when there is more.
PREVIEW_LIMIT = 20000


def preview(value: Any, limit: int = PREVIEW_LIMIT) -> tuple[str, bool]:
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


def data_preview(payload: dict[str, Any], limit: int = 4000) -> str:
    """A readable rendering of the payload a worker stored under ``data``."""
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
        names = [str(entry.get("value") if isinstance(entry, dict) else entry) for entry in technologies]
        lines.append("technologies: " + ", ".join(names))

    for entry in (payload.get("headers") or [])[:12]:
        if isinstance(entry, dict):
            lines.append(f"header: {entry.get('key')}: {entry.get('value')}")
        else:
            lines.append(f"header: {entry}")

    for entry in (payload.get("network") or [])[:12]:
        if isinstance(entry, dict):
            lines.append(
                f"request: {entry.get('status_code')} {entry.get('url')} "
                f"({entry.get('mime_type') or 'unknown type'})"
            )

    if not lines:
        return preview(payload, limit)[0]
    return "\n".join(lines)[:limit]


def report_for_scan(database: Any, platform_scan_id: str) -> tuple[Optional[str], dict[str, Any]]:
    """The report document the workers wrote for a platform scan.

    The legacy documents carry no link to the platform scan, so the chain
    is followed: the platform scan names the legacy scan, the legacy scan
    names the domain document, and the domain document names the report.
    """
    for legacy in database.collection("scans").find({"Platform_Scan_Id": platform_scan_id}):
        for domain in database.collection("domains").find({"Scanid": str(legacy.get("_id"))}):
            report_id = domain.get("report_id")
            if not report_id:
                continue
            report = database.collection("reports").find_one({"_id": ObjectId(str(report_id))})
            if report:
                return str(report_id), report
    return None, {}


def produced(database: Any, report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """What each worker wrote, grouped by the worker that wrote it."""
    output: dict[str, list[dict[str, Any]]] = {}

    def add(identity: str, field: str, value: Any) -> None:
        items = count_items(value)
        if not items:
            return
        text, truncated = preview(value)
        output.setdefault(identity, []).append(
            {
                "field": field,
                "count": items,
                "preview": text,
                "truncated": truncated,
                "values": values_of(value),
            }
        )

    for path, identity in WORKER_FIELDS:
        add(identity, path, dig(report, path))

    report_id = report.get("_id")
    for link in database.collection("links").find({"report_id": report_id}):
        identity = str(link.get("source", ""))
        if identity in LINK_WORKERS:
            add(identity, "links", link.get("Links") or [])

    javascript: list[str] = []
    for entry in database.collection("js").find({"report_id": report_id}):
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
        output.setdefault(identity, []).append(
            {
                "field": f"data.{key}",
                "count": 1,
                "preview": data_preview(payload),
                "truncated": False,
            }
        )

    return output


def candidates(database: Any, report: dict[str, Any]) -> dict[str, int]:
    """What the crawlers found, and how much of it a scanner can test.

    A path scanner tests the URLs that carry parameters.  The third-party
    URLs are counted as crawled - they are part of the page - but a
    scanner filters them out before it starts, so they are not counted as
    candidates.
    """
    target = str(report.get("Domain") or "")
    crawled = 0
    with_parameters = 0
    for link in database.collection("links").find({"report_id": report.get("_id")}):
        for url in link.get("Links") or []:
            crawled += 1
            if "?" in str(url) and BHunters.is_on_target(target, url):
                with_parameters += 1
    return {"crawled_urls": crawled, "urls_with_parameters": with_parameters}


def scanner_report(
    database: Any,
    platform_scan_id: str,
    *,
    participation: Optional[dict[str, int]] = None,
    live: Optional[dict[str, int]] = None,
    connected: Optional[list[str]] = None,
) -> dict[str, Any]:
    """The per-worker view of a scan.

    ``participation`` is the task count the platform recorded for the
    scan, ``live`` the counters Karton keeps across every scan, and
    ``connected`` the workers that are bound to the router right now.
    """
    report_id, report = report_for_scan(database, platform_scan_id)
    output = produced(database, report) if report else {}
    participation = participation or {}
    live = live or {}

    identities = list(WORKER_IDENTITIES)
    for identity in sorted(set(participation) | set(output) | set(connected or [])):
        if identity not in identities:
            identities.append(identity)

    # The crawlers' haul, and how much of it a path scanner can use.  The
    # scanners that test parameters need URLs that carry parameters; the
    # page of the target usually has none.
    counts = (
        candidates(database, report)
        if report
        else {
            "crawled_urls": 0,
            "urls_with_parameters": 0,
        }
    )

    workers = []
    for identity in identities:
        found = output.get(identity, [])
        tasks = int(participation.get(identity, 0))
        workers.append(
            {
                "worker": identity,
                "tasks": tasks,
                "live_tasks": int(live.get(identity, 0)),
                "items": sum(item["count"] for item in found),
                "candidates": counts["urls_with_parameters"],
                "output": found,
                "status": _status(tasks, found, int(live.get(identity, 0))),
            }
        )

    return {
        "scan_id": platform_scan_id,
        "report_id": report_id or "",
        "workers": workers,
        "summary": counts,
    }


def _status(tasks: int, found: list[dict[str, Any]], live_tasks: int) -> str:
    """What the console says about one worker."""
    if found:
        return "found"
    if tasks:
        return "ran, found nothing"
    if live_tasks:
        return "running"
    return "did not run"
