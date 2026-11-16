"""The asset inventory: one row per URL a scan saw.

The inventory is what the console shows and what the agents read.  It is
keyed by the scan and the normalised URL, so a URL that the crawler, a
worker and the fingerprinters all saw is one row that names all three,
rather than three rows that say the same thing.

Only metadata is stored.  A body or an image byte never reaches this
collection.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from pymongo.errors import DuplicateKeyError

from ..assets import ASSET_KINDS, extension_of, normalise_url

#: The most assets one page of the inventory returns.
MAX_PAGE = 2000


class AssetRepository:
    """The URLs a scan saw."""

    def __init__(self, db: Any) -> None:
        self._db = db

    @property
    def _col(self) -> Any:
        return self._db.collection("platform_assets")

    def upsert(
        self,
        *,
        scan_id: str,
        url: str,
        kind: str,
        scope: str = "first_party",
        host: str = "",
        path: str = "",
        status_code: int = 0,
        content_type: str = "",
        size_bytes: int = 0,
        depth: int = 0,
        source: str = "",
        discovered_from: str = "",
        extension: str = "",
    ) -> tuple[dict[str, Any], bool]:
        """Store one URL, or update the row that already holds it.

        The row is found by the scan and the normalised URL, so the same
        URL is one row however many tools saw it.  A second tool adds its
        name to the sources of that row rather than writing a new one.

        Returns the document and whether it was created.
        """
        canonical = normalise_url(url) or (url or "").strip()
        if not canonical:
            return {}, False

        now = time.time()
        existing = self._col.find_one({"scan_id": scan_id, "url": canonical})
        if existing is None:
            document = {
                "asset_id": uuid.uuid4().hex,
                "scan_id": scan_id,
                "url": canonical,
                "host": host or _host_of(canonical),
                "path": path or _path_of(canonical),
                "kind": kind or "other",
                "scope": scope or "first_party",
                "status_code": int(status_code),
                "content_type": content_type,
                "size_bytes": int(size_bytes),
                "depth": int(depth),
                "sources": [source] if source else [],
                "source": source,
                "discovered_from": discovered_from,
                "extension": extension or extension_of(canonical),
                "first_seen_at": now,
                "last_seen_at": now,
            }
            self._col.insert_one(dict(document))
            return document, True

        changes = self._changes_for(
            existing,
            kind=kind,
            status_code=status_code,
            content_type=content_type,
            size_bytes=size_bytes,
            host=host,
            path=path,
            source=source,
            discovered_from=discovered_from,
            extension=extension,
            now=now,
        )
        if changes:
            self._col.update_one({"_id": existing["_id"]}, {"$set": changes})
        document = {key: value for key, value in existing.items() if key != "_id"}
        document.update(changes)
        return document, False

    def get(self, asset_id: str) -> dict[str, Any] | None:
        """The asset with the given identifier."""
        document = self._col.find_one({"asset_id": asset_id})
        if document is None:
            return None
        return {key: value for key, value in document.items() if key != "_id"}

    def list_for_scan(
        self,
        scan_id: str,
        *,
        kind: str = "",
        scope: str = "",
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """The assets of a scan, sorted by URL.

        The page is capped: a scan that found thousands of URLs must not
        pull all of them into one answer.
        """
        query: dict[str, Any] = {"scan_id": scan_id}
        if kind:
            query["kind"] = kind
        if scope:
            query["scope"] = scope
        capped = min(max(1, int(limit)), MAX_PAGE)
        cursor = self._col.find(query).sort("url", 1).skip(max(0, int(offset))).limit(capped)
        return [{key: value for key, value in document.items() if key != "_id"} for document in cursor]

    def hosts_across_scans(
        self,
        *,
        host: str = "",
        kind: str = "",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Every host the platform has seen, across every scan.

        A host that was seen in two scans is one host: it is listed
        once, with the scans it was seen in, the URLs that were found
        on it, and when it was first and last seen.
        """
        query: dict[str, Any] = {}
        if host:
            query["host"] = host
        if kind:
            query["kind"] = kind
        pipeline = [
            {"$match": query},
            {
                "$group": {
                    "_id": "$host",
                    "urls": {"$addToSet": "$url"},
                    "scans": {"$addToSet": "$scan_id"},
                    "first_seen": {"$min": "$first_seen_at"},
                    "last_seen": {"$max": "$last_seen_at"},
                }
            },
            {"$sort": {"last_seen": -1}},
            {"$limit": max(1, min(int(limit), 2000))},
        ]
        rows: list[dict[str, Any]] = []
        for entry in self._col.aggregate(pipeline):
            rows.append(
                {
                    "host": entry.get("_id", ""),
                    "urls": sorted(str(url) for url in entry.get("urls", []) if url),
                    "scans": sorted(str(scan) for scan in entry.get("scans", []) if scan),
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen"),
                    "open_findings": self._open_findings(entry.get("_id", "")),
                    "technologies": self._technologies(entry.get("_id", "")),
                    "ports": self._ports(entry.get("_id", "")),
                }
            )
        return rows

    def _open_findings(self, host: str) -> int:
        """The findings that are still open on a host."""
        if not host:
            return 0
        return int(
            self._db.collection("platform_findings").count_documents(
                {"host": host, "verification_status": {"$in": ["confirmed", "likely", "unverified"]}}
            )
        )

    def _technologies(self, host: str) -> list[str]:
        """The technologies the platform identified on a host."""
        if not host:
            return []
        names = {
            str(row.get("title", ""))
            for row in self._db.collection("platform_findings").find(
                {"host": host, "detection_source": "technology"}
            )
        }
        return sorted(name for name in names if name)

    def _ports(self, host: str) -> list[int]:
        """The ports the platform saw on a host."""
        if not host:
            return []
        ports = set()
        for row in self._db.collection("platform_services").find({"host": host}):
            port = row.get("port")
            if port:
                ports.add(int(port))
        return sorted(ports)

    def counts_for_scan(self, scan_id: str) -> dict[str, int]:
        """How many assets of a scan there are per kind."""
        counts: dict[str, int] = dict.fromkeys(ASSET_KINDS, 0)
        pipeline = [
            {"$match": {"scan_id": scan_id}},
            {"$group": {"_id": "$kind", "count": {"$sum": 1}}},
        ]
        for entry in self._col.aggregate(pipeline):
            kind = str(entry.get("_id") or "other")
            counts[kind] = counts.get(kind, 0) + int(entry.get("count", 0))
        return counts

    def count(self, scan_id: str = "") -> int:
        """How many assets there are, of a scan or of every scan."""
        query: dict[str, Any] = {"scan_id": scan_id} if scan_id else {}
        return int(self._col.count_documents(query))

    @staticmethod
    def _changes_for(
        existing: dict[str, Any],
        *,
        kind: str,
        status_code: int,
        content_type: str,
        size_bytes: int,
        host: str,
        path: str,
        source: str,
        discovered_from: str,
        extension: str,
        now: float,
    ) -> dict[str, Any]:
        """What a second look at a known URL changes.

        What the row already knows is kept: the crawler records a URL
        before it has fetched it, and the fetch fills in the status, the
        content type and the size.  A tool that sees the URL again only
        adds its name to the sources.
        """
        changes: dict[str, Any] = {"last_seen_at": now}

        sources = [str(item) for item in (existing.get("sources") or [])]
        if source and source not in sources:
            sources.append(source)
            changes["sources"] = sources

        if not existing.get("status_code") and status_code:
            changes["status_code"] = int(status_code)
        if not existing.get("content_type") and content_type:
            changes["content_type"] = content_type
        if not existing.get("size_bytes") and size_bytes:
            changes["size_bytes"] = int(size_bytes)
        if existing.get("kind") in ("", "other") and kind and kind != "other":
            changes["kind"] = kind
        if not existing.get("host") and host:
            changes["host"] = host
        if not existing.get("path") and path:
            changes["path"] = path
        if not existing.get("source") and source:
            changes["source"] = source
        if not existing.get("discovered_from") and discovered_from:
            changes["discovered_from"] = discovered_from
        if not existing.get("extension") and extension:
            changes["extension"] = extension
        return changes


class WorkerRunRepository:
    """What every scanner worker did in one scan.

    A worker that finds nothing writes nothing anywhere, so the platform
    cannot tell "ran and found nothing" from "never ran" by looking at
    the output.  This repository holds the facts that tell the two
    apart: which workers were online when the scan started, how many
    tasks each of them consumed, how many findings they produced and how
    many of their tasks crashed.

    The row is keyed by the scan and the worker, so a scan has one row
    per worker however often the outcome is recorded.
    """

    def __init__(self, db: Any) -> None:
        self._db = db

    @property
    def _col(self) -> Any:
        return self._db.collection("platform_worker_runs")

    def record(
        self,
        *,
        scan_id: str,
        worker: str,
        tasks: int = 0,
        findings: int = 0,
        crashed_tasks: int = 0,
        connected: bool = False,
        expected_version: str = "",
        candidates: int = 0,
    ) -> dict[str, Any]:
        """Record what one worker did in one scan.

        The record is merged into the row that is already there: the
        highest task count is kept - a snapshot taken before the work
        must not lower the count the work produced - and the crashed
        tasks are added, because a crash is an event rather than a
        state.  A worker that was seen to be online stays connected.

        ``candidates`` is how many of the crawler's URLs carry a
        parameter, which is how many a path scanner could test.  It is
        the difference between a scanner that tested everything and
        found nothing and one that was handed nothing to test.
        """
        name = str(worker or "").strip()
        if not name:
            return {}

        now = time.time()
        existing = self._col.find_one({"scan_id": scan_id, "worker": name})
        if existing is None:
            document = {
                "scan_id": scan_id,
                "worker": name,
                "tasks": int(tasks),
                "findings": int(findings),
                "crashed_tasks": int(crashed_tasks),
                "connected": bool(connected),
                "expected_version": str(expected_version or ""),
                "candidates": int(candidates),
                "first_seen_at": now,
                "last_seen_at": now,
            }
            try:
                self._col.insert_one(dict(document))
            except DuplicateKeyError:
                # Another writer created the row first; the update below
                # merges this record into it.
                existing = self._col.find_one({"scan_id": scan_id, "worker": name})
            else:
                return document

        changes: dict[str, Any] = {
            "tasks": max(int(existing.get("tasks", 0) or 0), int(tasks)),
            "findings": max(int(existing.get("findings", 0) or 0), int(findings)),
            "crashed_tasks": int(existing.get("crashed_tasks", 0) or 0) + int(crashed_tasks),
            "connected": bool(existing.get("connected")) or bool(connected),
            "candidates": max(int(existing.get("candidates", 0) or 0), int(candidates)),
            "last_seen_at": now,
        }
        if expected_version and not existing.get("expected_version"):
            changes["expected_version"] = str(expected_version)
        self._col.update_one({"_id": existing["_id"]}, {"$set": changes})
        document = {key: value for key, value in existing.items() if key != "_id"}
        document.update(changes)
        return document

    def list_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """What every worker did in a scan, one row per worker."""
        cursor = self._col.find({"scan_id": scan_id}).sort("worker", 1)
        return [{key: value for key, value in document.items() if key != "_id"} for document in cursor]

    def snapshot_connection(self, scan_id: str, identities: Sequence[str]) -> None:
        """Record the workers that were online when the scan started.

        A worker that was online but never dispatched a task is a
        different fact from a worker that was not online at all, so the
        snapshot is kept even when nothing else is known about it.
        """
        for identity in identities:
            name = str(identity or "").strip()
            if not name:
                continue
            self.record(scan_id=scan_id, worker=name, connected=True)


def _host_of(url: str) -> str:
    """The host of a URL."""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _path_of(url: str) -> str:
    """The path of a URL."""
    try:
        return urlsplit(url).path
    except ValueError:
        return ""
