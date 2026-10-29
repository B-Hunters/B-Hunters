"""The durable issues.

A finding belongs to the scan that found it: it is the evidence of one
run, and it disappears with that run.  An issue is the durable thing
behind the finding.  It carries the triage state (is it open, in
progress, fixed?), the observation state (was it seen in the last scan?)
and the history (which scans saw it?).

The identity of an issue is the target it belongs to plus the
fingerprint of the finding, so the same problem found by a later scan of
the same target is the same issue with the same triage state.  A scan
without a target key falls back to its own id: an unkeyed scan never
shares an issue with anything else, because there is no way to tell that
two scans looked at the same thing.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Optional

from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError

from .client import Database
from .repositories import new_id, utcnow

#: The states a triage can be in.
TRIAGE_STATUSES = (
    "open",
    "in_progress",
    "fixed",
    "risk_accepted",
    "false_positive",
    "duplicate",
    "auto_closed",
)

#: The states that a human decided on.  An issue in one of them is never
#: closed automatically: the operator said what it is.
MANUAL_TRIAGE_STATUSES = ("fixed", "risk_accepted", "false_positive")

#: The states an observation can be in.
OBSERVATION_STATUSES = ("observed", "not_observed", "auto_closed")


class IssueRepository:
    """The durable issues and their triage state."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_issues")

    @property
    def _scans(self):
        return self._db.collection("platform_scans")

    # ------------------------------------------------------------------
    # The issue itself
    # ------------------------------------------------------------------
    def upsert_for_finding(
        self,
        *,
        scan_id: str,
        fingerprint: str,
        title: str,
        severity: str,
        vuln_class: str,
    ) -> tuple[dict[str, Any], bool]:
        """Record the issue of a finding.

        The first sighting creates the issue; every later sighting of the
        same fingerprint on the same target updates it and appends the
        scan to its history.  Returns ``(document, created)``.
        """
        now = utcnow()
        target_key = self.target_key_of(scan_id)
        document: dict[str, Any] = {
            "issue_id": new_id(),
            "target_key": target_key,
            "fingerprint": fingerprint,
            "title": title,
            "severity": severity,
            "vuln_class": vuln_class,
            "triage_status": "open",
            "assignee": "",
            "tags": [],
            "due_at": None,
            "observation_status": "observed",
            "consecutive_misses": 0,
            "first_seen_at": now,
            "last_seen_at": now,
            "last_seen_scan_id": scan_id,
            "seen_scans": [scan_id],
            "created_at": now,
            "updated_at": now,
        }
        try:
            self._col.insert_one(document)
        except DuplicateKeyError:
            existing = self._col.find_one({"target_key": target_key, "fingerprint": fingerprint})
            if existing is None:
                raise
            self._col.update_one(
                {"issue_id": existing["issue_id"]},
                {
                    "$set": {
                        "last_seen_at": now,
                        "last_seen_scan_id": scan_id,
                        "severity": severity,
                        "title": title,
                        "updated_at": now,
                    },
                    "$addToSet": {"seen_scans": scan_id},
                },
            )
            stored = self._col.find_one({"issue_id": existing["issue_id"]})
            return (stored or existing), False
        return document, True

    def target_key_of(self, scan_id: str) -> str:
        """The target key of a scan, or the scan id when it has none.

        The fallback keeps an unkeyed scan to itself: without a target
        key there is no way to tell that two scans looked at the same
        thing, so they must not share an issue.
        """
        document = self._scans.find_one({"scan_id": scan_id})
        target_key = str((document or {}).get("target_key", "") or "")
        return target_key or scan_id

    def get(self, issue_id: str) -> Optional[dict[str, Any]]:
        """Return one issue document."""
        return self._col.find_one({"issue_id": issue_id})

    def get_by_key(self, *, target_key: str, fingerprint: str) -> Optional[dict[str, Any]]:
        """Return the issue of a target and a fingerprint, if there is one."""
        return self._col.find_one({"target_key": target_key, "fingerprint": fingerprint})

    def set_triage(
        self,
        issue_id: str,
        *,
        status: str,
        assignee: str = "",
        tags: Sequence[str] = (),
        due_at: float | None = None,
    ) -> bool:
        """Set the triage state of an issue."""
        if status not in TRIAGE_STATUSES:
            raise ValueError(f"invalid triage status '{status}'")
        payload: dict[str, Any] = {
            "triage_status": status,
            "assignee": assignee,
            "tags": list(tags),
            "due_at": due_at,
            "updated_at": utcnow(),
        }
        result = self._col.update_one({"issue_id": issue_id}, {"$set": payload})
        return result.matched_count > 0

    def history(self, issue_id: str) -> list[dict[str, Any]]:
        """The scans that saw the issue, with the state of each scan."""
        document = self._col.find_one({"issue_id": issue_id})
        if document is None:
            return []
        rows: list[dict[str, Any]] = []
        for scan_id in document.get("seen_scans", []):
            scan = self._scans.find_one({"scan_id": scan_id}) or {}
            rows.append(
                {
                    "scan_id": scan_id,
                    "name": scan.get("name", ""),
                    "status": scan.get("status", ""),
                    "created_at": scan.get("created_at"),
                }
            )
        return rows

    def list(
        self,
        *,
        triage_status: str = "",
        severity: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List the issues, the most recently seen first."""
        query: dict[str, Any] = {}
        if triage_status:
            query["triage_status"] = triage_status
        if severity:
            query["severity"] = severity
        cursor = (
            self._col.find(query)
            .sort("last_seen_at", DESCENDING)
            .skip(max(0, offset))
            .limit(max(1, min(limit, 1000)))
        )
        return list(cursor)

    # ------------------------------------------------------------------
    # The observation state
    # ------------------------------------------------------------------
    def apply_scan_observations(
        self,
        *,
        scan_id: str,
        target_key: str,
        observed_fingerprints: Sequence[str],
        auto_close_misses: int = 2,
    ) -> dict[str, int]:
        """Record what a scan saw of the issues of a target.

        An issue that was not seen misses once.  An issue that was missed
        often enough is closed automatically, unless an operator has
        already decided what it is.
        """
        observed = set(observed_fingerprints or ())
        counts = {"observed": 0, "not_observed": 0, "auto_closed": 0}
        now = utcnow()
        limit = max(1, int(auto_close_misses))
        for document in self._col.find({"target_key": target_key}):
            issue_id = document.get("issue_id", "")
            if str(document.get("fingerprint", "")) in observed:
                self._col.update_one(
                    {"issue_id": issue_id},
                    {
                        "$set": {
                            "observation_status": "observed",
                            "consecutive_misses": 0,
                            "last_seen_at": now,
                            "last_seen_scan_id": scan_id,
                            "updated_at": now,
                        }
                    },
                )
                counts["observed"] += 1
                continue
            misses = int(document.get("consecutive_misses", 0)) + 1
            payload: dict[str, Any] = {
                "observation_status": "not_observed",
                "consecutive_misses": misses,
                "updated_at": now,
            }
            triage_status = str(document.get("triage_status", "open"))
            if misses >= limit and triage_status not in MANUAL_TRIAGE_STATUSES:
                payload["observation_status"] = "auto_closed"
                payload["triage_status"] = "auto_closed"
            self._col.update_one({"issue_id": issue_id}, {"$set": payload})
            counts["not_observed"] += 1
            if payload["observation_status"] == "auto_closed":
                counts["auto_closed"] += 1
        return counts
