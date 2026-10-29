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
        """Save what the workers produced for a scan, replacing what was there.

        The replacement matters: a scan that is resumed writes into the
        same report again, and the items that are gone must not linger.
        """
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
