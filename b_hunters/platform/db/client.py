"""MongoDB access layer for the B-Hunters platform.

B-Hunters already stores its scan results in MongoDB, so the platform keeps
using MongoDB rather than introducing a second database.  The legacy
collections (``scans``, ``domains``, ``reports``, ``js``) are left exactly
as they are so that the existing workers and the ``report`` CLI command
keep working; the platform adds its own namespaced collections.

Every collection the platform owns is listed in :data:`PLATFORM_COLLECTIONS`
so that index creation, migrations and the retention job have a single
source of truth.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Optional

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.database import Database as MongoDatabase
from pymongo.errors import CollectionInvalid, OperationFailure, PyMongoError

from ..settings import Settings, get_settings

log = logging.getLogger(__name__)

#: Collections owned by the platform (the legacy ones are untouched).
PLATFORM_COLLECTIONS = (
    "platform_users",
    "platform_sessions",
    "platform_audit",
    "platform_providers",
    "platform_agent_definitions",
    "platform_scans",
    "platform_scan_events",
    "platform_tasks",
    "platform_agents",
    "platform_messages",
    "platform_tool_calls",
    "platform_findings",
    "platform_evidence",
    "platform_services",
    "platform_artifacts",
    "platform_benchmarks",
    "platform_benchmark_runs",
    "platform_benchmark_results",
    "platform_migrations",
    "platform_counters",
    "platform_jobs",
    "platform_target_locks",
    "platform_identities",
    "platform_issues",
    "platform_findings",
    "platform_runner_heartbeats",
    "platform_assets",
    "platform_worker_runs",
)


@dataclass(frozen=True)
class IndexSpec:
    """Declarative index definition."""

    keys: list[tuple[str, int]]
    name: str
    unique: bool = False
    sparse: bool = False
    expire_after_seconds: Optional[int] = None
    partial_filter: Optional[dict[str, Any]] = None


#: Index definitions applied by :func:`ensure_indexes`.
INDEXES: dict[str, list[IndexSpec]] = {
    "platform_users": [
        IndexSpec([("username", ASCENDING)], "uniq_username", unique=True),
        IndexSpec([("role", ASCENDING)], "by_role"),
        IndexSpec([("active", ASCENDING)], "by_active"),
    ],
    "platform_sessions": [
        IndexSpec([("session_id_hash", ASCENDING)], "uniq_session_hash", unique=True),
        IndexSpec([("user_id", ASCENDING)], "by_user"),
        IndexSpec([("expires_at", ASCENDING)], "ttl_expires", expire_after_seconds=0),
    ],
    "platform_audit": [
        IndexSpec([("at", DESCENDING)], "by_at"),
        IndexSpec([("actor", ASCENDING)], "by_actor"),
        IndexSpec([("action", ASCENDING)], "by_action"),
        IndexSpec([("target_type", ASCENDING), ("target_id", ASCENDING)], "by_target"),
    ],
    "platform_providers": [
        IndexSpec([("name", ASCENDING)], "uniq_provider_name", unique=True),
        IndexSpec([("enabled", ASCENDING)], "by_enabled"),
    ],
    "platform_agent_definitions": [
        IndexSpec([("role", ASCENDING), ("version", DESCENDING)], "by_role_version"),
        IndexSpec([("name", ASCENDING), ("version", DESCENDING)], "uniq_name_version", unique=True),
        IndexSpec([("enabled", ASCENDING)], "by_enabled"),
    ],
    "platform_scans": [
        IndexSpec([("status", ASCENDING), ("created_at", DESCENDING)], "by_status_created"),
        IndexSpec([("created_by", ASCENDING)], "by_creator"),
        IndexSpec([("name", ASCENDING)], "by_name"),
        IndexSpec([("targets", ASCENDING)], "by_targets"),
        IndexSpec([("updated_at", DESCENDING)], "by_updated"),
    ],
    "platform_scan_events": [
        IndexSpec([("event_id", ASCENDING)], "uniq_event_id", unique=True),
        IndexSpec([("scan_id", ASCENDING), ("seq", ASCENDING)], "by_scan_seq"),
        IndexSpec([("scan_id", ASCENDING), ("at", DESCENDING)], "by_scan_at"),
        IndexSpec([("kind", ASCENDING)], "by_kind"),
    ],
    "platform_tasks": [
        IndexSpec([("scan_id", ASCENDING)], "by_scan"),
        IndexSpec([("scan_id", ASCENDING), ("status", ASCENDING)], "by_scan_status"),
        IndexSpec([("status", ASCENDING), ("updated_at", ASCENDING)], "by_status"),
        IndexSpec([("depends_on", ASCENDING)], "by_depends"),
        IndexSpec([("karton_task_uid", ASCENDING)], "by_karton_uid"),
    ],
    "platform_agents": [
        IndexSpec([("scan_id", ASCENDING)], "by_scan"),
        IndexSpec([("scan_id", ASCENDING), ("role", ASCENDING)], "by_scan_role"),
        IndexSpec([("status", ASCENDING)], "by_status"),
        IndexSpec([("last_seen_at", DESCENDING)], "by_last_seen"),
    ],
    "platform_messages": [
        IndexSpec([("scan_id", ASCENDING), ("seq", ASCENDING)], "by_scan_seq"),
        IndexSpec([("scan_id", ASCENDING), ("task_id", ASCENDING)], "by_task"),
        IndexSpec([("kind", ASCENDING)], "by_kind"),
    ],
    "platform_tool_calls": [
        IndexSpec([("scan_id", ASCENDING), ("at", DESCENDING)], "by_scan_at"),
        IndexSpec([("agent_role", ASCENDING)], "by_role"),
        IndexSpec([("tool", ASCENDING)], "by_tool"),
    ],
    "platform_findings": [
        IndexSpec([("scan_id", ASCENDING), ("fingerprint", ASCENDING)], "uniq_scan_fingerprint", unique=True),
        IndexSpec([("scan_id", ASCENDING), ("severity", ASCENDING)], "by_scan_severity"),
        IndexSpec([("scan_id", ASCENDING), ("verification_status", ASCENDING)], "by_scan_verification"),
        IndexSpec([("scan_id", ASCENDING), ("vuln_class", ASCENDING)], "by_scan_class"),
        IndexSpec([("host", ASCENDING)], "by_host"),
        IndexSpec([("first_seen_at", ASCENDING)], "by_first_seen"),
        IndexSpec([("confidence", ASCENDING)], "by_confidence"),
        IndexSpec([("detected_by", ASCENDING)], "by_detected_by"),
        IndexSpec([("issue_id", ASCENDING)], "by_issue"),
    ],
    "platform_evidence": [
        IndexSpec([("finding_id", ASCENDING)], "by_finding"),
        IndexSpec([("scan_id", ASCENDING)], "by_scan"),
    ],
    "platform_services": [
        IndexSpec([("scan_id", ASCENDING), ("url", ASCENDING)], "by_scan_url"),
        IndexSpec([("url", ASCENDING)], "by_url"),
        IndexSpec([("scan_id", ASCENDING), ("host", ASCENDING)], "by_scan_host"),
        IndexSpec([("services.name", ASCENDING)], "by_service_name"),
        IndexSpec([("services.version", ASCENDING)], "by_service_version"),
    ],
    "platform_artifacts": [
        IndexSpec([("scan_id", ASCENDING)], "by_scan"),
        IndexSpec([("sha256", ASCENDING)], "by_sha"),
        IndexSpec([("created_at", ASCENDING)], "ttl_created", expire_after_seconds=None),
    ],
    "platform_benchmarks": [
        IndexSpec([("slug", ASCENDING)], "uniq_slug", unique=True),
    ],
    "platform_benchmark_runs": [
        IndexSpec([("benchmark_id", ASCENDING), ("started_at", DESCENDING)], "by_bench"),
        IndexSpec([("scan_id", ASCENDING)], "by_scan"),
    ],
    "platform_benchmark_results": [
        IndexSpec([("run_id", ASCENDING), ("test_id", ASCENDING)], "uniq_run_test", unique=True),
        IndexSpec([("run_id", ASCENDING), ("outcome", ASCENDING)], "by_run_outcome"),
    ],
    "platform_counters": [
        IndexSpec([("key", ASCENDING)], "uniq_counter_key", unique=True),
    ],
    "platform_jobs": [
        IndexSpec([("job_id", ASCENDING)], "uniq_job_id", unique=True),
        IndexSpec(
            [("status", ASCENDING), ("available_at", ASCENDING), ("priority", DESCENDING)],
            "by_status_available",
        ),
        IndexSpec([("status", ASCENDING), ("lease_expires_at", ASCENDING)], "by_status_lease"),
        IndexSpec([("kind", ASCENDING), ("created_at", ASCENDING)], "by_kind_created"),
        IndexSpec([("payload.scan_id", ASCENDING)], "by_scan_id"),
    ],
    "platform_target_locks": [
        IndexSpec([("target_key", ASCENDING)], "uniq_target_key", unique=True),
        IndexSpec([("expires_at", ASCENDING)], "ttl_expires", expire_after_seconds=0),
    ],
    "platform_identities": [
        IndexSpec([("identity_id", ASCENDING)], "uniq_identity_id", unique=True),
        IndexSpec([("name", ASCENDING)], "by_name"),
    ],
    "platform_issues": [
        IndexSpec(
            [("target_key", ASCENDING), ("fingerprint", ASCENDING)],
            "uniq_target_fingerprint",
            unique=True,
        ),
        IndexSpec([("triage_status", ASCENDING), ("severity", ASCENDING)], "by_triage_severity"),
        IndexSpec([("last_seen_at", DESCENDING)], "by_last_seen"),
    ],
    "platform_runner_heartbeats": [
        IndexSpec([("runner_id", ASCENDING)], "uniq_runner_id", unique=True),
        IndexSpec([("last_seen_at", DESCENDING)], "by_last_seen"),
    ],
    "platform_assets": [
        IndexSpec([("scan_id", ASCENDING), ("url", ASCENDING)], "uniq_scan_url", unique=True),
        IndexSpec([("scan_id", ASCENDING), ("kind", ASCENDING)], "by_scan_kind"),
        IndexSpec([("host", ASCENDING)], "by_host"),
        IndexSpec([("kind", ASCENDING), ("last_seen_at", DESCENDING)], "by_kind_last_seen"),
    ],
    "platform_worker_runs": [
        IndexSpec([("scan_id", ASCENDING), ("worker", ASCENDING)], "uniq_scan_worker", unique=True),
        IndexSpec([("scan_id", ASCENDING), ("crashed_tasks", DESCENDING)], "by_scan_crashed"),
    ],
}


class Database:
    """Thin wrapper around a MongoDB database with lazy connection."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client: Optional[MongoClient] = None
        self._db: Optional[MongoDatabase] = None
        # Reentrant: the ``db`` property calls ``client`` while already
        # holding this lock, so a plain Lock would self-deadlock.
        self._lock = threading.RLock()
        self._indexed = False

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    @property
    def client(self) -> MongoClient:
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = MongoClient(
                        self.settings.mongo_uri,
                        serverSelectionTimeoutMS=self.settings.mongo_timeout_ms,
                        connectTimeoutMS=self.settings.mongo_timeout_ms,
                        appname="b-hunters-platform",
                    )
        return self._client

    @property
    def db(self) -> MongoDatabase:
        if self._db is None:
            with self._lock:
                if self._db is None:
                    self._db = self.client[self.settings.mongo_db]
        return self._db

    def collection(self, name: str) -> Collection:
        """Return a platform collection (or a legacy one if named directly)."""
        return self.db[name]

    def ping(self) -> bool:
        """Return ``True`` when the database answers a ping."""
        try:
            self.client.admin.command("ping")
            return True
        except PyMongoError:
            return False

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
            self._db = None

    # ------------------------------------------------------------------
    # Index / migration management
    # ------------------------------------------------------------------
    def ensure_indexes(self) -> dict[str, list[str]]:
        """Create the platform indexes.  Safe to call repeatedly."""
        created: dict[str, list[str]] = {}
        for collection_name, specs in INDEXES.items():
            names: list[str] = []
            for spec in specs:
                options: dict[str, Any] = {"name": spec.name, "unique": spec.unique}
                if spec.sparse:
                    options["sparse"] = True
                # MongoDB rejects a null expireAfterSeconds / partialFilterExpression.
                if spec.expire_after_seconds is not None:
                    options["expireAfterSeconds"] = spec.expire_after_seconds
                if spec.partial_filter is not None:
                    options["partialFilterExpression"] = spec.partial_filter
                try:
                    self.db[collection_name].create_index(spec.keys, **options)
                    names.append(spec.name)
                except (OperationFailure, CollectionInvalid) as exc:
                    log.warning("Could not create index %s on %s: %s", spec.name, collection_name, exc)
            created[collection_name] = names
        self._indexed = True
        return created

    def ensure_indexes_once(self) -> None:
        if not self._indexed:
            self.ensure_indexes()

    # ------------------------------------------------------------------
    # Idempotency helpers
    # ------------------------------------------------------------------
    def claim_event(self, event_id: str, document: dict[str, Any]) -> bool:
        """Insert an event exactly once.

        Returns ``True`` when the event was newly written and ``False`` when
        it had already been recorded.  The unique index on ``event_id`` makes
        this safe against concurrent writers and worker retries.
        """
        try:
            self.db["platform_scan_events"].insert_one(document)
            return True
        except OperationFailure as exc:
            if "duplicate" in str(exc).lower() or getattr(exc, "code", None) == 11000:
                return False
            raise

    def next_sequence(self, key: str, increment: int = 1) -> int:
        """Atomically increment and return a named counter."""
        result = self.db["platform_counters"].find_one_and_update(
            {"key": key},
            {"$inc": {"value": increment}},
            upsert=True,
            return_document=True,
        )
        return int(result["value"]) if result else increment

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------
    def apply_retention(self, *, event_retention_days: int, artifact_retention_days: int) -> dict[str, int]:
        """Delete expired events and artefacts.  Returns the removal counts."""
        removed: dict[str, int] = {}
        now = time.time()
        event_cutoff = now - (event_retention_days * 86400)
        artifact_cutoff = now - (artifact_retention_days * 86400)
        removed["events"] = (
            self.db["platform_scan_events"].delete_many({"at": {"$lt": event_cutoff}}).deleted_count
        )
        removed["artifacts"] = (
            self.db["platform_artifacts"].delete_many({"created_at": {"$lt": artifact_cutoff}}).deleted_count
        )
        removed["sessions"] = (
            self.db["platform_sessions"].delete_many({"expires_at": {"$lt": now}}).deleted_count
        )
        return removed


_default_db: Optional[Database] = None
_default_lock = threading.Lock()


def get_database(settings: Settings | None = None) -> Database:
    """Return the process-wide database handle."""
    global _default_db
    if settings is not None:
        return Database(settings)
    if _default_db is None:
        with _default_lock:
            if _default_db is None:
                _default_db = Database()
    return _default_db


def reset_database() -> None:
    """Drop the cached database handle (used by tests)."""
    global _default_db
    with _default_lock:
        if _default_db is not None:
            _default_db.close()
        _default_db = None


def iter_collection(database: Database, name: str, batch_size: int = 500) -> Iterable[dict[str, Any]]:
    """Iterate a collection in batches to avoid loading everything in memory."""
    cursor = database.db[name].find({}).batch_size(batch_size)
    yield from cursor
