"""Repository layer.

Repositories wrap MongoDB access with the domain semantics the API and the
agent runtime need: lifecycle transitions, idempotent writes, filtering and
aggregation.  Nothing above this layer touches pymongo directly.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError

from ..security.passwords import hash_password, needs_rehash
from ..security.sessions import hash_session_id
from .client import Database

SEVERITIES = ("critical", "high", "medium", "low", "info")
VERIFICATION_STATUSES = ("confirmed", "likely", "unverified", "inconclusive", "rejected")

SCAN_STATUSES = (
    "draft",
    "queued",
    "running",
    "paused",
    "stopping",
    "completed",
    "failed",
    "cancelled",
)

TASK_STATUSES = ("pending", "ready", "running", "succeeded", "failed", "cancelled", "blocked")


def utcnow() -> float:
    return time.time()


def new_id() -> str:
    return str(uuid.uuid4())


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return None


class RepositoryError(Exception):
    """Raised for repository level failures."""


class NotFound(RepositoryError):
    """Raised when an entity does not exist."""


# ----------------------------------------------------------------------
# Users and sessions
# ----------------------------------------------------------------------
class UserRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_users")

    def create(
        self,
        *,
        username: str,
        password: str,
        role: str = "viewer",
        email: str = "",
        display_name: str = "",
    ) -> dict[str, Any]:
        document = {
            "user_id": new_id(),
            "username": username.strip().lower(),
            "email": email.strip().lower(),
            "display_name": display_name or username,
            "role": role,
            "password_hash": hash_password(password),
            "active": True,
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "last_login_at": None,
        }
        try:
            self._col.insert_one(document)
        except DuplicateKeyError as exc:
            raise RepositoryError(f"username '{username}' already exists") from exc
        return document

    def get_by_username(self, username: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"username": (username or "").strip().lower()})

    def get_by_id(self, user_id: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"user_id": user_id})

    def list_users(self) -> list[dict[str, Any]]:
        return list(self._col.find({}).sort("username", 1))

    def set_password(self, user_id: str, password: str) -> bool:
        result = self._col.update_one(
            {"user_id": user_id},
            {"$set": {"password_hash": hash_password(password), "updated_at": utcnow()}},
        )
        return result.matched_count > 0

    def update(self, user_id: str, changes: dict[str, Any]) -> bool:
        allowed = {"role", "active", "email", "display_name"}
        payload = {k: v for k, v in changes.items() if k in allowed}
        if not payload:
            return False
        payload["updated_at"] = utcnow()
        result = self._col.update_one({"user_id": user_id}, {"$set": payload})
        return result.matched_count > 0

    def record_login(self, user_id: str) -> None:
        self._col.update_one({"user_id": user_id}, {"$set": {"last_login_at": utcnow()}})

    def needs_rehash(self, user: dict[str, Any]) -> bool:
        return needs_rehash(user.get("password_hash", ""))

    def public(self, user: dict[str, Any]) -> dict[str, Any]:
        return {
            "user_id": user.get("user_id"),
            "username": user.get("username"),
            "email": user.get("email", ""),
            "display_name": user.get("display_name", ""),
            "role": user.get("role", "viewer"),
            "active": bool(user.get("active", True)),
            "created_at": _iso(user.get("created_at")) or user.get("created_at"),
            "last_login_at": _iso(user.get("last_login_at")) or user.get("last_login_at"),
        }


class SessionRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_sessions")

    def create(self, record: dict[str, Any]) -> None:
        self._col.insert_one(record)

    def get(self, session_id: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"session_id_hash": hash_session_id(session_id)})

    def touch(self, session_id: str, when: float | None = None) -> None:
        self._col.update_one(
            {"session_id_hash": hash_session_id(session_id)},
            {"$set": {"last_seen_at": when if when is not None else utcnow()}},
        )

    def delete(self, session_id: str) -> bool:
        result = self._col.delete_one({"session_id_hash": hash_session_id(session_id)})
        return result.deleted_count > 0

    def delete_for_user(self, user_id: str) -> int:
        return self._col.delete_many({"user_id": user_id}).deleted_count

    def list_for_user(self, user_id: str) -> list[dict[str, Any]]:
        return list(self._col.find({"user_id": user_id}).sort("created_at", -1))


# ----------------------------------------------------------------------
# Audit
# ----------------------------------------------------------------------
class AuditRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def record(
        self,
        *,
        action: str,
        actor: str,
        target_type: str = "",
        target_id: str = "",
        detail: dict[str, Any] | None = None,
        ip_address: str = "",
        outcome: str = "success",
    ) -> dict[str, Any]:
        document = {
            "audit_id": new_id(),
            "at": utcnow(),
            "action": action,
            "actor": actor or "anonymous",
            "target_type": target_type,
            "target_id": target_id,
            "detail": detail or {},
            "ip_address": ip_address,
            "outcome": outcome,
        }
        self._db.collection("platform_audit").insert_one(document)
        return document

    def list(self, *, limit: int = 100, action: str = "", actor: str = "") -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if action:
            query["action"] = action
        if actor:
            query["actor"] = actor
        return list(
            self._db.collection("platform_audit")
            .find(query)
            .sort("at", DESCENDING)
            .limit(max(1, min(limit, 1000)))
        )


# ----------------------------------------------------------------------
# Scans
# ----------------------------------------------------------------------
@dataclass
class ScanRecord:
    """A scan as stored in MongoDB."""

    scan_id: str
    name: str
    status: str
    created_by: str
    created_at: float
    updated_at: float
    definition: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> ScanRecord:
        return cls(
            scan_id=doc.get("scan_id", ""),
            name=doc.get("name", ""),
            status=doc.get("status", "draft"),
            created_by=doc.get("created_by", ""),
            created_at=doc.get("created_at", 0.0),
            updated_at=doc.get("updated_at", 0.0),
            definition=doc.get("definition", {}),
            stats=doc.get("stats", {}),
            scope=doc.get("scope", {}),
            error=doc.get("error", ""),
        )

    def public(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "name": self.name,
            "status": self.status,
            "created_by": self.created_by,
            "created_at": _iso(self.created_at) or self.created_at,
            "updated_at": _iso(self.updated_at) or self.updated_at,
            "definition": self.definition,
            "stats": self.stats,
            "scope": self.scope,
            "error": self.error,
        }


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_scans")

    def create(self, document: dict[str, Any]) -> ScanRecord:
        now = utcnow()
        document.setdefault("scan_id", new_id())
        document.setdefault("status", "draft")
        document.setdefault("created_at", now)
        document["updated_at"] = now
        document.setdefault("stats", {})
        document.setdefault("scope", {})
        document.setdefault("definition", {})
        self._col.insert_one(document)
        return ScanRecord.from_document(document)

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        doc = self._col.find_one({"scan_id": scan_id})
        return ScanRecord.from_document(doc) if doc else None

    def require(self, scan_id: str) -> ScanRecord:
        record = self.get(scan_id)
        if record is None:
            raise NotFound(f"scan '{scan_id}' does not exist")
        return record

    def list(
        self,
        *,
        status: str = "",
        created_by: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[ScanRecord]:
        query: dict[str, Any] = {}
        if status:
            query["status"] = status
        if created_by:
            query["created_by"] = created_by
        cursor = (
            self._col.find(query)
            .sort("created_at", DESCENDING)
            .skip(max(0, offset))
            .limit(max(1, min(limit, 1000)))
        )
        return [ScanRecord.from_document(doc) for doc in cursor]

    def count(self, *, status: str = "") -> int:
        query = {"status": status} if status else {}
        return self._col.count_documents(query)

    def update(self, scan_id: str, changes: dict[str, Any]) -> bool:
        if not changes:
            return False
        changes = dict(changes)
        changes["updated_at"] = utcnow()
        result = self._col.update_one({"scan_id": scan_id}, {"$set": changes})
        return result.matched_count > 0

    def set_status(self, scan_id: str, status: str, *, error: str = "") -> bool:
        payload: dict[str, Any] = {"status": status, "updated_at": utcnow()}
        if error:
            payload["error"] = error
        result = self._col.update_one({"scan_id": scan_id}, {"$set": payload})
        return result.matched_count > 0

    def bump_stat(self, scan_id: str, key: str, delta: int = 1) -> None:
        self._col.update_one({"scan_id": scan_id}, {"$inc": {f"stats.{key}": delta}})

    def set_stats(self, scan_id: str, stats: dict[str, Any]) -> None:
        payload = {f"stats.{key}": value for key, value in stats.items()}
        payload["updated_at"] = utcnow()
        self._col.update_one({"scan_id": scan_id}, {"$set": payload})


# ----------------------------------------------------------------------
# Events (SSE with replay)
# ----------------------------------------------------------------------
class EventRepository:
    """Append-only event log with monotonic per-scan sequence numbers."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_scan_events")

    def append(
        self,
        *,
        scan_id: str,
        kind: str,
        payload: dict[str, Any] | None = None,
        event_id: str | None = None,
        actor: str = "",
    ) -> Optional[dict[str, Any]]:
        """Append an event.  Returns ``None`` when the event was a duplicate."""
        event_id = event_id or f"{scan_id}:{kind}:{new_id()}"
        seq = self._db.next_sequence(f"events:{scan_id}")
        document = {
            "event_id": event_id,
            "scan_id": scan_id,
            "seq": seq,
            "kind": kind,
            "at": utcnow(),
            "actor": actor,
            "payload": payload or {},
        }
        if not self._db.claim_event(event_id, document):
            return None
        return document

    def list_after(self, scan_id: str, after_seq: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        cursor = (
            self._col.find({"scan_id": scan_id, "seq": {"$gt": after_seq}})
            .sort("seq", 1)
            .limit(max(1, min(limit, 2000)))
        )
        return list(cursor)

    def latest_seq(self, scan_id: str) -> int:
        doc = self._col.find_one({"scan_id": scan_id}, sort=[("seq", DESCENDING)])
        return int(doc["seq"]) if doc else 0

    def recent(self, limit: int = 50, scan_id: str = "") -> list[dict[str, Any]]:
        query = {"scan_id": scan_id} if scan_id else {}
        return list(self._col.find(query).sort("at", DESCENDING).limit(max(1, min(limit, 500))))


# ----------------------------------------------------------------------
# Tasks
# ----------------------------------------------------------------------
class TaskRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_tasks")

    def create(
        self,
        *,
        scan_id: str,
        title: str,
        kind: str = "agent",
        agent_role: str = "",
        depends_on: Sequence[str] = (),
        budget: dict[str, Any] | None = None,
        input: dict[str, Any] | None = None,
        karton_task_uid: str = "",
        task_id: str = "",
    ) -> dict[str, Any]:
        document = {
            "task_id": task_id or new_id(),
            "scan_id": scan_id,
            "title": title,
            "kind": kind,
            "agent_role": agent_role,
            "status": "pending",
            "depends_on": list(depends_on),
            "budget": budget or {},
            "input": input or {},
            "karton_task_uid": karton_task_uid,
            "created_at": utcnow(),
            "updated_at": utcnow(),
            "started_at": None,
            "finished_at": None,
            "attempts": 0,
            "error": "",
            "result": None,
        }
        self._col.insert_one(document)
        return document

    def get(self, task_id: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"task_id": task_id})

    def list_for_scan(self, scan_id: str, status: str = "") -> list[dict[str, Any]]:
        query: dict[str, Any] = {"scan_id": scan_id}
        if status:
            query["status"] = status
        return list(self._col.find(query).sort("created_at", 1))

    def set_status(self, task_id: str, status: str, *, error: str = "", result: Any = None) -> bool:
        payload: dict[str, Any] = {"status": status, "updated_at": utcnow()}
        if error:
            payload["error"] = error
        if result is not None:
            payload["result"] = result
        if status == "running":
            payload["started_at"] = utcnow()
        if status in {"succeeded", "failed", "cancelled"}:
            payload["finished_at"] = utcnow()
        result_obj = self._col.update_one({"task_id": task_id}, {"$set": payload})
        return result_obj.matched_count > 0

    def increment_attempts(self, task_id: str) -> None:
        self._col.update_one({"task_id": task_id}, {"$inc": {"attempts": 1}})

    def counts_by_status(self, scan_id: str = "") -> dict[str, int]:
        query = {"scan_id": scan_id} if scan_id else {}
        pipeline = [{"$match": query}, {"$group": {"_id": "$status", "count": {"$sum": 1}}}]
        return {row["_id"]: row["count"] for row in self._col.aggregate(pipeline)}


# ----------------------------------------------------------------------
# Agents
# ----------------------------------------------------------------------
class AgentStateRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_agents")

    def upsert(
        self,
        *,
        scan_id: str,
        role: str,
        instance_id: str = "",
        status: str = "idle",
        task_id: str = "",
        conclusion: str = "",
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        document = {
            "scan_id": scan_id,
            "role": role,
            "instance_id": instance_id or role,
            "status": status,
            "task_id": task_id,
            "conclusion": conclusion,
            "detail": detail or {},
            "last_seen_at": now,
        }
        self._col.update_one(
            {"scan_id": scan_id, "role": role, "instance_id": document["instance_id"]},
            {"$set": document},
            upsert=True,
        )
        return document

    def list_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        return list(self._col.find({"scan_id": scan_id}).sort("role", 1))

    def list_active(self, *, stale_after: float = 300.0) -> list[dict[str, Any]]:
        cutoff = utcnow() - stale_after
        return list(self._col.find({"last_seen_at": {"$gte": cutoff}}).sort("scan_id", 1))


class AgentDefinitionRepository:
    """Versioned agent definitions.

    A definition is immutable once created: editing produces a new version so
    that a scan can be replayed with exactly the configuration it used.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_agent_definitions")

    def create(self, definition: dict[str, Any]) -> dict[str, Any]:
        now = utcnow()
        base = definition.get("role", "")
        version = self._next_version(base)
        document = {
            "definition_id": new_id(),
            "name": definition.get("name", base),
            "role": base,
            "version": version,
            "system_prompt": definition.get("system_prompt", ""),
            "instructions": definition.get("instructions", ""),
            "model_ref": definition.get("model_ref", ""),
            "tools": list(definition.get("tools", [])),
            "permissions": definition.get("permissions", {}),
            "budget": definition.get("budget", {}),
            "output_schema": definition.get("output_schema", {}),
            "enabled": bool(definition.get("enabled", True)),
            "created_by": definition.get("created_by", ""),
            "created_at": now,
        }
        self._col.insert_one(document)
        return document

    def _next_version(self, role: str) -> int:
        latest = self._col.find_one({"role": role}, sort=[("version", DESCENDING)])
        return int(latest["version"]) + 1 if latest else 1

    def get(self, definition_id: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"definition_id": definition_id})

    def latest_for_role(self, role: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"role": role}, sort=[("version", DESCENDING)])

    def get_by_role_and_name(self, name: str, role: str) -> Optional[dict[str, Any]]:
        """Return the newest definition for a (name, role) pair."""
        return self._col.find_one({"name": name, "role": role}, sort=[("version", DESCENDING)])

    def list(self, *, role: str = "", enabled_only: bool = False) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if role:
            query["role"] = role
        if enabled_only:
            query["enabled"] = True
        return list(self._col.find(query).sort([("role", 1), ("version", -1)]))

    def set_enabled(self, definition_id: str, enabled: bool) -> bool:
        result = self._col.update_one({"definition_id": definition_id}, {"$set": {"enabled": enabled}})
        return result.matched_count > 0


# ----------------------------------------------------------------------
# Messages (agent collaboration)
# ----------------------------------------------------------------------
class MessageRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_messages")

    def append(self, message: dict[str, Any]) -> dict[str, Any]:
        scan_id = message.get("scan_id", "")
        message.setdefault("message_id", new_id())
        message.setdefault("at", utcnow())
        message["seq"] = self._db.next_sequence(f"messages:{scan_id}")
        self._col.insert_one(message)
        return message

    def list_for_scan(
        self, scan_id: str, *, limit: int = 200, kind: str = "", task_id: str = ""
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"scan_id": scan_id}
        if kind:
            query["kind"] = kind
        if task_id:
            query["task_id"] = task_id
        return list(self._col.find(query).sort("seq", 1).limit(max(1, min(limit, 1000))))

    def count_for_scan(self, scan_id: str) -> int:
        return self._col.count_documents({"scan_id": scan_id})


# ----------------------------------------------------------------------
# Tool calls
# ----------------------------------------------------------------------
class ToolCallRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def record(self, call: dict[str, Any]) -> dict[str, Any]:
        call.setdefault("call_id", new_id())
        call.setdefault("at", utcnow())
        self._db.collection("platform_tool_calls").insert_one(call)
        return call

    def list_for_scan(self, scan_id: str, *, limit: int = 200, agent_role: str = "") -> list[dict[str, Any]]:
        query: dict[str, Any] = {"scan_id": scan_id}
        if agent_role:
            query["agent_role"] = agent_role
        return list(
            self._db.collection("platform_tool_calls")
            .find(query)
            .sort("at", DESCENDING)
            .limit(max(1, min(limit, 1000)))
        )

    def failure_rate(self, scan_id: str = "") -> tuple[int, int]:
        query = {"scan_id": scan_id} if scan_id else {}
        total = self._db.collection("platform_tool_calls").count_documents(query)
        failed = self._db.collection("platform_tool_calls").count_documents({**query, "status": "error"})
        return failed, total


# ----------------------------------------------------------------------
# Findings and evidence
# ----------------------------------------------------------------------
def compute_fingerprint(
    *,
    vuln_class: str,
    host: str,
    path: str,
    parameter: str = "",
    extra: str = "",
) -> str:
    """Stable identity for a finding, used for deduplication.

    The identity deliberately excludes the detector so that two tools
    reporting the same issue collapse into one finding.
    """
    material = "|".join(
        [
            (vuln_class or "").strip().lower(),
            (host or "").strip().lower(),
            (path or "").strip(),
            (parameter or "").strip().lower(),
            (extra or "").strip().lower(),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_findings")

    @property
    def _evidence(self):
        return self._db.collection("platform_evidence")

    def upsert(
        self,
        *,
        scan_id: str,
        title: str,
        summary: str,
        vuln_class: str,
        severity: str,
        host: str = "",
        path: str = "",
        parameter: str = "",
        cwe: str = "",
        confidence: float = 0.5,
        detected_by: Sequence[str] = (),
        detection_source: str = "",
        affected_url: str = "",
        evidence: Sequence[dict[str, Any]] = (),
        remediation: str = "",
        extra_key: str = "",
    ) -> tuple[dict[str, Any], bool]:
        """Insert or merge a finding.

        Returns ``(document, created)``.  Merging is idempotent: repeating a
        finding update its ``last_seen_at`` and widens the detector list
        instead of creating a duplicate.
        """
        fingerprint = compute_fingerprint(
            vuln_class=vuln_class,
            host=host,
            path=path,
            parameter=parameter,
            extra=extra_key,
        )
        now = utcnow()
        existing = self._col.find_one({"scan_id": scan_id, "fingerprint": fingerprint})
        if existing is None:
            document = {
                "finding_id": new_id(),
                "scan_id": scan_id,
                "fingerprint": fingerprint,
                "title": title,
                "summary": summary,
                "vuln_class": vuln_class,
                "severity": severity if severity in SEVERITIES else "info",
                "host": host,
                "path": path,
                "parameter": parameter,
                "cwe": cwe,
                "confidence": float(confidence),
                "detected_by": list(dict.fromkeys(detected_by)),
                "detection_source": detection_source,
                "affected_url": affected_url,
                "evidence": list(evidence),
                "remediation": remediation,
                "verification_status": "unverified",
                "verification_notes": "",
                "verified_by": "",
                "false_positive_reason": "",
                "first_seen_at": now,
                "last_seen_at": now,
                "created_at": now,
                "updated_at": now,
            }
            try:
                self._col.insert_one(document)
            except DuplicateKeyError:
                existing = self._col.find_one({"scan_id": scan_id, "fingerprint": fingerprint})
                if existing is None:
                    raise
                document = existing
                created = False
            else:
                created = True
                for item in evidence:
                    self._add_evidence(document["finding_id"], scan_id, item)
                return document, created

        merged_detectors = list(dict.fromkeys(list(existing.get("detected_by", [])) + list(detected_by)))
        updates: dict[str, Any] = {
            "last_seen_at": now,
            "updated_at": now,
            "detected_by": merged_detectors,
            "confidence": max(float(existing.get("confidence", 0.0)), float(confidence)),
        }
        if not existing.get("evidence") and evidence:
            updates["evidence"] = list(evidence)
        if not existing.get("remediation") and remediation:
            updates["remediation"] = remediation
        self._col.update_one({"finding_id": existing["finding_id"]}, {"$set": updates})
        if evidence:
            for item in evidence:
                self._add_evidence(existing["finding_id"], scan_id, item)
        existing.update(updates)
        return existing, False

    def _add_evidence(self, finding_id: str, scan_id: str, item: dict[str, Any]) -> None:
        self._evidence.insert_one(
            {
                "evidence_id": new_id(),
                "finding_id": finding_id,
                "scan_id": scan_id,
                "kind": item.get("kind", "note"),
                "reference": item.get("reference", ""),
                "excerpt": item.get("excerpt", ""),
                "request": item.get("request", ""),
                "response": item.get("response", ""),
                "created_at": utcnow(),
            }
        )

    def get(self, finding_id: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"finding_id": finding_id})

    def evidence_for(self, finding_id: str) -> list[dict[str, Any]]:
        return list(self._evidence.find({"finding_id": finding_id}).sort("created_at", 1))

    def list(
        self,
        scan_id: str = "",
        *,
        severity: Sequence[str] = (),
        verification_status: Sequence[str] = (),
        vuln_class: str = "",
        host: str = "",
        detected_by: str = "",
        confidence_min: float | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if scan_id:
            query["scan_id"] = scan_id
        if severity:
            query["severity"] = {"$in": list(severity)}
        if verification_status:
            query["verification_status"] = {"$in": list(verification_status)}
        if vuln_class:
            query["vuln_class"] = vuln_class
        if host:
            query["host"] = host
        if detected_by:
            query["detected_by"] = detected_by
        if confidence_min is not None:
            query["confidence"] = {"$gte": float(confidence_min)}
        cursor = (
            self._col.find(query)
            .sort([("severity", 1), ("confidence", -1)])
            .skip(max(0, offset))
            .limit(max(1, min(limit, 2000)))
        )
        return list(cursor)

    def count(self, scan_id: str = "") -> int:
        query = {"scan_id": scan_id} if scan_id else {}
        return self._col.count_documents(query)

    def set_verification(
        self,
        finding_id: str,
        *,
        status: str,
        notes: str = "",
        verified_by: str = "",
        severity: str = "",
        false_positive_reason: str = "",
    ) -> bool:
        if status not in VERIFICATION_STATUSES:
            raise ValueError(f"invalid verification status '{status}'")
        payload: dict[str, Any] = {
            "verification_status": status,
            "verification_notes": notes,
            "verified_by": verified_by,
            "updated_at": utcnow(),
        }
        if severity and severity in SEVERITIES:
            payload["severity"] = severity
        if false_positive_reason:
            payload["false_positive_reason"] = false_positive_reason
        result = self._col.update_one({"finding_id": finding_id}, {"$set": payload})
        return result.matched_count > 0

    def severity_counts(self, scan_id: str = "") -> dict[str, int]:
        query = {"scan_id": scan_id} if scan_id else {}
        pipeline = [{"$match": query}, {"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
        counts = dict.fromkeys(SEVERITIES, 0)
        for row in self._col.aggregate(pipeline):
            counts[row["_id"]] = row["count"]
        return counts

    def class_counts(self, scan_id: str = "") -> dict[str, int]:
        query = {"scan_id": scan_id} if scan_id else {}
        pipeline = [{"$match": query}, {"$group": {"_id": "$vuln_class", "count": {"$sum": 1}}}]
        return {row["_id"]: row["count"] for row in self._col.aggregate(pipeline)}


# ----------------------------------------------------------------------
# Providers
# ----------------------------------------------------------------------
class ProviderRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_providers")

    def upsert(self, provider: dict[str, Any]) -> dict[str, Any]:
        provider.setdefault("provider_id", new_id())
        provider.setdefault("created_at", utcnow())
        provider["updated_at"] = utcnow()
        provider.setdefault("enabled", True)
        provider.setdefault("secret_ref", "")
        self._col.update_one({"name": provider["name"]}, {"$set": provider}, upsert=True)
        return provider

    def get(self, name: str) -> Optional[dict[str, Any]]:
        return self._col.find_one({"name": name})

    def list(self) -> list[dict[str, Any]]:
        return list(self._col.find({}).sort("name", 1))

    def delete(self, name: str) -> bool:
        return self._col.delete_one({"name": name}).deleted_count > 0

    def public(self, provider: dict[str, Any]) -> dict[str, Any]:
        out = dict(provider)
        for key in ("api_key", "secret", "token"):
            if key in out:
                out[key] = "***" if out[key] else ""
        out["secret_ref"] = out.get("secret_ref", "")
        return out


# ----------------------------------------------------------------------
# Artifacts
# ----------------------------------------------------------------------
class ArtifactRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def record(
        self,
        *,
        scan_id: str,
        kind: str,
        reference: str,
        sha256: str = "",
        size_bytes: int = 0,
        content_type: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        document = {
            "artifact_id": new_id(),
            "scan_id": scan_id,
            "kind": kind,
            "reference": reference,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "content_type": content_type,
            "metadata": metadata or {},
            "created_at": utcnow(),
        }
        self._db.collection("platform_artifacts").insert_one(document)
        return document

    def list_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        return list(
            self._db.collection("platform_artifacts").find({"scan_id": scan_id}).sort("created_at", 1)
        )


# ----------------------------------------------------------------------
# Benchmarks
# ----------------------------------------------------------------------
class BenchmarkRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def upsert_benchmark(self, manifest: dict[str, Any]) -> dict[str, Any]:
        self._db.collection("platform_benchmarks").update_one(
            {"slug": manifest["slug"]}, {"$set": manifest}, upsert=True
        )
        return manifest

    def list_benchmarks(self) -> list[dict[str, Any]]:
        return list(self._db.collection("platform_benchmarks").find({}).sort("slug", 1))

    def get_benchmark(self, slug: str) -> Optional[dict[str, Any]]:
        return self._db.collection("platform_benchmarks").find_one({"slug": slug})

    def start_run(self, run: dict[str, Any]) -> dict[str, Any]:
        run.setdefault("run_id", new_id())
        run.setdefault("started_at", utcnow())
        run.setdefault("status", "running")
        run.setdefault("results", [])
        run.setdefault("summary", {})
        self._db.collection("platform_benchmark_runs").insert_one(run)
        return run

    def finish_run(self, run_id: str, *, summary: dict[str, Any], status: str = "completed") -> bool:
        result = self._db.collection("platform_benchmark_runs").update_one(
            {"run_id": run_id},
            {"$set": {"summary": summary, "status": status, "finished_at": utcnow()}},
        )
        return result.matched_count > 0

    def get_run(self, run_id: str) -> Optional[dict[str, Any]]:
        return self._db.collection("platform_benchmark_runs").find_one({"run_id": run_id})

    def list_runs(self, benchmark_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        query = {"benchmark_id": benchmark_id} if benchmark_id else {}
        return list(
            self._db.collection("platform_benchmark_runs")
            .find(query)
            .sort("started_at", -1)
            .limit(max(1, min(limit, 500)))
        )

    def save_results(self, run_id: str, results: Sequence[dict[str, Any]]) -> None:
        collection = self._db.collection("platform_benchmark_results")
        for result in results:
            collection.update_one(
                {"run_id": run_id, "test_id": result["test_id"]},
                {"$set": {**result, "run_id": run_id}},
                upsert=True,
            )

    def list_results(self, run_id: str) -> list[dict[str, Any]]:
        return list(
            self._db.collection("platform_benchmark_results").find({"run_id": run_id}).sort("test_id", 1)
        )
