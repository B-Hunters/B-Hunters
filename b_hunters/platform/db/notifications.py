"""The notifications and the API tokens.

Two things a single operator needs that a browser session cannot give.

**A notification** is a webhook the platform posts to when something
happens: a scan finished, a scan failed, a critical finding appeared.
The receiver can tell that the payload came from this platform, because
the payload is signed with a shared secret when one is configured.

**An API token** is how a pipeline asks the platform for something
without a browser.  The token is stored as a SHA-256 hash, so the
database never holds the thing that authenticates: a dump of the
database is not a way in.  The plaintext is returned once, at the moment
of creation, and never again.
"""

from __future__ import annotations

import builtins
import hashlib
import hmac
import json
import secrets
from typing import Any, Optional

from .client import Database
from .repositories import new_id, utcnow

#: The events a notification can ask for.
NOTIFICATION_EVENTS = (
    "scan.started",
    "scan.completed",
    "scan.failed",
    "scan.cancelled",
    "finding.critical",
    "finding.high",
    "issue.reopened",
)

#: The kinds of notification the platform knows how to deliver.
NOTIFICATION_KINDS = ("webhook",)

#: The scopes an API token can carry.
TOKEN_SCOPES = (
    "scans:read",
    "scans:write",
    "findings:read",
    "issues:read",
    "issues:write",
    "admin",
)

#: How long a webhook is given before the delivery is abandoned.
DELIVERY_TIMEOUT_SECONDS = 15.0


def hash_token(plaintext: str) -> str:
    """The hash of a token."""
    return hashlib.sha256((plaintext or "").encode()).hexdigest()


def _check_web_target(target: str) -> None:
    """Check that a webhook target is a web address.

    A target of another scheme would make the platform do something
    else entirely: a ``file:`` target would make it read a local file
    and post the contents of it.
    """
    from urllib.parse import urlsplit

    try:
        scheme = (urlsplit(target or "").scheme or "").lower()
    except ValueError as exc:
        raise ValueError(f"the webhook target is not a URL: {exc}") from exc
    if scheme not in {"http", "https"}:
        raise ValueError("a webhook target must be an http or https address")


def sign_payload(secret: str, body: dict[str, Any]) -> str:
    """The signature of a payload.

    The receiver recomputes it over the body it received, so a payload
    that was changed in flight does not match.
    """
    material = json.dumps(body, sort_keys=True, default=str).encode()
    digest = hmac.new((secret or "").encode(), material, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class TokenRepository:
    """The API tokens.

    The token is stored as a hash.  The plaintext is shown once, when
    the token is created, and cannot be recovered afterwards.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_api_tokens")

    def create(
        self,
        *,
        name: str,
        scopes: Optional[list[str]] = None,
        user_id: str = "",
        expires_at: Optional[float] = None,
    ) -> tuple[dict[str, Any], str]:
        """Create a token and return it with its plaintext.

        The plaintext is returned exactly once.  It is not stored and
        it cannot be recovered.
        """
        chosen = [scope for scope in (scopes or []) if scope in TOKEN_SCOPES]
        if not chosen:
            chosen = ["scans:read"]
        plaintext = "bh_" + secrets.token_urlsafe(32)
        now = utcnow()
        document: dict[str, Any] = {
            "token_id": new_id(),
            "name": name or "token",
            "token_hash": hash_token(plaintext),
            "prefix": plaintext[:11],
            "scopes": chosen,
            "user_id": user_id,
            "created_at": now,
            "expires_at": expires_at,
            "revoked_at": None,
            "last_used_at": None,
        }
        self._col.insert_one(document)
        return document, plaintext

    def get(self, token_id: str) -> Optional[dict[str, Any]]:
        """Return one token."""
        return self._col.find_one({"token_id": token_id})

    def list(self) -> builtins.list[dict[str, Any]]:
        """The tokens, without their hashes."""
        rows: list[dict[str, Any]] = []
        for document in self._col.find({}).sort("created_at", -1):
            rows.append({key: value for key, value in document.items() if key not in {"_id", "token_hash"}})
        return rows

    def revoke(self, token_id: str) -> bool:
        """Revoke a token.  It stops working at once."""
        result = self._col.update_one(
            {"token_id": token_id, "revoked_at": None},
            {"$set": {"revoked_at": utcnow()}},
        )
        return result.matched_count > 0

    def authenticate(self, plaintext: str) -> Optional[dict[str, Any]]:
        """The token a plaintext belongs to, when it is a live one."""
        if not plaintext:
            return None
        document = self._col.find_one({"token_hash": hash_token(plaintext)})
        if document is None:
            return None
        if document.get("revoked_at"):
            return None
        expires_at = document.get("expires_at")
        if expires_at and float(expires_at) <= utcnow():
            return None
        self._col.update_one(
            {"token_id": document["token_id"]},
            {"$set": {"last_used_at": utcnow()}},
        )
        return document


class NotificationRepository:
    """The notifications and the record of what was delivered."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _col(self):
        return self._db.collection("platform_notifications")

    @property
    def _deliveries(self):
        return self._db.collection("platform_notification_deliveries")

    def create(
        self,
        *,
        name: str,
        kind: str,
        target: str,
        events: list[str],
        secret: str = "",
        filters: Optional[dict[str, Any]] = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Store a notification."""
        if kind not in NOTIFICATION_KINDS:
            raise ValueError(f"unknown notification kind '{kind}'")
        if not (target or "").strip():
            raise ValueError("a notification needs a target")
        _check_web_target(target)
        chosen = [event for event in (events or []) if event in NOTIFICATION_EVENTS]
        if not chosen:
            unknown = [event for event in (events or []) if event not in NOTIFICATION_EVENTS]
            raise ValueError(f"unknown notification event: {', '.join(unknown) or 'none given'}")
        document: dict[str, Any] = {
            "notification_id": new_id(),
            "name": name or "notification",
            "kind": kind,
            "target": target.strip(),
            "events": chosen,
            "secret": secret or "",
            "filters": dict(filters or {}),
            "enabled": bool(enabled),
            "created_at": utcnow(),
            "updated_at": utcnow(),
        }
        self._col.insert_one(document)
        return document

    def get(self, notification_id: str) -> Optional[dict[str, Any]]:
        """Return one notification."""
        return self._col.find_one({"notification_id": notification_id})

    def list(self) -> builtins.list[dict[str, Any]]:
        """The notifications, without their secrets."""
        rows: list[dict[str, Any]] = []
        for document in self._col.find({}).sort("created_at", -1):
            rows.append({key: value for key, value in document.items() if key not in {"_id", "secret"}})
        return rows

    def update(self, notification_id: str, changes: dict[str, Any]) -> bool:
        """Change a notification."""
        allowed = {"name", "target", "events", "filters", "enabled", "secret"}
        payload = {key: value for key, value in changes.items() if key in allowed}
        if "events" in payload:
            chosen = [event for event in payload["events"] if event in NOTIFICATION_EVENTS]
            if not chosen:
                raise ValueError("the notification has no known event")
            payload["events"] = chosen
        if not payload:
            return False
        payload["updated_at"] = utcnow()
        result = self._col.update_one({"notification_id": notification_id}, {"$set": payload})
        return result.matched_count > 0

    def delete(self, notification_id: str) -> bool:
        """Remove a notification."""
        result = self._col.delete_one({"notification_id": notification_id})
        return result.deleted_count > 0

    def due(self, event: str, *, now: Optional[float] = None) -> builtins.list[dict[str, Any]]:
        """The notifications that want this event."""
        rows: list[dict[str, Any]] = []
        for document in self._col.find({"enabled": True, "events": event}):
            if not self._matches(document.get("filters") or {}, event):
                continue
            rows.append(document)
        return rows

    @staticmethod
    def _matches(filters: dict[str, Any], event: str) -> bool:
        """Whether the filters of a notification let this event through."""
        wanted = filters.get("events")
        if wanted and event not in wanted:
            return False
        severities = filters.get("severities")
        if severities:
            severity = str(filters.get("severity", ""))
            if severity and severity not in severities:
                return False
        return True

    # ------------------------------------------------------------------
    # The delivery
    # ------------------------------------------------------------------
    def post(self, url: str, *, headers: dict[str, str], json_body: dict[str, Any], timeout: float) -> int:
        """Post a payload to a webhook.

        The platform does not depend on an HTTP client being installed
        for the notification to work, so this uses the standard library.
        """
        import urllib.error
        import urllib.request

        _check_web_target(url)
        body = json.dumps(json_body, default=str).encode()
        request = urllib.request.Request(url, data=body, method="POST")  # noqa: S310
        for name, value in headers.items():
            request.add_header(name, value)
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                return int(response.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)

    def deliver(
        self,
        notification: dict[str, Any],
        *,
        event: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deliver one event to one notification.

        Every delivery is recorded, whether it worked or not: a webhook
        that silently stopped working is the worst kind of webhook.
        """
        body: dict[str, Any] = {
            "event": event,
            "notification": notification.get("name", ""),
            "at": utcnow(),
            "payload": payload,
        }
        headers = {"User-Agent": "B-Hunters"}
        secret = str(notification.get("secret", "") or "")
        if secret:
            headers["X-BHunters-Signature"] = sign_payload(secret, body)

        target = str(notification.get("target", ""))
        delivered = False
        error = ""
        status = 0
        try:
            status = self.post(
                target,
                headers=headers,
                json_body=body,
                timeout=DELIVERY_TIMEOUT_SECONDS,
            )
            delivered = 200 <= status < 300
            if not delivered:
                error = f"the webhook answered with {status}"
        except Exception as exc:  # a webhook that is down is not a crash
            error = f"{type(exc).__name__}: {exc}"

        record = {
            "delivery_id": new_id(),
            "notification_id": notification.get("notification_id", ""),
            "event": event,
            "target": target,
            "delivered": delivered,
            "status": status,
            "error": error,
            "at": utcnow(),
        }
        self._deliveries.insert_one(record)
        return record

    def deliveries(self, notification_id: str, *, limit: int = 50) -> builtins.list[dict[str, Any]]:
        """The deliveries of a notification, newest first."""
        rows = list(
            self._deliveries.find({"notification_id": notification_id})
            .sort("at", -1)
            .limit(max(1, min(limit, 500)))
        )
        return rows

    def notify(self, event: str, payload: dict[str, Any]) -> builtins.list[dict[str, Any]]:
        """Deliver an event to every notification that wants it."""
        results = []
        for notification in self.due(event):
            results.append(self.deliver(notification, event=event, payload=payload))
        return results
