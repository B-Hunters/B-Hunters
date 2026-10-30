"""The out-of-band callbacks.

A blind vulnerability cannot be confirmed by looking at the response: it
is confirmed by the target reaching back.  The platform runs its own
callback service so that this does not depend on a third party — a
public out-of-band service sees every test the operator runs, and the
operator's traffic is not the public service's business.

A token is unguessable and expires.  Only the path of a live token
answers; every other path is a 404.
"""

from __future__ import annotations

import secrets
from typing import Any, Optional

from .client import Database
from .repositories import new_id, utcnow

#: How long a callback token lives.
TOKEN_TTL_SECONDS = 24 * 3600

#: The most bytes of a body that are kept.
MAX_BODY_BYTES = 4096

#: The most headers that are kept.
MAX_HEADERS = 64


class CallbackRepository:
    """The callback tokens and the hits they received."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @property
    def _tokens(self):
        return self._db.collection("platform_callback_tokens")

    @property
    def _callbacks(self):
        return self._db.collection("platform_callbacks")

    def create_token(
        self,
        *,
        label: str,
        scan_id: str = "",
        ttl_seconds: int = TOKEN_TTL_SECONDS,
        expires_at: Optional[float] = None,
    ) -> dict[str, Any]:
        """Create a callback token.

        The token is unguessable: 32 bytes, URL-safe.  A callback
        service that answers on a guessable token is an open relay.
        """
        token = secrets.token_urlsafe(32)
        moment = utcnow()
        document: dict[str, Any] = {
            "token_id": new_id(),
            "token": token,
            "label": label or "callback",
            "scan_id": scan_id,
            "created_at": moment,
            "expires_at": float(expires_at) if expires_at else moment + max(60, int(ttl_seconds)),
            "hits": 0,
        }
        self._tokens.insert_one(document)
        return document

    def get_token(self, token: str) -> Optional[dict[str, Any]]:
        """The token document, when there is one."""
        return self._tokens.find_one({"token": token})

    def token_is_live(self, token: str) -> bool:
        """Whether the token may still be used."""
        document = self.get_token(token)
        if document is None:
            return False
        return float(document.get("expires_at", 0)) > utcnow()

    def tokens_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """The tokens of a scan."""
        return list(self._tokens.find({"scan_id": scan_id}))

    def record(
        self,
        *,
        token: str,
        method: str,
        path: str,
        headers: dict[str, Any],
        body: bytes,
        source: str = "",
    ) -> Optional[dict[str, Any]]:
        """Record a callback.

        A callback that arrives twice for the same token and the same
        path is one callback that happened twice: the count says how
        many times, and the first arrival says when.
        """
        document = self.get_token(token)
        if document is None:
            return None
        if float(document.get("expires_at", 0)) <= utcnow():
            return None

        kept_headers = {str(name): str(value) for name, value in list(headers.items())[:MAX_HEADERS]}
        raw = body or b""
        text = raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
        now = utcnow()

        existing = self._callbacks.find_one({"token": token, "method": method.upper(), "path": path})
        if existing is not None:
            self._callbacks.update_one(
                {"_id": existing["_id"]},
                {"$set": {"last_seen_at": now}, "$inc": {"count": 1}},
            )
            return self._callbacks.find_one({"_id": existing["_id"]})

        record: dict[str, Any] = {
            "callback_id": new_id(),
            "token": token,
            "token_id": document.get("token_id", ""),
            "label": document.get("label", ""),
            "scan_id": document.get("scan_id", ""),
            "method": method.upper(),
            "path": path,
            "headers": kept_headers,
            "body": text,
            "body_bytes": len(raw),
            "source": source,
            "at": now,
            "last_seen_at": now,
            "count": 1,
        }
        self._callbacks.insert_one(record)
        self._tokens.update_one({"token": token}, {"$inc": {"hits": 1}})
        return record

    def list_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """The callbacks a scan received, newest first."""
        return list(self._callbacks.find({"scan_id": scan_id}).sort("at", -1))

    def list_for_token(self, token: str) -> list[dict[str, Any]]:
        """The callbacks of one token."""
        return list(self._callbacks.find({"token": token}).sort("at", -1))

    def delete_token(self, token: str) -> bool:
        """Remove a token and its callbacks."""
        self._callbacks.delete_many({"token": token})
        result = self._tokens.delete_one({"token": token})
        return result.deleted_count > 0
