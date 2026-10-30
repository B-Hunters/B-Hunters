"""The identity vault: the credentials the platform uses to log in.

A scan can name an identity: a named set of credentials for a target —
a username and a password, a bearer token, a cookie, a header.  The
credentials are the target's secrets and they are stored encrypted,
with the key the deployment holds in its environment.  The API accepts
them, never returns them, and the runner decrypts them at the moment
they are used.

The vault holds one thing that is not a secret: the session state the
login recorder captured.  It is encrypted as well, because a session
cookie is a credential.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Optional

log = logging.getLogger(__name__)

#: The kinds of identity the platform knows.
IDENTITY_KINDS = ("form", "basic", "bearer", "cookie", "header")

#: The secret fields of an identity, and the document field they are
#: stored in.
SECRET_FIELDS = {
    "password": "password_ciphertext",
    "totp_secret": "totp_secret_ciphertext",
    "headers": "headers_ciphertext",
    "cookies": "cookies_ciphertext",
    "storage_state": "storage_state_ciphertext",
}


class IdentityRepository:
    """The identities of a deployment."""

    def __init__(self, db: Any, secret_box: Any = None) -> None:
        self._db = db
        self._secret_box = secret_box

    @property
    def _col(self):
        return self._db.collection("platform_identities")

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def create(
        self,
        *,
        name: str,
        kind: str,
        login_url: str = "",
        username: str = "",
        password: str = "",
        totp_secret: str = "",
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        username_field: str = "",
        password_field: str = "",
        success_url: str = "",
        success_selector: str = "",
        verify_url: str = "",
        verify_selector: str = "",
        verify_text: str = "",
    ) -> dict[str, Any]:
        """Store an identity.  The secrets are encrypted on the way in."""
        if kind not in IDENTITY_KINDS:
            raise ValueError(f"'{kind}' is not a kind of identity")
        now = time.time()
        document: dict[str, Any] = {
            # A unique identifier: two identities with the same name
            # created in the same millisecond must not collide.
            "identity_id": f"id-{uuid.uuid4().hex[:16]}",
            "name": name,
            "kind": kind,
            "login_url": login_url,
            "username": username,
            "username_field": username_field,
            "password_field": password_field,
            "success_url": success_url,
            "success_selector": success_selector,
            "verify_url": verify_url,
            "verify_selector": verify_selector,
            "verify_text": verify_text,
            "status": "ready",
            "last_login_at": None,
            "last_used_at": None,
            "session_expires_at": None,
            "created_at": now,
            "updated_at": now,
        }
        self._encrypt_into(document, "password", password)
        self._encrypt_into(document, "totp_secret", totp_secret)
        self._encrypt_into(document, "headers", headers or {})
        self._encrypt_into(document, "cookies", cookies or {})
        self._col.insert_one(document)
        return document

    def _encrypt_into(self, document: dict[str, Any], name: str, value: Any) -> None:
        """Store one secret, encrypted, when there is one."""
        if value in (None, "", {}, []):
            return
        if self._secret_box is None:
            # Without a key the deployment cannot hold a secret safely,
            # and a secret in the clear is worse than no secret at all.
            raise RuntimeError("the deployment has no BHUNTERS_SECRET_KEY; a credential cannot be stored")
        document[SECRET_FIELDS[name]] = self._secret_box.encrypt(
            value if isinstance(value, str) else _json(value)
        )

    def update(self, identity_id: str, changes: dict[str, Any]) -> bool:
        """Change an identity.  A secret in the changes is encrypted."""
        payload = dict(changes or {})
        for name in SECRET_FIELDS:
            if name in payload:
                value = payload.pop(name)
                self._encrypt_into(payload, name, value)
        payload["updated_at"] = time.time()
        result = self._col.update_one({"identity_id": identity_id}, {"$set": payload})
        return result.matched_count > 0

    def delete(self, identity_id: str) -> bool:
        """Remove an identity."""
        return self._col.delete_one({"identity_id": identity_id}).deleted_count > 0

    def set_session(
        self,
        identity_id: str,
        *,
        storage_state: dict[str, Any],
        expires_at: float | None = None,
    ) -> bool:
        """Store the session the login recorder captured."""
        payload: dict[str, Any] = {"updated_at": time.time()}
        if self._secret_box is not None:
            payload["storage_state_ciphertext"] = self._secret_box.encrypt(_json(storage_state))
        payload["session_expires_at"] = expires_at
        payload["last_login_at"] = time.time()
        payload["status"] = "ready"
        result = self._col.update_one({"identity_id": identity_id}, {"$set": payload})
        return result.matched_count > 0

    def touch(self, identity_id: str) -> bool:
        """Record that the identity was used."""
        result = self._col.update_one({"identity_id": identity_id}, {"$set": {"last_used_at": time.time()}})
        return result.matched_count > 0

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def get(self, identity_id: str) -> Optional[dict[str, Any]]:
        """One identity, with its secrets still encrypted."""
        return self._col.find_one({"identity_id": identity_id})

    def list(self) -> list[dict[str, Any]]:
        """Every identity, with its secrets still encrypted."""
        return list(self._col.find({}).sort("name", 1))

    def secrets_for(self, identity_id: str) -> dict[str, Any]:
        """The decrypted secrets of an identity.

        This is what the runner uses and what the identity injection
        uses: the values never leave the process that needs them.
        """
        document = self.get(identity_id)
        if document is None:
            return {}
        if self._secret_box is None:
            return {}
        secrets: dict[str, Any] = {}
        for name, field in SECRET_FIELDS.items():
            token = document.get(field)
            if not token:
                continue
            try:
                plain = self._secret_box.decrypt(token)
            except Exception as exc:  # pragma: no cover - a wrong key is a deployment error
                log.warning("could not read the %s of an identity: %s", name, exc)
                continue
            secrets[name] = plain if name in ("password", "totp_secret") else _from_json(plain)
        return secrets

    def auth_payload(self, identity_id: str) -> dict[str, Any]:
        """The payload a worker needs to use the session.

        The workers read the cookies and the headers from the task's
        ``auth`` payload; the values are the target's and they are only
        ever in the task, never in the report.
        """
        secrets = self.secrets_for(identity_id)
        payload: dict[str, Any] = {}
        cookies = secrets.get("cookies") or {}
        headers = secrets.get("headers") or {}
        if cookies:
            payload["cookies"] = cookies
        if headers:
            payload["headers"] = headers
        return payload

    def public(self, identity: dict[str, Any]) -> dict[str, Any]:
        """The identity without its secrets."""
        out = {
            key: value
            for key, value in (identity or {}).items()
            if key not in SECRET_FIELDS.values() and key != "_id"
        }
        out["has_password"] = bool(identity.get("password_ciphertext"))
        out["has_totp"] = bool(identity.get("totp_secret_ciphertext"))
        out["has_headers"] = bool(identity.get("headers_ciphertext"))
        out["has_cookies"] = bool(identity.get("cookies_ciphertext"))
        out["has_storage_state"] = bool(identity.get("storage_state_ciphertext"))
        return out


def _json(value: Any) -> str:
    """A mapping as the text that is encrypted."""
    import json

    return json.dumps(value)


def _from_json(text: str) -> Any:
    """The mapping a secret was stored from."""
    import json

    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {}
