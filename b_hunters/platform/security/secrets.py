"""Encryption of the credentials the platform stores at rest.

The platform keeps the model provider keys in MongoDB.  A database dump
must not hand out working credentials, so the deployment provides one
key (``BHUNTERS_SECRET_KEY``) and every stored secret is encrypted with
AES-GCM before it is written.

The format is deliberately self-describing::

    bh1.<base64url(nonce || ciphertext||tag)>

The ``bh1.`` prefix marks an encrypted value, so a deployment can be
migrated from plaintext to encrypted storage without a flag day: a value
that carries the prefix is decrypted, a value that does not is still
plaintext.  The associated data binds a ciphertext to this format, so a
token from another deployment is refused rather than silently misread.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..settings import Settings

#: The prefix that marks an encrypted value.
CIPHER_PREFIX = "bh1."

#: The associated data that binds a ciphertext to this format.
ASSOCIATED_DATA = b"b-hunters/secret/v1"

#: The length of the deployment key in bytes (AES-256).
KEY_BYTES = 32

#: The length of the GCM nonce in bytes.
NONCE_BYTES = 12


class SecretKeyError(RuntimeError):
    """Raised for a missing, short or wrong key and for a failed decryption."""


@dataclass(frozen=True)
class SecretBox:
    """Encrypts and decrypts short secrets with AES-GCM.

    The box holds the deployment key.  It is immutable: a box never
    changes its key, so a value encrypted with one box is always
    decrypted by the same box.
    """

    #: The deployment key (exactly 32 bytes).
    key: bytes

    @classmethod
    def from_base64(cls, value: str) -> SecretBox:
        """Build a box from a base64 encoded 32 byte key."""
        try:
            raw = base64.b64decode((value or "").strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SecretKeyError("the secret key is not valid base64") from exc
        if len(raw) != KEY_BYTES:
            raise SecretKeyError(f"the secret key must be {KEY_BYTES} bytes, got {len(raw)}")
        return cls(key=raw)

    @classmethod
    def from_settings(cls, settings: Settings) -> SecretBox | None:
        """Build a box from the settings, or ``None`` when no key is configured."""
        configured = (getattr(settings, "secret_key", "") or "").strip()
        if not configured:
            return None
        return cls.from_base64(configured)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a value and return the marked, base64url encoded token."""
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext.encode("utf-8"), ASSOCIATED_DATA)
        return CIPHER_PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt a token produced by :meth:`encrypt`."""
        if not token.startswith(CIPHER_PREFIX):
            raise SecretKeyError("the value is not an encrypted secret")
        payload = token[len(CIPHER_PREFIX) :]
        try:
            raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
            raise SecretKeyError("the encrypted secret is not valid base64") from exc
        if len(raw) <= NONCE_BYTES:
            raise SecretKeyError("the encrypted secret is too short")
        try:
            plaintext = AESGCM(self.key).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], ASSOCIATED_DATA)
        except (InvalidTag, ValueError) as exc:
            raise SecretKeyError("the encrypted secret could not be decrypted") from exc
        return plaintext.decode("utf-8")

    @staticmethod
    def is_encrypted(value: str) -> bool:
        """Return ``True`` when the value carries the encrypted marker."""
        return bool(value) and value.startswith(CIPHER_PREFIX)
