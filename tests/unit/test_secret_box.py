"""The secret box: the encryption of the credentials stored at rest."""

from __future__ import annotations

import base64

import pytest

from b_hunters.platform.security.secrets import SecretBox, SecretKeyError
from b_hunters.platform.settings import load_settings


def base64_key(seed: int = 1) -> str:
    """Return a valid 32 byte deployment key as base64."""
    return base64.b64encode(bytes([seed]) * 32).decode()


def test_a_secret_round_trips():
    box = SecretBox.from_base64(base64_key())
    token = box.encrypt("hunter2")
    assert token != "hunter2"
    assert box.decrypt(token) == "hunter2"


def test_the_ciphertext_is_prefixed_and_marked():
    box = SecretBox.from_base64(base64_key())
    token = box.encrypt("hunter2")
    assert token.startswith("bh1.")
    assert SecretBox.is_encrypted(token)
    assert not SecretBox.is_encrypted("hunter2")


def test_a_tampered_ciphertext_is_refused():
    box = SecretBox.from_base64(base64_key())
    token = box.encrypt("hunter2")
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(SecretKeyError):
        box.decrypt(tampered)


def test_a_foreign_key_cannot_decrypt():
    token = SecretBox.from_base64(base64_key()).encrypt("hunter2")
    with pytest.raises(SecretKeyError):
        SecretBox.from_base64(base64_key(seed=7)).decrypt(token)


def test_a_short_key_is_refused():
    with pytest.raises(SecretKeyError):
        SecretBox.from_base64(base64.b64encode(b"too-short").decode())


def test_from_settings_returns_none_without_a_key(settings):
    assert SecretBox.from_settings(settings) is None


def test_the_new_settings_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("BHUNTERS_RUNNER_CONCURRENCY", "3")
    monkeypatch.setenv("BHUNTERS_RUNNER_POLL_SECONDS", "0.5")
    monkeypatch.setenv("BHUNTERS_SECRET_KEY", "abc")
    settings = load_settings(overrides={"mongo_uri": "mongodb://127.0.0.1:27017"})
    assert settings.runner_concurrency == 3
    assert settings.runner_poll_seconds == 0.5
    assert settings.secret_key == "abc"
    assert settings.redacted()["secret_key"] == "***redacted***"
