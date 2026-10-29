"""The production compose file.

A production deployment is not the development stack with a different
name: the databases are not published, the session cookie is secure,
the resources are limited and there is a backup.  The file is checked
here so that a change that undoes one of those is caught before it is
deployed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parent.parent.parent
COMPOSE = REPOSITORY / "docker-compose.prod.yml"


@pytest.fixture(scope="module")
def compose() -> str:
    assert COMPOSE.exists(), "docker-compose.prod.yml is missing"
    return COMPOSE.read_text(encoding="utf-8")


def _service(compose: str, name: str) -> str:
    """The block of one service."""
    lines = compose.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(rf"^  {re.escape(name)}:\s*$", line):
            start = index
            break
    if start is None:
        return ""
    block = []
    for line in lines[start + 1 :]:
        if line and not line.startswith("    ") and not line.startswith(" "):
            break
        if re.match(r"^  [a-zA-Z]", line):
            break
        block.append(line)
    return "\n".join(block)


def test_the_data_stores_are_not_published(compose: str) -> None:
    for name in ("mongo", "redis", "s3"):
        block = _service(compose, name)
        assert block, f"the {name} service is missing"
        assert "ports:" not in block, f"the {name} service publishes a port"


def test_the_session_cookie_is_secure(compose: str) -> None:
    block = _service(compose, "platform")
    assert "BHUNTERS_SESSION_COOKIE_SECURE=true" in block
    assert "BHUNTERS_ENVIRONMENT=production" in block


def test_the_secret_key_is_required(compose: str) -> None:
    assert "BHUNTERS_SECRET_KEY=${BHUNTERS_SECRET_KEY:?" in compose


def test_the_services_have_resource_limits(compose: str) -> None:
    for name in ("platform", "runner", "mongo"):
        block = _service(compose, name)
        assert "limits:" in block, f"the {name} service has no resource limit"


def test_there_is_a_backup(compose: str) -> None:
    block = _service(compose, "backup")
    assert block, "there is no backup service"
    assert "mongodump" in block


def test_the_tls_is_terminated_in_front(compose: str) -> None:
    block = _service(compose, "caddy")
    assert block, "there is no reverse proxy"
    assert "443:443" in block
