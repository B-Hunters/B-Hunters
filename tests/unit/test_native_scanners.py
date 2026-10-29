"""Tests for the in-process scanner adapters.

The adapters run inside the platform, so they are exercised directly.
The TLS adapter is the interesting one: it has to distinguish a target
that speaks TLS from a target that speaks plain HTTP, because a handshake
against an HTTP server produces an error that says nothing about the
target.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from b_hunters.platform.scanners.base import ScanRequest  # noqa: E402
from b_hunters.platform.scanners.native import (  # noqa: E402
    tls_configuration_executor,
)


def _request(*targets: str) -> ScanRequest:
    return ScanRequest(scan_id="scan", targets=list(targets))


class TestTlsConfiguration:
    @pytest.mark.asyncio
    async def test_a_plain_http_target_is_skipped(self) -> None:
        """An HTTP target has no TLS session, so it is not an error."""
        result = await tls_configuration_executor(_request("http://lab-dvga:5013/"))

        assert result.error == ""
        assert result.ok is True
        assert result.items == []

    @pytest.mark.asyncio
    async def test_a_plain_http_target_is_skipped_next_to_an_https_one(self) -> None:
        result = await tls_configuration_executor(_request("http://lab-dvga:5013/", "https://127.0.0.1:1/"))

        # The HTTPS target is attempted and fails to connect, the HTTP one
        # is not attempted at all: only the HTTPS target is reported.
        assert "lab-dvga" not in result.error
        assert "127.0.0.1:1" in result.error

    @pytest.mark.asyncio
    async def test_a_target_without_a_scheme_is_still_attempted(self) -> None:
        """A bare host is treated as a TLS target, as before."""
        result = await tls_configuration_executor(_request("127.0.0.1:1"))

        assert "127.0.0.1:1" in result.error


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
