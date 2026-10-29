"""The sandbox may not leave the scope.

`python3` and `node` can open a socket to any host, which would be a way
around the scope enforcer that `http_request` goes through.  A command
that names a host outside the scan is refused.

A name that is a file of the agent's own workspace is not a host: the
command `python3 script.py` must not be refused because `script.py` looks
like a domain name.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from b_hunters.platform.tools.builtin.shell import check_command


def _only(*hosts: str):
    allowed = {host.lower() for host in hosts}

    def _check(host: str) -> bool:
        return host.lower() in allowed

    return _check


def test_a_command_that_stays_local_is_allowed() -> None:
    parts = check_command(
        "grep -r secret .",
        allowlist=("grep",),
        deny_patterns=(),
        host_allowed=_only("172.25.0.15"),
    )
    assert parts[0] == "grep"


def test_a_command_that_names_an_out_of_scope_host_is_refused() -> None:
    with pytest.raises(Exception):
        check_command(
            "curl http://10.0.0.1/",
            allowlist=("curl",),
            deny_patterns=(),
            host_allowed=_only("172.25.0.15"),
        )


def test_a_command_that_names_an_in_scope_host_is_allowed() -> None:
    parts = check_command(
        "curl http://172.25.0.15:5013/health",
        allowlist=("curl",),
        deny_patterns=(),
        host_allowed=_only("172.25.0.15"),
    )
    assert parts[-1] == "http://172.25.0.15:5013/health"


def test_a_workspace_file_is_not_a_host(tmp_path: Path) -> None:
    (tmp_path / "script.py").write_text("print('hi')")
    parts = check_command(
        "python3 script.py",
        allowlist=("python3",),
        deny_patterns=(),
        host_allowed=_only("172.25.0.15"),
        workspace=tmp_path,
    )
    assert parts[-1] == "script.py"


def test_without_a_scope_the_command_is_not_checked_for_hosts() -> None:
    parts = check_command(
        "curl http://10.0.0.1/",
        allowlist=("curl",),
        deny_patterns=(),
    )
    assert parts[0] == "curl"
