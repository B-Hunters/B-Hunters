"""No tracked file may hold a usable credential.

The repository is public.  A configuration file with a password in it is
a password in the repository, however development the deployment is.  The
configuration files are therefore written from the environment by
``scripts/render_config.py``, and the tracked files are the examples.

The check looks at the configuration files only.  The source code holds
the *names* of the settings — ``password = hash_password(password)`` is
not a password — and a check that read the source would report every
assignment it found.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent.parent

#: The files a credential would live in.
CONFIG_SUFFIXES = {".ini", ".cfg", ".conf", ".env", ".toml", ".yaml", ".yml"}

#: The settings whose value is a secret.
SECRET_KEYS = re.compile(
    r"(?i)^\s*(password|passwd|secret_key|secret|api_key|apikey|access_key|"
    r"secret_key|token|private_key)\s*=\s*(.*)$"
)

#: A value that is a placeholder rather than a credential.
PLACEHOLDER = re.compile(r"^\s*(<[^>]*>|\{\{[^}]*\}\}|)\s*$")


def tracked_files() -> list[Path]:
    """The files the repository tracks."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        check=True,
    )
    return [REPOSITORY / name for name in result.stdout.split() if name]


def offenders() -> list[str]:
    """The tracked configuration files that hold a credential."""
    found: list[str] = []
    for path in tracked_files():
        if path.suffix not in CONFIG_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            match = SECRET_KEYS.match(line)
            if not match:
                continue
            value = match.group(2).strip()
            if PLACEHOLDER.match(value):
                continue
            if len(value) < 8:
                continue
            found.append(f"{path.relative_to(REPOSITORY)}:{number}")
    return found


def test_no_tracked_file_contains_a_credential():
    assert offenders() == []


def test_the_configuration_files_are_git_ignored():
    ignored = subprocess.run(
        ["git", "check-ignore", "deploy/platform.ini", "deploy/b-hunters.ini"],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
    )
    assert ignored.returncode == 0, "the configuration files are not ignored"


def test_the_examples_are_tracked():
    result = subprocess.run(
        ["git", "ls-files", "deploy/"],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        check=True,
    )
    names = {Path(name).name for name in result.stdout.split()}
    assert "platform.example.ini" in names
    assert "b-hunters.example.ini" in names
    assert "platform.ini" not in names
    assert "b-hunters.ini" not in names
