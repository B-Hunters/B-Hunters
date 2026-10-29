#!/usr/bin/env python3
"""Write the deployment's configuration files from the environment.

The repository holds the **examples**: `deploy/b-hunters.example.ini`
and `deploy/platform.example.ini`.  The files the stack actually reads
carry the credentials, so they are written here from the environment and
they are not in the repository.

Usage::

    python3 scripts/render_config.py [--env-file .env] [--check]

The placeholders in the examples look like ``{{BHUNTERS_MONGO_PASSWORD}}``
and are replaced with the value of that environment variable.  A
placeholder with no value is an error: a configuration file with an
empty password is a configuration file that fails at the worst moment.

``--check`` writes nothing and reports what is missing instead.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"

#: Where the environment file is looked for, in order.  The deployment
#: keeps it next to the repositories rather than inside one.
ENV_FILE_CANDIDATES = (
    ROOT.parent / ".env",
    ROOT.parent.parent / ".env",
    ROOT / ".env",
)

#: The example and the file it produces.
PAIRS = (
    ("b-hunters.example.ini", "b-hunters.ini"),
    ("platform.example.ini", "platform.ini"),
)

#: The placeholder in an example.
PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def read_env_file(path: Path) -> dict[str, str]:
    """Read a ``.env`` file into a mapping."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip().strip("'\"")
    return values


def _first_env_file() -> Path:
    """The environment file the deployment uses."""
    for candidate in ENV_FILE_CANDIDATES:
        if candidate.exists():
            return candidate
    return ENV_FILE_CANDIDATES[0]


def render(template: str, values: dict[str, str]) -> tuple[str, list[str]]:
    """Fill the placeholders of a template.

    Returns the rendered text and the names of the placeholders that had
    no value.
    """
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = values.get(name, "")
        if not value:
            missing.append(name)
            return ""
        return value

    return PLACEHOLDER.sub(replace, template), missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        default="",
        help="the environment file; the usual places are looked at when it is not given",
    )
    parser.add_argument("--check", action="store_true", help="report what is missing, write nothing")
    args = parser.parse_args(argv)

    env_file = Path(args.env_file) if args.env_file else _first_env_file()
    values = read_env_file(env_file)
    values.update({key: value for key, value in os.environ.items() if key.startswith("BHUNTERS_")})

    problems: list[str] = []
    for example_name, target_name in PAIRS:
        example = DEPLOY / example_name
        if not example.exists():
            problems.append(f"{example_name} is missing")
            continue
        rendered, missing = render(example.read_text(encoding="utf-8"), values)
        for name in missing:
            problems.append(f"{example_name}: {name} has no value")
        if missing:
            continue
        if args.check:
            print(f"{target_name}: ready")
            continue
        target = DEPLOY / target_name
        target.write_text(rendered, encoding="utf-8")
        target.chmod(0o600)
        print(f"wrote {target}")

    if problems:
        for problem in problems:
            print(f"missing: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
