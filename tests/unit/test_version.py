"""There is one version, and it is the one that is published.

The package carried a second copy of the version number, and the API
answered the health check with a literal.  Both drifted from the
release: the package said 1.4.0 and the health check said 1.3.0, in
the same image.
"""

from __future__ import annotations

import re
from pathlib import Path

import b_hunters
from b_hunters.platform import __version__ as platform_version


def test_the_package_and_the_platform_agree():
    assert platform_version == b_hunters.__version__


def test_the_api_reports_the_version_that_runs():
    from b_hunters.platform.api.app import create_app

    assert create_app().version == b_hunters.__version__


def test_no_source_file_carries_its_own_version_literal():
    """A second copy of the number is how it drifts."""
    root = Path(b_hunters.__path__[0])
    quote = re.escape("\"'")
    pattern = re.compile(quote + r"\d+\.\d+\.\d+" + quote)

    offenders = []
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line) and "__version__" not in line:
                offenders.append(f"{path.name}:{number}: {line.strip()}")

    assert not offenders, "a version literal outside __version__:\n" + "\n".join(offenders)
