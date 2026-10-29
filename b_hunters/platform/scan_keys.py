"""The stable identities of a scan.

Two scans of the same target are the same target, even when the
operator wrote the hosts in another order or with another capital
letter.  The *target key* is that identity: it says what was scanned.

The *comparison key* adds what the scan did - the profile, the scanners,
the agent roles, the excluded paths and the identities it used.  Two
scans may only be compared when their comparison keys are equal: a scan
with more scanners found more because it looked at more, not because
the target changed.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

#: How long a key is.  A hex digest of 32 characters is short enough to
#: read in a log line and long enough that a collision is not a thing
#: that happens.
KEY_LENGTH = 32


def _digest(material: str) -> str:
    """The key of a material string."""
    return hashlib.sha256(material.encode()).hexdigest()[:KEY_LENGTH]


def compute_target_key(*, authorized_hosts: Sequence[str], targets: Sequence[str]) -> str:
    """The identity of the target of a scan.

    The hosts and the targets are normalised and sorted, so that the
    same target written in another order has the same key.
    """
    hosts = sorted({host.strip().lower().rstrip(".") for host in authorized_hosts if host and host.strip()})
    urls = sorted({target.strip() for target in targets if target and target.strip()})
    return _digest("|".join(hosts + urls))


def compute_comparison_key(
    *,
    target_key: str,
    excluded_paths: Sequence[str],
    profile: str,
    scanners: Sequence[str],
    agent_roles: Sequence[str],
    identity_ids: Sequence[str],
) -> str:
    """The identity of what a scan did to a target.

    Two scans of the same target may only be compared when this key is
    the same: a scan that ran more scanners or used more identities
    looked at more, and its findings are not a change of the target.
    """
    material = "|".join(
        [
            target_key,
            profile,
            ",".join(sorted(excluded_paths)),
            ",".join(sorted(scanners)),
            ",".join(sorted(agent_roles)),
            ",".join(sorted(identity_ids)),
        ]
    )
    return _digest(material)
