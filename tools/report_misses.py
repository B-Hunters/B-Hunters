"""What the platform found, and what it missed.

The benchmark manifests say what each laboratory application contains.
The findings say what the platform found.  This script puts the two
side by side, using the platform's own matching rules — the same ones
the benchmark runner uses — so the answer is the platform's answer and
not a second opinion.

    python tools/report_misses.py --host juice-shop=172.25.0.13

The output is one line per test case: what was expected, whether it was
found, and what the platform found instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from b_hunters.platform.bench.manifest import default_manifests  # noqa: E402
from b_hunters.platform.bench.scoring import match_finding  # noqa: E402


def _database() -> Any:
    """The platform's database."""
    from b_hunters.platform.db.client import Database
    from b_hunters.platform.settings import get_settings

    return Database(get_settings())


def _findings(database: Any, host: str) -> list[dict[str, Any]]:
    """Every finding the platform has for a host."""
    query: dict[str, Any] = {}
    if host:
        query["host"] = host
    rows = list(database.collection("platform_findings").find(query))
    for row in rows:
        row.pop("_id", None)
    return rows


def _location_hint(case: Any) -> str:
    """Where the case says the vulnerability is."""
    probe = getattr(case, "probe", {}) or {}
    path = str(probe.get("path", "") or "")
    parameter = str(probe.get("parameter", "") or "")
    if path and parameter:
        return f"{path}?{parameter}"
    return path


def _matches(case: Any, findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings that satisfy a test case."""
    hint = _location_hint(case)
    matched = []
    for finding in findings:
        if match_finding(
            finding,
            vuln_class=case.vuln_class,
            expected_evidence=case.expected_evidence,
            location_hint=hint,
        ):
            matched.append(finding)
    return matched


def _nearest(case: Any, findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings of the same class, whether or not they matched.

    A miss that has a near miss beside it is a different problem from a
    miss with nothing beside it: the first is a matching rule that is
    too strict, the second is a detection that did not happen.
    """
    return [
        finding
        for finding in findings
        if str(finding.get("vuln_class", "")).strip().lower() == case.vuln_class.strip().lower()
    ]


def report(database: Any, hosts: dict[str, str]) -> list[dict[str, Any]]:
    """The outcome of every test case of every application."""
    rows: list[dict[str, Any]] = []
    for manifest in default_manifests():
        host = hosts.get(manifest.slug, "")
        findings = _findings(database, host) if host else []
        for case in manifest.test_cases:
            matched = _matches(case, findings)
            nearest = _nearest(case, findings)
            rows.append(
                {
                    "application": manifest.slug,
                    "test_id": case.test_id,
                    "name": case.name,
                    "vuln_class": case.vuln_class,
                    "expectation": case.expectation,
                    "expected_severity": case.expected_severity,
                    "unsupported": case.unsupported,
                    "found": bool(matched),
                    "matched": [str(item.get("title", "")) for item in matched],
                    "nearest": [
                        {
                            "title": str(item.get("title", "")),
                            "severity": str(item.get("severity", "")),
                            "status": str(item.get("verification_status", "")),
                            "class": str(item.get("vuln_class", "")),
                        }
                        for item in nearest
                    ],
                    "notes": case.notes,
                }
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        action="append",
        default=[],
        help="the host of an application, as slug=address; may be repeated",
    )
    parser.add_argument("--json", action="store_true", help="print the rows as JSON")
    args = parser.parse_args()

    hosts: dict[str, str] = {}
    for entry in args.host:
        if "=" not in entry:
            print(f"not a host: {entry!r}; it must be slug=address")
            return 2
        slug, address = entry.split("=", 1)
        hosts[slug.strip()] = address.strip()
    if not hosts:
        hosts = {
            "juice-shop": "172.25.0.13",
            "webgoat": "172.25.0.14",
            "dvga": "172.25.0.15",
        }

    database = _database()
    rows = report(database, hosts)

    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0

    missed = 0
    for row in rows:
        if row["expectation"] == "not_applicable":
            verdict = "not applicable"
        elif row["found"]:
            verdict = "FOUND"
        else:
            verdict = "MISSED"
            missed += 1
        print(f"{verdict:>14}  {row['application']:<12} {row['test_id']:<26} {row['name']}")
        if row["found"]:
            for title in row["matched"]:
                print(f"{'':>14}  found: {title[:88]}")
        elif row["nearest"]:
            print(f"{'':>14}  the same class was reported, but it did not match:")
            for item in row["nearest"]:
                print(f"{'':>14}    - {item['title'][:76]} [{item['severity']}] ({item['status']})")
        elif row["expectation"] == "expected":
            print(f"{'':>14}  nothing of this class was reported at all")
    print()
    print(f"{missed} test case(s) were missed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
