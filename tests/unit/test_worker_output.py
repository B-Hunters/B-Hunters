"""How many candidates a scanner had.

The path scanners test the URLs that carry parameters.  A target whose
pages carry none leaves them with nothing, and the console has to say so
rather than show an empty result.
"""

from __future__ import annotations

from typing import Any

from b_hunters.platform.scanners import worker_output


class _Collection:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents

    def find(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            document
            for document in self.documents
            if all(document.get(key) == value for key, value in query.items())
        ]

    def find_one(self, query: dict[str, Any]) -> Any:
        found = self.find(query)
        return found[0] if found else None


class _Database:
    def __init__(self, links: list[dict[str, Any]]) -> None:
        self._collections = {"links": _Collection(links)}

    def collection(self, name: str) -> Any:
        return self._collections.get(name, _Collection([]))


class _ScanDatabase(_Database):
    """A database that carries the legacy scan, domain and report."""

    def __init__(self, links: list[dict[str, Any]], report: dict[str, Any]) -> None:
        from bson import ObjectId

        scan_id = ObjectId()
        report_id = report["_id"]
        super().__init__(links)
        self._collections["scans"] = _Collection(
            [{"_id": scan_id, "Platform_Scan_Id": "scan", "Domain": "172.25.0.15:5013"}]
        )
        self._collections["domains"] = _Collection(
            [
                {
                    "Scanid": str(scan_id),
                    "Domain": "172.25.0.15:5013",
                    "report_id": report_id,
                }
            ]
        )
        self._collections["reports"] = _Collection([report])


def test_the_candidates_are_the_urls_that_carry_parameters() -> None:
    links = [
        {
            "report_id": "r",
            "source": "B-Hunters-Katana",
            "Links": [
                "http://172.25.0.15:5013/graphql?query=1",
                "http://172.25.0.15:5013/audit",
                "https://www.youtube.com/watch?v=1",
            ],
        }
    ]
    database = _Database(links)

    counts = worker_output.candidates(database, {"_id": "r", "Domain": "172.25.0.15:5013"})

    assert counts["crawled_urls"] == 3
    assert counts["urls_with_parameters"] == 1


def test_a_target_without_parameters_leaves_nothing_to_test() -> None:
    links = [
        {
            "report_id": "r",
            "source": "B-Hunters-Katana",
            "Links": ["http://172.25.0.15:5013/audit", "http://172.25.0.15:5013/"],
        }
    ]
    database = _Database(links)

    counts = worker_output.candidates(database, {"_id": "r", "Domain": "172.25.0.15:5013"})

    assert counts["crawled_urls"] == 2
    assert counts["urls_with_parameters"] == 0


def test_the_count_is_per_report() -> None:
    links = [
        {"report_id": "r", "source": "B-Hunters-Katana", "Links": ["http://a/b?c=1"]},
        {"report_id": "other", "source": "B-Hunters-Katana", "Links": ["http://a/d?e=1"]},
    ]
    database = _Database(links)

    counts = worker_output.candidates(database, {"_id": "r", "Domain": "172.25.0.15:5013"})

    assert counts["crawled_urls"] == 1


def test_every_worker_reports_the_candidates() -> None:
    from bson import ObjectId

    report_id = ObjectId()
    links = [
        {
            "report_id": report_id,
            "source": "B-Hunters-Katana",
            "Links": ["http://172.25.0.15:5013/graphql?query=1"],
        }
    ]
    database = _ScanDatabase(links, {"_id": report_id, "Domain": "172.25.0.15:5013"})

    report = worker_output.scanner_report(database, "scan", participation={})

    assert report["summary"]["urls_with_parameters"] == 1
    assert all("candidates" in worker for worker in report["workers"])
