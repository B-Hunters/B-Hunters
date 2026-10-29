"""The bookkeeping of the scanners is per scan, not per host.

``checklinksexist`` records the URLs a scanner has already checked in the
legacy ``scans`` document.  It used to find that document by host, and a
host can have several scans: a second scan of the same host read the
first scan's record and treated those URLs as checked, so it never tested
them.
"""

from __future__ import annotations

from typing import Any

from b_hunters.bhunter import BHunters


class _Collection:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self.documents = documents

    def find_one(self, query: dict[str, Any]) -> Any:
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None

    def update_one(self, query: dict[str, Any], update: dict[str, Any]) -> Any:
        document = self.find_one(query)
        if document is not None:
            for key, value in update.get("$push", {}).items():
                bucket, _, field = key.partition(".")
                document.setdefault(bucket, {}).setdefault(field, []).extend(value.get("$each", []))
        return None


class _Database:
    def __init__(self, scans: list[dict[str, Any]], domains: list[dict[str, Any]]) -> None:
        self._collections = {"scans": _Collection(scans), "domains": _Collection(domains)}

    def __getitem__(self, name: str) -> Any:
        return self._collections[name]


class _Worker(BHunters):
    """The base class without its Karton and Mongo plumbing."""

    def __init__(self, database: Any, scanid: str = "") -> None:
        self.db = database
        self.scanid = scanid

    def waitformongo(self) -> None:
        """The database is a stub here; there is nothing to wait for."""
        return None

    def process(self, task: Any) -> None:  # noqa: D102 - abstract method
        raise NotImplementedError


def _worker(scanid: str, scans: list[dict[str, Any]], domains: list[dict[str, Any]]) -> _Worker:
    worker = _Worker(_Database(scans, domains), scanid)
    worker.identity = "B-Hunters-DalFox"
    return worker


def test_a_second_scan_of_the_same_host_gets_the_urls_again() -> None:
    from bson import ObjectId

    first = ObjectId()
    second = ObjectId()
    scans = [
        {"_id": first, "Domain": "172.25.0.15:5013"},
        {"_id": second, "Domain": "172.25.0.15:5013"},
    ]
    # Every scan creates its own domain document for the host, so the
    # host has two of them.
    domains = [
        {"Domain": "172.25.0.15:5013", "Scanid": str(first)},
        {"Domain": "172.25.0.15:5013", "Scanid": str(second)},
    ]
    url = "http://172.25.0.15:5013/graphql"

    first_worker = _worker(str(first), scans, domains)
    assert first_worker.checklinksexist("172.25.0.15:5013", [url]) == [url]

    second_worker = _worker(str(second), scans, domains)
    assert second_worker.checklinksexist("172.25.0.15:5013", [url]) == [url], (
        "the second scan of a host has to test the URL again"
    )


def test_within_one_scan_a_url_is_checked_once() -> None:
    from bson import ObjectId

    scan = ObjectId()
    scans = [{"_id": scan, "Domain": "172.25.0.15:5013"}]
    domains = [{"Domain": "172.25.0.15:5013", "Scanid": str(scan)}]
    url = "http://172.25.0.15:5013/graphql"

    worker = _worker(str(scan), scans, domains)
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == [url]
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == []


def test_a_link_of_another_host_is_never_checked() -> None:
    from bson import ObjectId

    scan = ObjectId()
    scans = [{"_id": scan, "Domain": "172.25.0.15:5013"}]
    domains = [{"Domain": "172.25.0.15:5013", "Scanid": str(scan)}]
    worker = _worker(str(scan), scans, domains)

    assert worker.checklinksexist("172.25.0.15:5013", ["https://www.youtube.com/watch?v=1"]) == []


def test_a_worker_without_a_scan_id_falls_back_to_the_domain_document() -> None:
    from bson import ObjectId

    scan = ObjectId()
    scans = [{"_id": scan, "Domain": "172.25.0.15:5013"}]
    domains = [{"Domain": "172.25.0.15:5013", "Scanid": str(scan)}]
    worker = _Worker(_Database(scans, domains), "")
    worker.identity = "B-Hunters-DalFox"

    url = "http://172.25.0.15:5013/graphql"
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == [url]
    assert worker.checklinksexist("172.25.0.15:5013", [url]) == []
