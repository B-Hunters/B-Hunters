"""The output of the scanner workers is saved per scan."""

from __future__ import annotations

from typing import Any

from b_hunters.platform.db.worker_output_repository import WorkerOutputRepository


class _Collection:
    def __init__(self) -> None:
        self.documents: list[dict[str, Any]] = []

    def delete_many(self, query: dict[str, Any]) -> Any:
        self.documents = [
            document
            for document in self.documents
            if not all(document.get(key) == value for key, value in query.items())
        ]
        return None

    def insert_many(self, documents: list[dict[str, Any]]) -> Any:
        self.documents.extend(documents)
        return None

    def find(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            document
            for document in self.documents
            if all(document.get(key) == value for key, value in query.items())
        ]


class _Database:
    def __init__(self) -> None:
        self.collections: dict[str, _Collection] = {}

    def collection(self, name: str) -> Any:
        return self.collections.setdefault(name, _Collection())


def test_the_output_is_saved_and_read_back() -> None:
    repository = WorkerOutputRepository(_Database())
    written = repository.replace_for_scan(
        "scan-1",
        [
            {"worker": "B-Hunters-Katana", "kind": "url", "value": "http://a/x"},
            {"worker": "B-Hunters-dirsearch", "kind": "path", "value": "/admin"},
        ],
    )
    assert written == 2
    items = repository.list_for_scan("scan-1")
    assert [item["value"] for item in items] == ["http://a/x", "/admin"]


def test_the_output_is_filtered_by_worker_and_kind() -> None:
    repository = WorkerOutputRepository(_Database())
    repository.replace_for_scan(
        "scan-1",
        [
            {"worker": "B-Hunters-Katana", "kind": "url", "value": "http://a/x"},
            {"worker": "B-Hunters-dirsearch", "kind": "path", "value": "/admin"},
        ],
    )
    assert len(repository.list_for_scan("scan-1", worker="B-Hunters-Katana")) == 1
    assert len(repository.list_for_scan("scan-1", kind="path")) == 1
    assert repository.list_for_scan("scan-2") == []


def test_a_second_ingestion_replaces_the_first() -> None:
    repository = WorkerOutputRepository(_Database())
    repository.replace_for_scan("scan-1", [{"worker": "W", "kind": "url", "value": "http://a/x"}])
    repository.replace_for_scan("scan-1", [{"worker": "W", "kind": "url", "value": "http://a/y"}])
    items = repository.list_for_scan("scan-1")
    assert [item["value"] for item in items] == ["http://a/y"]


def test_an_empty_value_is_not_saved() -> None:
    repository = WorkerOutputRepository(_Database())
    written = repository.replace_for_scan("scan-1", [{"worker": "W", "kind": "url", "value": "   "}])
    assert written == 0


def test_the_counts_name_the_workers() -> None:
    repository = WorkerOutputRepository(_Database())
    repository.replace_for_scan(
        "scan-1",
        [
            {"worker": "A", "kind": "url", "value": "http://a/x"},
            {"worker": "A", "kind": "url", "value": "http://a/y"},
            {"worker": "B", "kind": "path", "value": "/admin"},
        ],
    )
    assert repository.counts_for_scan("scan-1") == {"A": 2, "B": 1}
