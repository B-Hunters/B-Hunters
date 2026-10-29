"""The static contract reader.

The reader analyses the source of every worker repository.  A worker
repository may hold tests next to the worker, and the reader must not
mistake a test file for the worker: a repository whose tests sort first
would otherwise report that the worker declares no identity, because
the test file declares none.
"""

from __future__ import annotations

from pathlib import Path

from b_hunters.platform.scanners.contracts import analyse_worker


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_the_worker_module_is_found_next_to_a_test_file(tmp_path: Path) -> None:
    worker = tmp_path / "B-Hunters-Example"
    # The test file sorts before the worker module.
    _write(
        worker / "tests" / "test_example.py",
        "def test_something():\n    assert True\n",
    )
    _write(
        worker / "example" / "example.py",
        "from b_hunters.bhunter import BHunters\n\n\nclass example(BHunters):\n"
        '    identity = "B-Hunters-Example"\n'
        '    version = "1.2.0"\n'
        '    filters = (("domain", "new"),)\n',
    )

    contract = analyse_worker(worker)

    assert contract is not None
    assert contract.identity == "B-Hunters-Example"
    assert contract.version == "1.2.0"


def test_the_worker_module_is_found_when_there_are_no_tests(tmp_path: Path) -> None:
    worker = tmp_path / "B-Hunters-Example"
    _write(
        worker / "example" / "example.py",
        "from b_hunters.bhunter import BHunters\n\n\nclass example(BHunters):\n"
        '    identity = "B-Hunters-Example"\n',
    )

    contract = analyse_worker(worker)

    assert contract is not None
    assert contract.identity == "B-Hunters-Example"
