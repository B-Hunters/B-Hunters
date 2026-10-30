"""The error ledger: an expected failure and an unexplained one."""

from __future__ import annotations

import pytest

from b_hunters.platform.errors import ErrorLedger, classify_error, ledger_from_records


@pytest.mark.parametrize(
    "text,expected",
    [
        ("HTTP 404 Not Found", "http_status"),
        ("the request failed with status 500", "http_status"),
        ("Connection refused", "connection"),
        ("connection reset by peer", "connection"),
        ("the request timed out", "timeout"),
        ("TimeoutError: the deadline passed", "timeout"),
        ("the host could not be resolved", "dns"),
        ("nodename nor servname provided", "dns"),
        ("the request is out of scope", "scope"),
        ("permission denied", "permission"),
        ("unknown tool 'list_assets'", "unknown_tool"),
        ("the token budget ran out", "budget"),
        ("", "unexplained"),
        ("something nobody expected", "unexplained"),
    ],
)
def test_a_failure_is_classified(text, expected):
    assert classify_error(text) == expected


def test_a_traceback_is_a_crash_even_when_it_mentions_a_timeout():
    assert classify_error("Traceback (most recent call last):\nTimeoutError: timed out") == "crash"


def test_an_exception_class_is_a_crash():
    assert classify_error("RuntimeError: object has no attribute 'x'") == "crash"


def test_a_status_code_alone_is_an_http_status():
    assert classify_error("", status="404") == "http_status"


def test_a_provider_failure_is_an_http_status():
    assert classify_error("the model endpoint returned 500") == "http_status"


def test_an_expected_failure_keeps_the_verdict_clean():
    ledger = ErrorLedger()
    ledger.add("tool_call", "HTTP 404 Not Found")
    ledger.add("tool_call", "Connection refused")
    ledger.add("tool_call", "the request timed out")
    verdict = ledger.verdict()
    assert verdict["verdict"] == "pass"
    assert verdict["total"] == 3
    assert verdict["by_class"]["http_status"] == 1
    assert verdict["by_class"]["connection"] == 1
    assert verdict["by_class"]["timeout"] == 1


def test_an_unexplained_failure_fails_the_verdict():
    ledger = ErrorLedger()
    ledger.add("tool_call", "RuntimeError: object has no attribute 'x'")
    verdict = ledger.verdict()
    assert verdict["verdict"] == "fail"
    assert verdict["failing"] == 1
    assert verdict["crash"] == 1


def test_a_validation_failure_is_an_explained_failure():
    # The tool said what was wrong with the arguments.
    assert (
        classify_error(
            "invalid arguments for 'http_request': headers/Content-Type: "
            "{'application/json': ''} is not of type 'string'"
        )
        == "arguments"
    )


def test_an_empty_failure_is_unexplained():
    ledger = ErrorLedger()
    ledger.add("tool_call", "")
    assert ledger.verdict()["verdict"] == "fail"
    assert ledger.verdict()["unexplained"] == 1


def test_the_entries_keep_where_the_failure_came_from():
    ledger = ErrorLedger()
    ledger.add("scanner", "Connection refused")
    ledger.add("worker", "RuntimeError: boom")
    entries = ledger.entries()
    assert entries[0]["source"] == "scanner"
    assert entries[1]["source"] == "worker"
    assert entries[1]["class"] == "crash"


def test_an_empty_ledger_passes():
    assert ErrorLedger().verdict()["verdict"] == "pass"


def test_the_ledger_is_read_back_from_the_records_of_a_scan():
    ledger = ledger_from_records(
        tool_calls=[
            {"status": "ok", "error": ""},
            {"status": "error", "error": "HTTP 404 Not Found"},
        ],
        events=[
            {"kind": "scanner.completed", "payload": {"error": "nothing"}},
            {"kind": "scanner.error", "payload": {"error": "Connection refused"}},
            {"kind": "worker.error", "payload": {"error": "the host could not be resolved"}},
        ],
        tasks=[
            {"status": "succeeded", "error": ""},
            {"status": "failed", "error": "RuntimeError: boom"},
        ],
    )

    verdict = ledger.verdict()
    assert verdict["total"] == 4
    assert verdict["by_class"]["http_status"] == 1
    assert verdict["by_class"]["connection"] == 1
    assert verdict["by_class"]["dns"] == 1
    assert verdict["verdict"] == "fail"
