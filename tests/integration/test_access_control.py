"""The access-control comparison.

An object-level authorisation flaw is invisible to a single session.  The
only way to see it is to make the same request twice with two different
sessions and put the answers side by side.
"""

from __future__ import annotations

import asyncio

from b_hunters.platform.agents.access_control import (
    compare_responses,
    compare_two_identities,
    request_with,
)


class _Requester:
    """A target that answers differently to different sessions."""

    def __init__(self, answers: dict[str, dict]):
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, url, *, method="GET", headers=None, timeout=20.0):
        cookie = (headers or {}).get("Cookie", "")
        self.calls.append((url, cookie))
        for marker, answer in self.answers.items():
            if marker in cookie:
                return answer
        return {"status": 404, "body": "not found", "length": 9}


def test_two_sessions_that_agree_prove_nothing():
    same = {"status": 200, "length": 100, "body_excerpt": "same"}

    result = compare_responses(
        url="https://demo.test/rest/basket/1",
        primary=dict(same),
        secondary=dict(same),
    )

    assert result is None


def test_a_different_status_is_a_finding():
    result = compare_responses(
        url="https://demo.test/rest/basket/1",
        primary={"status": 200, "length": 100, "body_excerpt": "the basket"},
        secondary={"status": 403, "length": 20, "body_excerpt": "forbidden"},
        primary_name="alice",
        secondary_name="bob",
    )

    assert result is not None
    assert result["vuln_class"] == "access_control"
    assert result["severity"] == "medium"
    assert "alice" in result["summary"]
    assert "bob" in result["summary"]


def test_the_finding_carries_both_responses_as_evidence():
    result = compare_responses(
        url="https://demo.test/rest/basket/1",
        primary={"status": 200, "length": 100, "body_excerpt": "the basket"},
        secondary={"status": 403, "length": 20, "body_excerpt": "forbidden"},
        primary_name="alice",
        secondary_name="bob",
    )

    assert result is not None
    identities = {item["identity"] for item in result["evidence"]}
    assert identities == {"alice", "bob"}
    statuses = {item["identity"]: item["status"] for item in result["evidence"]}
    assert statuses == {"alice": 200, "bob": 403}


def test_a_different_length_is_also_a_difference():
    result = compare_responses(
        url="https://demo.test/rest/basket/1",
        primary={"status": 200, "length": 1000, "body_excerpt": "a lot"},
        secondary={"status": 200, "length": 10, "body_excerpt": "a little"},
    )

    assert result is not None
    assert result["difference"] == "length"


def test_the_same_request_is_made_with_both_sessions():
    requester = _Requester(
        {
            "alice": {"status": 200, "body": "the basket", "length": 100},
            "bob": {"status": 403, "body": "forbidden", "length": 20},
        }
    )

    result = asyncio.run(
        compare_two_identities(
            url="https://demo.test/rest/basket/1",
            primary={"cookies": {"session": "alice"}},
            secondary={"cookies": {"session": "bob"}},
            request=requester,
            primary_name="alice",
            secondary_name="bob",
        )
    )

    assert result is not None
    assert len(requester.calls) == 2
    assert {cookie for _url, cookie in requester.calls} == {"session=alice", "session=bob"}


def test_the_cookies_of_the_session_are_sent():
    requester = _Requester({"alice": {"status": 200, "body": "ok", "length": 2}})

    asyncio.run(
        request_with(
            "https://demo.test/",
            {"cookies": {"session": "alice", "csrf": "xyz"}},
            request=requester,
        )
    )

    cookie = requester.calls[0][1]
    assert "session=alice" in cookie
    assert "csrf=xyz" in cookie


def test_a_request_that_fails_does_not_raise():
    async def broken(url, *, method="GET", headers=None, timeout=20.0):
        raise OSError("the host is down")

    answer = asyncio.run(request_with("https://demo.test/", {}, request=broken))

    assert answer["status"] == 0
    assert answer["error"]
