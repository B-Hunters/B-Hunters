"""The browser is inside the scope.

The browser is the one part of the platform that a model drives, and it
can reach anything the target's page can.  These tests check the three
properties that make it safe: an out-of-scope host is refused, a
state-changing method is refused, and the refusal is recorded.
"""

from __future__ import annotations

from b_hunters.platform.browser.scope import ScopeBrowser
from b_hunters.platform.security.scope import build_policy_from_scan

#: The resolver the browser uses: the addresses a host resolves to.
#: The real one is used in a scan; a test cannot rely on DNS.
_RESOLVER = lambda host: ["93.184.216.34"]  # noqa: E731


def _policy(**overrides):
    payload = {
        "authorized_hosts": ["demo.test"],
        "excluded_paths": [],
        "allow_private_network": False,
        "allow_http": True,
        "allow_state_changing": False,
    }
    payload.update(overrides)
    return build_policy_from_scan(**payload)


def test_a_host_inside_the_scope_is_allowed():
    browser = ScopeBrowser(policy=_policy(), resolver=_RESOLVER)

    allowed, reason = browser.allows("https://demo.test/app.js")

    assert allowed is True
    assert reason == ""


def test_a_host_outside_the_scope_is_refused():
    browser = ScopeBrowser(policy=_policy(), resolver=_RESOLVER)

    allowed, reason = browser.allows("https://evil.test/x")

    assert allowed is False
    assert reason


def test_a_state_changing_method_is_refused():
    browser = ScopeBrowser(policy=_policy(), resolver=_RESOLVER)

    allowed, reason = browser.allows("https://demo.test/login", "POST")

    assert allowed is False
    assert "changes server state" in reason


def test_a_state_changing_method_is_allowed_when_the_policy_says_so():
    browser = ScopeBrowser(policy=_policy(allow_state_changing=True), resolver=_RESOLVER)

    allowed, _ = browser.allows("https://demo.test/login", "POST")

    assert allowed is True


def test_an_excluded_path_is_refused():
    browser = ScopeBrowser(policy=_policy(excluded_paths=["/admin"]), resolver=_RESOLVER)

    allowed, reason = browser.allows("https://demo.test/admin/panel")

    assert allowed is False
    assert reason


def test_a_refusal_is_recorded():
    recorded: list[dict[str, str]] = []
    browser = ScopeBrowser(policy=_policy(), on_violation=recorded.append, resolver=_RESOLVER)

    browser._record("https://evil.test/x", "the url is outside the scope")

    assert browser.violations
    assert recorded[0]["url"] == "https://evil.test/x"


def test_a_private_address_is_refused_without_the_lab_flag():
    from b_hunters.platform.security.scope import ScopeEnforcer

    policy = _policy()
    enforcer = ScopeEnforcer(policy, resolver=_RESOLVER)

    decision = enforcer.evaluate_url("http://127.0.0.1:8080/")

    assert decision.allowed is False
    assert decision.reason
