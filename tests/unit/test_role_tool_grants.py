"""The roles have the tools their job needs.

A role that may not use the tools of its job cannot do it: the
reconciliation analyst cannot read the files of the workspace, and the
reconnaissance analyst cannot run a command in it.  The grants are also a
security boundary - the shell is only safe because the sandbox refuses a
command that names a host outside the scan.
"""

from __future__ import annotations

from b_hunters.platform.agents.roles import builtin_roles

#: The roles that work on the application's own artefacts: they read files
#: and run a command.  The roles that read untrusted content - the
#: crawler's output, the application's scripts - must not have a shell: a
#: page could put a command into the content they read.
SHELL_ROLES = {"vuln_config", "source_analysis"}

#: The roles that read untrusted content.
UNTRUSTED_ROLES = {"recon", "javascript", "api"}

#: The roles that reason about the surface: they ask what the crawlers found.
OUTPUT_ROLES = {
    "recon",
    "javascript",
    "api",
    "authn",
    "access_control",
    "vuln_injection",
    "vuln_xss",
    "vuln_ssrf",
    "vuln_config",
    "source_analysis",
}


def test_every_role_may_use_the_tools_it_is_given() -> None:
    for role in builtin_roles().values():
        allowed = role.permissions.tools
        if not allowed:
            continue
        missing = [tool for tool in role.tools if tool not in allowed]
        assert not missing, f"{role.role} may not use {missing}"


def test_every_role_declares_no_tool_it_does_not_offer() -> None:
    for role in builtin_roles().values():
        allowed = role.permissions.tools
        if not allowed:
            continue
        unused = [tool for tool in allowed if tool not in role.tools]
        assert not unused, f"{role.role} allows {unused} but does not offer them"


def test_the_artefact_roles_may_run_a_command() -> None:
    roles = builtin_roles()
    for name in SHELL_ROLES:
        assert "run_command" in roles[name].tools, f"{name} may not run a command"
        assert "shell" in roles[name].permissions.capabilities


def test_the_analysis_roles_may_make_requests() -> None:
    roles = builtin_roles()
    for name in OUTPUT_ROLES:
        assert "http_request" in roles[name].tools, f"{name} may not make a request"


def test_the_roles_that_reason_about_the_surface_see_the_worker_output() -> None:
    roles = builtin_roles()
    for name in OUTPUT_ROLES:
        assert "list_worker_output" in roles[name].tools, f"{name} may not read it"


def test_the_roles_that_read_untrusted_content_do_not_run_commands() -> None:
    roles = builtin_roles()
    for name in UNTRUSTED_ROLES:
        assert "run_command" not in roles[name].tools, f"{name} may not run a command"
        assert "shell" not in roles[name].permissions.capabilities


def test_the_reporting_roles_do_not_run_commands() -> None:
    roles = builtin_roles()
    for name in ("verifier", "adjudicator"):
        assert "run_command" not in roles[name].tools
        assert "shell" not in roles[name].permissions.capabilities
