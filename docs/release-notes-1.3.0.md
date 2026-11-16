# B-Hunters 1.3.0 — what changed

The release that makes the platform able to do the things it could
only describe before: log in, confirm a blind finding, judge what it
found, tell the operator, and be driven from a pipeline.

## The scanning

**The login.** The platform can now log in as an identity, keep the
session and use it for the rest of the scan. The recorder drives a
browser whose every request is checked against the scan's scope before
it leaves, and the service worker is blocked — a service worker is a
second network stack inside the page that the request hook does not
see. `docs/authenticated-scanning.md`.

**The preflight.** A scan that names an identity checks the session
*before* it runs, and refreshes it if it has expired. A scan that
finds out in the worker phase that its session has expired spends the
whole worker phase on a target it cannot reach.

**The comparison.** A scan may name two identities. The `compare_access`
tool makes the same request as each of them: an object-level
authorisation flaw is invisible to a single session, because the request
that is refused to you is the request that is allowed to somebody else.

**The browser.** The agents have a browser of their own, and a
`browser_crawl` adapter that crawls the target the way a *page* uses it:
the links it carries, the endpoints it fetches over XHR or fetch, and
the hash routes it navigates to. There is no action that reads the
session and no action that runs JavaScript in the page.

**The callbacks.** A blind vulnerability is confirmed by the target
reaching back. The platform runs its own callback service — the only
part of it exposed to the outside world, answering on one path and on
nothing else. `docs/oast.md`.

## The findings

**One name for each kind of vulnerability.** The scans had produced
seventy-eight spellings of about twenty kinds of vulnerability. The
class is normalised when a finding is stored, and the original text is
kept beside it: the same issue is one issue everywhere — in the
triage view, in the fingerprint and in the score.

**A judge rules; it does not propose.** The adjudicator had been
putting the same defect into the report twice: once as the tool found
it, with a verdict, and once as the judge found it, without one. The
adjudicator's schema has no `findings` array now, and the orchestrator
never stores a judging role's findings.

**A cut-off role keeps what it found.** The findings of a role travel
in its final answer, and a role that ran out of time never gave one.
What the role last said is now read as its answer.

**The budget.** A reasoning model spends about 150 seconds and 150,000
tokens on a role, so twelve roles need nine minutes of agent time on
their own. The roles are admitted in the order of their yield, the
judging roles keep half of the agent budget, and the worker phase and
the agent phase split the scan evenly.

## The operator

**The triage.** The issue, not the occurrence, carries the state: it
can be triaged, bulk-triaged, commented on, and its history read. An
issue that is seen again reopens, and the reopen is recorded.

**The notifications.** A webhook, signed with a shared secret when one
is configured. Every delivery is recorded, whether it worked or not.

**The API token.** A pipeline authenticates with a token instead of a
browser session. It is stored as a hash, so a dump of the database is
not a way in.

**The CI entry point.**

```bash
b-hunters ci scan --target https://demo.test/ --token "$BHUNTERS_API_TOKEN" --fail-on high
```

The exit code is the point: zero when nothing was found at or above the
threshold, one when there was.

**The trend.** The open issues by severity, what was new and what was
closed per week, the rate at which the findings are verified, and the
mean time to triage — all per issue, not per occurrence.

## The fleet

**`gospider` is retired.** The project has not been committed to since
April 2024, and `katana` — its successor — was already in the fleet.

**`ffuf` takes its place.** It mutates a value in a request, which is
what an object-level authorisation flaw needs: the other tools
enumerate names and paths, this one changes what is asked for.

**The workers are bounded.** sqlmap was pointed at the root of the
target and asked for level 1 and risk 1, which is the shallowest
setting it has; it now crawls, asks for more and ignores the 401s of
an application that answers them. Every worker has a rate, a
concurrency and a timeout.

**The images are built against the shared class of this repository.**
The published release does not have the `auth_headers` helper the
workers call, and a worker that fails on it fails *inside* a scan.
`scripts/build_workers.sh`.

## The measurements

| | Before | After |
|---|---|---|
| Roles that completed | 0 | **12 of 12** |
| The verifier, the role that judges | never started | completed |
| The adjudicator | never started | completed, 10 rounds |
| Findings with a verdict | 0 | 9 of 9 |
| The roles that did not run | 12, unexplained | 0 |

Two of the seven findings the adjudicator judged came back **rejected**
— and both rejections were right.
