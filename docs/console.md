# The console

The console is the platform's own web interface: a zero-build ES module
application served from `b_hunters/web`. There is no bundler, no
framework and no build step — the browser loads the modules itself.

## The layout

```
b_hunters/web/
├── index.html          the shell: the login card, the sidebar, the view container
├── styles.css
├── app.js              the entry the HTML loads: imports js/main.js
└── js/
    ├── main.js         the routes, the shell wiring, the startup
    ├── api.js          the fetch wrapper, the cookie readers, the CSRF header
    ├── format.js       escape(), fmtTime(), fmtDuration(), the badges
    ├── router.js       the hash router
    ├── state.js        the shared state
    ├── stream.js       the event stream
    ├── components.js   the render helpers the views share
    └── views/          one module per view
```

## The views

| Route | What it shows |
|---|---|
| `#/dashboard` | The overview: the recent scans, the agents, the tool health, the providers, the errors |
| `#/scans` | The list of scans |
| `#/new-scan` | The scan form |
| `#/scans/{id}` | One scan, with its tabs |
| `#/findings` | Every finding, with a filter by what detected it |
| `#/issues` | The durable issues, with their triage state, their history and their comments |
| `#/agents` | The agent roles and their definitions |
| `#/karton` | The task router: the queues, the workers, the crashed tasks |
| `#/benchmarks` | The benchmark scores |
| `#/admin/*` | The users, the providers, the agent definitions, the audit trail |

## The tabs of a scan

| Tab | What it shows |
|---|---|
| Live activity | The event stream, as it happens |
| Task graph | Every task, its status and its dependencies |
| Agents | The live agent state, the per-role table with the stop reason, and the transcript of any role |
| Collaboration | The messages the roles sent each other |
| Tool calls | Every tool invocation, with its duration and its output |
| Scanners | The tool participation table and what each worker produced |
| Services | What runs on each URL, and which version |
| Changes | What is new, what was not seen again and what came back since the last comparable scan |
| URLs | The whole asset inventory, with a type filter |
| JS | The JavaScript files the target serves |
| Images | The images the target serves |
| Findings | The findings of the scan, filterable by what found them |

## The issues

A finding belongs to the scan that found it. An **issue** is the durable
thing behind it: it carries the triage state, the observation state and
the history, and it is what the operator works on.

The `#/issues` view lists them, filters them by state, and opens one
with its history and its comments. From there the operator can:

* set the state — open, in progress, fixed, risk accepted, a false
  positive, a duplicate — and the owner;
* comment on it, with a record of who said what;
* read the history: every change of state, and when.

The state is set on the **issue**, not on the occurrence, so a problem
found by a later scan of the same target is the same problem: marking
it fixed marks it fixed in every scan after that.

An issue that is seen again **reopens**, and the reopen is recorded. A
fix that did not hold is not a fix, and the operator has to be able to
see that their fix did not hold.

## The participation table

The Scanners tab answers the question the console could not answer
before: **did every tool report?**

| Reason | What it means |
|---|---|
| `ran` | The worker took tasks and produced findings |
| `ran, found nothing` | The worker took tasks and found nothing — a result, not a failure |
| `errored` | The worker took tasks and had tasks that crashed |
| `never dispatched` | The worker was online but never received a task |
| `not connected` | The worker was not online when the scan started |

The facts behind those reasons are recorded **during** the scan: the
worker phase snapshots which consumers are online — the Redis client
name is the worker identity — and records what each worker consumed,
produced and crashed. "Not connected" is therefore a fact about the
scan, not about the moment the report is read.

The native adapters have their own rows, with their real version from
the registry. The workers do not report a version, so that column is
labelled *expected*: it is the version the platform pins, not a report
from the worker.

## The stop reasons

The Agents tab gives each role the reason it ended:

| Stop reason | What it means |
|---|---|
| `completed` | The role concluded |
| `budget_exhausted` | The role ran out of rounds, tokens or tool calls |
| `no_new_evidence` | The role found nothing new for three rounds and stopped |
| `wall_clock` | The role ran out of time — it was cut off |
| `cancelled` | The scan was stopped |
| `failed` | The role raised an error |

The scan's time cap is an **enforced deadline**: a role that has not
started when the deadline passes is recorded as `wall_clock` and never
runs, and a role cut off mid-flight is recorded as `wall_clock` too.
A role that was cut off is never reported as one that found nothing.

A role that stopped for want of new evidence keeps what it worked out:
a role that concluded in prose stays a success, and a role that never
concluded keeps its last words and the reason it stopped.

## The changes

The Changes tab compares the scan with the last one of the same target
that asked the same question. When the two are not comparable — a
different scope, a different set of tools, a scan that did not finish
— the tab says so instead of showing a difference that is not there.

The groups are **new**, **reopened**, **not observed** and **still
there**. A finding that was not seen again is *not observed*, not
*fixed*: the absence of a finding is not evidence that it was fixed,
and the issue is closed by the auto-close rule after two comparable
scans in a row missed it.

## The transcript

The transcript of a role is its messages and its tool calls, merged
chronologically. It is fetched page by page — a role with hundreds of
tool calls carries megabytes of text — and the console loads what the
reader asks for rather than the whole of it.

## The tests

The console has no build step, so its tests have none either:

```bash
node --test tests/frontend/
```

The tests cover the pure functions — the escaping, the formatting, the
route resolution, the table renderers, the asset filters — and they
check that a hostile value from a target cannot inject markup into the
page. The CI runs them on Node 20.

`tests/frontend/index.js` imports every test file by hand. Node treats
a directory argument as a file to run, so a test file that nobody adds
to that list is silently skipped — the directory run would report green
without ever running it.
