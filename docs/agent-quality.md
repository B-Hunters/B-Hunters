# The agent quality work

## A role that stops learning should stop working

Two things made every agent task expensive.

**The rounds were a floor.** The deployment's `BHUNTERS_AGENT_MAX_ROUNDS`
was the *minimum* a role got, so a role that declared six rounds ran
twenty-four — every role spending every round it was given, most of
them on the same request. The rounds are now a **cap**: a role that
declares six rounds gets six, and a deployment that wants fewer lowers
the cap.

The tokens and the tool calls stay a **floor**, on purpose: a reasoning
model needs more of both than a plain one, because it spends a large
part of every turn on reasoning and the prompt grows with every tool
result.

**A role that learned nothing kept going.** The runtime now counts the
rounds that produced nothing new — no new tool output, no new URL, no
new thing said — and ends the task after three of them. The stop
reason is `no_new_evidence`, and it is a stop reason of its own: a
role that stopped for want of something to look at is not a role that
failed and not one that succeeded.

What counts as "new" is deliberately narrow. The **number** of tool
calls is not part of it: making the same call again is not learning
anything, and neither is saying the same thing again. What the role
*said* counts, because a role that reports in prose has produced
something.

### The work is not thrown away

A role that stopped keeps what it worked out:

* if it concluded — in prose, because the model did not use the answer
  tool — the conclusion is read and the run **succeeded**. The stop did
  not undo it;
* if it never concluded, its last words are kept as the conclusion and
  the stop reason says why it stopped.

## The providers

A provider can fail: a rejected credential, a rate limit, a timeout, a
server error. The `ProviderPool` tries the providers in priority order
and raises the last error when they are all exhausted. The provider
that answered is recorded on the task.

The provider document carries `priority`,
`price_per_million_prompt` and `price_per_million_completion`, and the
tokens and the estimated cost of every scan are recorded per provider
in `platform_provider_usage`. `GET /api/v1/usage` returns the cost per
scan, per role and per provider.

## The per-role benchmark

```
b-hunters bench agents --applications dvga,webgoat --roles recon,api --provider <name> --runs 1
```

It runs the agent phase against the benchmark manifest, attributes each
finding to the role that raised it, and scores precision, recall and F1
per role and overall. The results are stored in `platform_benchmark_runs`
with `mode="agent"`, beside the scanner runs, so the two can be
compared: what the scanners found, what the agents found, and what each
cost.

## The order the roles start in, and the budget they keep

A scan has a budget and the roles compete for it. When twelve roles are
planned at once, the budget is gone before the last of them starts, and
the ones that never ran are recorded as cut off — **including the roles
that give the findings their verdict**. A scan whose adjudicator never
ran leaves every finding unverified.

Two changes fix that:

* **The roles start in the order of their yield.** `recon` maps the
  surface, then the client-side and the API roles work on it, then the
  weakness roles. The order is `ROLE_PRIORITY` in the orchestrator.
* **The judging roles keep a reserved share of the budget.** The
  hypothesis roles stop short of the deadline by
  `BHUNTERS_AGENT_JUDGING_BUDGET_SHARE` (30% by default), so that the
  verifier and the adjudicator always have time to judge what was
  found.

A role that never started is recorded as `wall_clock`, never as one
that found nothing.

### What the change bought

A scan of the laboratory with the same parameters, before and after:

| | Before | After |
|---|---|---|
| Roles that completed | **0** | **5** |
| The verifier, the role that judges | never started | **completed** |
| The roles that did not run | 12, all cut off | 6, cut off with the reason |
| The tokens the scan spent | 0 | 681,569 |

The roles that completed were `recon`, `javascript`, `api`, `authn` and
the `verifier` — the four the budget admitted, in the order of their
yield, and then the role that judges.

The adjudicator was still cut off, because its cost scales with the
number of findings — two rounds each — and the reserve gave it less
than it needed. With a scan of thirty minutes it completes:

| Scan | Roles completed | The adjudicator | Findings judged |
|---|---|---|---|
| 15 minutes | 5 | cut off | 0 |
| 30 minutes | **6** | **completed, 10 rounds** | **7** |

The verdict is worth the time: five of the seven findings came back
*confirmed* and two came back *rejected* — one of them because it said
the same thing as another.

## The workers are bounded too

The worker phase has a budget of its own — 70% of the scan — and a
worker that spends it all starves the agents. Every worker is now
bounded: a rate, a concurrency and a timeout. sqlmap was also pointed at
the root of the target and asked for level 1 and risk 1, which is the
shallowest setting it has; it now crawls, asks for more, and ignores
the 401s of an application that answers them. See `docs/tooling.md`.

## A role that was cut off keeps what it found

The findings of a role travel in its final answer. A role that ran out
of time never gave one, and everything it had found was lost with it.

What the role last said is now read as its answer: the findings it
names are kept and judged like any other, and the run keeps the status
that says it was cut off. A role that recorded something already keeps
that — the salvage never overwrites what was found.

## How many roles a scan runs

The measured cost of one role, from a scan of the laboratory:

| Role | Rounds | Tokens | Wall clock |
|---|---|---|---|
| `javascript` | 7 | 156,371 | 150 s |
| `api` | 7 | 141,449 | 158 s |
| `authn` | 9 | 242,766 | 198 s |
| `access_control` | 7 | 101,268 | 159 s |

Twelve roles at four at a time need about **nine minutes of agent
time**, before the workers have taken their share. A fifteen-minute
scan cannot hold all of them, and starting twelve roles it cannot
finish leaves every finding unverified.

`BHUNTERS_AGENT_MAX_ROLES` (four in the deployment) decides how many
roles run. The roles are admitted **in the order of their yield** —
`recon` maps the surface, then the client-side and the API roles work
on it — and the roles that do not run are recorded as `wall_clock` with
the reason, not left pending. A scan that says what it did not do is
worth more than one that looks busy.

To run every role, give the scan the time. At the measured cost,
twelve roles need nine minutes of agent time and the workers need
their share of the rest, so **a scan of thirty minutes runs and judges
everything**. The platform's default scan is an hour, so every role
runs without anybody having to tune anything; the limit only matters
for a scan that is deliberately short.
