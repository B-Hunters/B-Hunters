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

## The workers are bounded too

The worker phase has a budget of its own — 70% of the scan — and a
worker that spends it all starves the agents. Every worker is now
bounded: a rate, a concurrency and a timeout. sqlmap was also pointed at
the root of the target and asked for level 1 and risk 1, which is the
shallowest setting it has; it now crawls, asks for more, and ignores
the 401s of an application that answers them. See `docs/tooling.md`.
