# Design: saved worker output, and an agent runtime on a real framework

Date: 2026-10-28
Status: approved (the operator asked for it directly and pre-approved the flow)

## The two asks

1. **The output of the scanner workers - the links Katana and GoSpider crawled,
   the paths Dirsearch found, the secrets Jsscanner read - should be saved as
   platform data, shown in the dashboard, and available for further scanning.**
2. **The agents should run on a robust framework instead of a hand-written
   tool-calling loop, and they should have enough tools - HTTP requests, a
   command line - to do their job.**

## What exists today

The worker output lives in the *legacy* documents: the `reports` document, the
`links` collection, the `js` collection. The karton-dashboard reads them and
renders them, but:

* the platform has no collection of its own for them, so they are not queryable
  through the API, not tied to a scan in a way the platform understands, and
  not reachable by an agent;
* an agent that wants to test a URL the crawler found has to know that the
  legacy documents exist;
* the console shows a preview, not a list that can be acted on.

The agent runtime (`agents/runtime.py`) is a hand-written loop: it builds the
prompt, calls an OpenAI-compatible endpoint with the tool definitions, parses
the tool calls, dispatches them through the gateway, checks the budgets and
asks for a conclusion. It works, but every part of it is bespoke: the retries,
the usage accounting, the structured output and the tool schema handling are
all hand-maintained.

The tools exist, but they are not evenly shared: `http_request` is with most
analysis roles, `run_command` only with `source_analysis`, and the shell
sandbox allows `python3` and `node` - which can reach any host, and so can
bypass the scope enforcer that `http_request` goes through.

## The design

### 1. The worker output becomes platform data

A new collection, `platform_worker_output`, holds one document per item:

```
{scan_id, worker, kind, value, source, created_at}
```

`kind` is one of `url`, `path`, `secret`, `port`, `technology`, `screenshot`,
`finding`. The rows are written when the worker phase ends, from the same
documents the dashboard reads - so the platform's copy and the dashboard's
view cannot disagree.

**Where it is written:** the orchestrator already records which workers took
part when the worker phase ends. The ingestion happens there, in one place.

**Where it is read:**

* `GET /api/v1/scans/{id}/worker-output` - the items, filterable by worker and
  by kind.
* **A new agent tool, `list_worker_output`** - an agent that wants to test the
  URLs the crawler found asks for them. This is the "further scan" from the
  agent's side, and it is the piece that makes the saved output worth saving.
* **The console** - the *Scanners* tab lists the saved items under the worker
  that produced them, and offers **Scan these URLs**: a button that creates a
  follow-up scan whose targets are those URLs, so the native adapters and the
  agents work on the surface the crawler found rather than only on the entry
  point.

### 2. The runtime moves onto a framework

**PydanticAI** (`pydantic-ai-slim[openai]`), because it fits the platform
rather than fighting it:

| What the platform needs | What the framework gives |
|---|---|
| the budgets (rounds, tool calls, tokens) | `UsageLimits(request_limit, tool_calls_limit, total_tokens_limit)` |
| a validated conclusion | `output_type` - a Pydantic model, so the JSON is parsed and checked by the framework |
| retries on a rate limit and a server error | `retries=` on the model |
| the tool gateway's JSON schemas | the tools are bridged, not re-described |
| a testable loop | `TestModel`/`FunctionModel` - the agent can be tested without a provider |

What **stays** the platform's own: the orchestrator (the plan, the
dependencies, the phases), the tool gateway (the capabilities, the audit, the
scope enforcer), the budgets' wall clock, the events, the collaboration
messages, and the provider (it stays the transport: it knows the MiniMax
quirks and the backoff).

**The bridge** (`agents/framework.py`) turns a role and the gateway's tool
definitions into a framework agent:

* each tool definition becomes a wrapper function whose signature is generated
  from the tool's JSON schema, so the model sees the same fields and
  descriptions it sees today;
* the wrapper calls the gateway exactly as the hand-written loop did - the
  capability check, the scope check and the audit stay in one place;
* the run context carries the platform's tool context;
* the conclusion is a Pydantic model, so a malformed answer is a validation
  error the framework retries rather than a silently empty conclusion;
* the "few rounds left, record it now" nudge becomes a message the framework
  injects into the history before the last requests.

### 3. The tools the agents need, without opening a hole

* `http_request` goes to every analysis role that reasons about the target's
  behaviour.
* `run_command` goes to the roles that work on artefacts - the JavaScript
  analyst, the API analyst, the reconnaissance analyst, the source analyst
  and the configuration analyst - because a sandboxed shell is what lets them
  parse a bundle, run a script or read a response body.
* **The shell becomes scope-aware.** `python3` and `node` can open a socket to
  any host, which would bypass the scope enforcer that `http_request` goes
  through. The shell tool therefore extracts the hosts a command names and
  refuses the command if any of them is outside the scan's authorised hosts.
  The scope is already on the tool context, so this is a check, not a new
  mechanism.
* `list_worker_output` goes to the roles that reason about the surface.

## What does not change

* The orchestrator, the phases and the scan budget.
* The tool gateway, the capabilities and the scope enforcer.
* The provider as the transport.
* The findings, their fingerprints and their verdicts.

## Testing

| Test | What it proves |
|---|---|
| `test_worker_output_repository.py` | the worker's output is saved per scan, filterable by worker and kind |
| `test_framework_tools.py` | a gateway tool becomes a framework tool with the same schema, and the capability check still refuses a tool the role may not use |
| `test_framework_conclusion.py` | the conclusion is validated; a malformed answer is a retry, not an empty conclusion |
| `test_shell_scope.py` | a command naming an out-of-scope host is refused |
| the existing suite | nothing else broke |

## Risks

* **The framework is a new dependency** in the platform image. It is pinned and
  installed through the platform extra, so the workers - which do not use it -
  are unaffected.
* **The shell is widened.** The scope check is the guarantee that keeps that
  safe, and it is tested.
* **The bridge is new code** where the hand-written loop used to be. The
  orchestrator's behaviour is unchanged, and the loop becomes testable
  without a provider, which the hand-written loop never was.
