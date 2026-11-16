# Quality gates — design

**Date:** 2026-11-16
**Status:** ready to implement
**Covers:** C1–C3 of `2026-11-16-rebaseline-design.md`

---

## 1. The issues

| # | Issue | Severity |
|---|-------|----------|
| C1 | The frontend has **no unit test suite** — only the Playwright browser check. | S3 |
| C2 | `mypy` is wired into CI but was **never run to completion locally**. | S3 |
| C3 | `dev/check_workers_one_by_one.py` **stops every worker** and restarts them one at a time. | S3 |

---

## 2. C1 — the frontend has no unit tests

**Today.** `b_hunters/web/` is the console, served without a build step.
`tests/frontend/` holds fourteen Playwright browser checks. A change to a
template that breaks a page is caught by a browser check — which is slow,
and which only runs if the whole stack is up.

**The fix.** A JavaScript test runner that needs no browser.

**Why no browser.** The console is server-rendered HTML plus a small amount
of script. The parts worth unit-testing are the pure functions: the
severity colour, the timestamp rendering, the class label, the query
builder, the escape helper. None of them needs a DOM.

**The choice.** `node --test` with the built-in test runner — no
dependencies, no configuration, and it is already in Node 24. If the
console's script grows modules that need bundling, the runner moves to
`vitest` at that point.

**What the tests cover.**

| Function | What is asserted |
|----------|------------------|
| the severity → colour map | every severity the platform records has a colour; an unknown severity has a fallback |
| the relative-time renderer | "3 minutes ago", "just now", and a future timestamp |
| the class label | the canonical name becomes the label the console shows |
| the query builder | a filter with two values becomes two query parameters |
| the HTML escape | a finding title with `<` and `&` cannot break out of its element |

**The gate.** `tests/frontend/` gains a `unit/` directory, and CI runs
`node --test tests/frontend/unit/` alongside the existing Playwright check.

---

## 3. C2 — mypy has never finished a run

**Today.** `mypy` is configured and wired into CI. It has not been run to
completion on this machine, so the number of errors it finds is unknown.

**The fix, in two steps.**

1. **Measure.** Run it. Record the number of errors and the number of files
   they are in. This is the number that matters, and it is currently
   unknown.
2. **Bring it to zero, or to a stated floor.**

   The recommendation is **zero**, with one exception: `b_hunters/platform/agents/`
   may be excluded in a first pass, because the agent schemas are built at
   runtime and a large `Any` surface is expected there. The exclusion is
   written in the configuration and in this document, and it is a debt, not
   a permission.

   The work is then one pass per file, with the test suite green after each
   pass.

**The gate.** CI fails on a new error. The configuration records the
baseline so the count cannot grow.

```ini
[mypy]
python_version = 3.12
warn_unused_configs = True
disallow_untyped_defs = True
exclude = (?x)(^b_hunters/platform/agents/|^build/|^dist/)
```

---

## 4. C3 — the verification script stops the fleet

**Today.** `dev/check_workers_one_by_one.py` stops every worker container
and restarts them one at a time, so that each worker can be seen to
register on its own. It is a verification tool.

**Why it is dangerous.** It is a script in a directory named `dev/`, next to
a live deployment, and it does the one thing a live scan cannot survive: it
takes the workers away while a scan is running. The scan then reports tools
that never ran — which reads exactly like a scan that found nothing.

**The fix.** Three parts.

1. **A guard.** The script refuses to run while a scan is in progress. It
   asks the API for the scans in a non-terminal state and stops if it finds
   one.
2. **A confirmation.** It asks before it stops anything, and says exactly
   what it is about to stop.
3. **A better name and a better home.** It moves to
   `scripts/verify_workers.sh` — no, it stays Python, but it moves to
   `tools/verify_worker_registration.py`, next to the other operator tools,
   and its docstring says in the first line that it is destructive.

**The gate.** A test asserts that the guard refuses when a scan is running.

---

## 5. Acceptance criteria

| # | Criterion |
|---|-----------|
| 1 | `node --test tests/frontend/unit/` runs green, with at least five tests over the console's pure functions. |
| 2 | CI runs the frontend unit tests. |
| 3 | `mypy b_hunters` completes and reports **zero** errors, or the exclusions are written down and the count cannot grow. |
| 4 | CI fails on a new type error. |
| 5 | The worker-verification script refuses to run while a scan is in progress, and says why. |
| 6 | The script is no longer in `dev/`, and its first line of documentation says it stops the fleet. |

---

## 6. Risks

| Risk | Mitigation |
|------|------------|
| The type-checking pass is large | It is done one module at a time, with the suite green after each module. The measurement comes first, so the size is known before it is started. |
| The frontend unit tests test the tests | The functions under test are the ones that were the most likely to break silently — a colour map and an escape helper are both easy to get wrong and hard to see. |
| The guard on the verification script is bypassed | The script also refuses to run outside a development environment unless `--force` is given. |
