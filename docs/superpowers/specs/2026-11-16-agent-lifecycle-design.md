# Agent lifecycle — design

**Date:** 2026-11-16
**Status:** ready to implement
**Covers:** D1–D2 of `2026-11-16-rebaseline-design.md`

---

## 1. The issues

| # | Issue | Severity |
|---|-------|----------|
| D1 | The hypothesis roles spend **all their rounds** on one scan. They conclude at the budget, not when they have nothing left to test. | S3 |
| D2 | Two benchmark applications — crAPI and Mutillidae — have manifests but **no reachable image**, so nine of the thirteen benchmark cases are unmeasured. | S3 |

---

## 2. D1 — the roles finish because the budget ran out, not because they are done

**Today.** A hypothesis role is given a number of rounds and a share of the
agent budget. It spends all of them on the WebGoat scan and stops at the
limit. The platform records this correctly — the role's status says it was
cut off, and the platform does not claim a clean bill of health — but a role
that is always cut off is a role that never converges, and its transcript
is dominated by work that was abandoned.

**Why it matters.** Two costs. The scan spends budget on rounds that
produce nothing. And the quality signal is lost: a role that stopped
because it had nothing left to test and a role that stopped because it ran
out of time look the same in the report unless the reason is recorded
separately.

**The fix has two halves.**

### Half one — stop when there is nothing left to test

A hypothesis role should be able to say *I have nothing left to test* and
finish. The mechanism is a **stop reason** the role can return, distinct
from the budget exhaustion:

| Stop reason | Meaning |
|-------------|---------|
| `concluded` | the role tested what it set out to test and reached a verdict |
| `budget_exhausted` | the role ran out of rounds or tokens |
| `no_further_hypothesis` | the role has no remaining line of enquiry |
| `cut_off` | the scan's deadline passed |

`no_further_hypothesis` is the one the roles cannot currently express. The
role's answer schema gains it, and the orchestrator treats it as a
successful conclusion rather than a failure.

**The condition the role uses.** The role stops when the hypotheses it
listed at the start have all been tested or explicitly dismissed. The
orchestrator gives it the list it started with, and the role reports which
of those it disposed of.

### Half two — budget the roles by what they have to judge

The adjudicator's budget already scales with the findings it has to judge
(`STATUS.md` #10). The hypothesis roles do not scale with the hypotheses
they have to test.

The recommendation: the role's round budget is
`min(phase_budget_share, base_rounds + hypotheses × rounds_per_hypothesis)`.
A scan with three hypotheses gets a small budget and finishes; a scan with
forty gets a large one and is allowed to use it.

**What it looks like in the report.** The role's report says which of the
three reasons it stopped, and the console shows it. A role that stopped
because it was cut off is visibly different from a role that stopped
because it was done.

---

## 3. D2 — two applications that cannot be scanned

**Today.** The benchmark has manifests for crAPI and Mutillidae, and no
container to scan. Nine of the thirteen benchmark cases belong to those two
applications, so the platform's measured score covers less than it appears
to.

**This is not a platform defect.** `docs/misses.md` says so: *"These are not
misses of detection. They are misses of coverage, and the platform says so:
the applications have manifests and no running container."* The platform
already reports the gap as a coverage gap rather than as a clean result.

**Three ways to close it.**

| Option | What it costs | What it needs |
|--------|---------------|---------------|
| **Pull the images elsewhere** and publish them into the registry the lab uses | Low | A registry the operator can push to |
| **Build from source** | Medium | The upstream build instructions, and a build that works offline |
| **Leave it** and report the coverage gap | Zero | Nothing — this is the status quo, and it is honestly reported |

**The recommendation is the first**, with the third as the fallback while
the first is arranged. The second is not worth it: crAPI and Mutillidae are
large applications with build chains that will break more often than the
images will.

**What must not happen.** The benchmark must not score an application it
never scanned. The platform already refuses to; the change is to make the
refusal visible in the score itself — a coverage figure beside the detection
figure, so "78% detected" is never read without "of 4 of 13 applications".

---

## 4. Acceptance criteria

| # | Criterion |
|---|-----------|
| 1 | A hypothesis role can finish with `no_further_hypothesis`, and the run records that reason. |
| 2 | A role that stopped because it was done is distinguishable in the report from one that was cut off. |
| 3 | A hypothesis role's round budget scales with the number of hypotheses it was given, and a scan with three hypotheses finishes before its budget. |
| 4 | The WebGoat scan no longer shows every hypothesis role as budget-exhausted. |
| 5 | The benchmark report states how many applications were scanned, beside the detection score. |
| 6 | An application with a manifest and no container is reported as unmeasured, and is not counted as a miss. |

---

## 5. Risks

| Risk | Mitigation |
|------|------------|
| A role stops early and misses something | The role has to list what it disposed of; the orchestrator checks that every hypothesis it started with is accounted for before it accepts `no_further_hypothesis`. |
| The budget change makes a scan slower | The budget only shrinks when the work is small. The phase budget is unchanged, so the scan cannot take longer than it did. |
| The score becomes easier to misread | The coverage figure is printed beside the detection figure, never in place of it. |
| The image pull never happens | The platform reports the coverage gap honestly in the meantime, so nothing is misstated while it is outstanding. |
