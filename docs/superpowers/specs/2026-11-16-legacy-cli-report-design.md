# The legacy CLI report — design

**Date:** 2026-11-16
**Status:** ready to implement
**Covers:** E1–E2 of `2026-11-16-rebaseline-design.md`

---

## 1. The issue

The `b-hunters report` command is the legacy report path. The platform has
its own report — the console, the PDF, the API — and this command was left
behind. It is still in the entry point, and it is wrong in four ways.

| # | Defect | Evidence |
|---|--------|----------|
| E1a | It reads the wrong collection. It fetches the `domains` documents and expects the shape of a `reports` document. | `b_hunters/cli.py:611` reads `db["domains"]`; the workers write `db["reports"]` (`nmapscan.py:101`, `nucleim.py:166`, `dirsearchm.py:113`, `dalfox.py:114`) |
| E1b | It attributes artefacts to a domain by substring. A file whose key contains `example.com` is written into the folder of every domain whose name is a substring of it. | `b_hunters/cli.py:656` — `filename for filename in files if domain in filename` |
| E1c | It blocks on `input()`. In a container, in CI, or on a terminal with no stdin, the command hangs. | `b_hunters/cli.py:638` |
| E1d | A domain cannot be scanned twice. `run_scan` refuses when the domain exists. | `b_hunters/cli.py:345-351` |

E1a is the serious one. The `domains` document has the shape
`{Scanid, Domain, report_id, resolve, active, status}`; the `reports`
document has `{Domain, Ports, Technology, Vulns, Paths, Paths403,
Screenshot, data}`. The report generator asks a `domains` document for
`Ports`, `Technology`, `Vulns` and `Paths`, and gets nothing. **The report
is empty for every category except the raw artefacts and the JavaScript
links.**

E2 — there is no SARIF export, although the normalised finding schema makes
it cheap.

---

## 2. The decision: fix it, or retire it

The platform's report is the product. The legacy command duplicates it,
with a worse output format, in a code path nobody has corrected since the
`reports` collection was introduced.

**The recommendation: retire it, and replace it with a thin shim.**

| Command | Before | After |
|---------|--------|-------|
| `b-hunters report -d example.com -o /tmp/out` | writes an empty report | **exits with a message** naming the platform's report and the API endpoint that serves it, and exits **0** so a script that calls it does not fail |
| `b-hunters report ... --legacy` | — | the corrected legacy report, for the one case the platform does not cover: a scan that was started by the CLI and never by the platform |

This is the honest choice. The command is broken; the thing it duplicates
works; keeping a broken duplicate is worse than removing it.

**If the organisation wants it kept instead**, the corrections below are
what it takes. They are written out so the decision can be made on the
merits rather than on effort.

---

## 3. The corrections, if it is kept

### 3.1 E1a — the join

The `domains` document already carries `report_id`, which is the `_id` of
the `reports` document. The join is one lookup per document.

```python
    collection = db["domains"]
    documents = list(collection.find({"Scanid": scan_id}))
    for document in documents:
        report_id = document.get("report_id")
        report = db["reports"].find_one({"_id": ObjectId(report_id)}) or {}
```

`save_document_data` then receives the **report** document, not the domain
document. The `Subdomains` handler is changed to read the domain list the
command already collects (`subdomains`), because no document ever held a
`Subdomains` field — that is the other half of why `subdomains.txt` was
never written.

### 3.2 E1b — the artefact index

The substring match is replaced by an index built from the key convention
the workers already use: `{tool}_{scan_id}_{encoded_target}`. The report
lists the objects once, parses each key, and files the object under the
target it names.

```python
def index_artifacts(keys, scan_id):
    """The objects of a scan, by the target they belong to."""
    indexed = {}
    for key in keys:
        parts = key.split("_")
        if len(parts) < 3 or parts[1] != scan_id:
            continue
        target = "_".join(parts[2:])
        indexed.setdefault(target, []).append(key)
    return indexed
```

The `scan_id` in the key is what makes the index exact: an artefact of one
scan can never be attributed to another.

### 3.3 E1c — the prompt

`input()` becomes a flag.

```python
    report_parser.add_argument(
        "--force", action="store_true",
        help="write the report even while domains are still being processed",
    )
```

and the prompt is only asked when there is a terminal and `--force` was not
given. In a container, the command proceeds and says which domains were
still processing.

### 3.4 E1d — the re-scan

The `scans` collection gets a compound unique index on
`(Domain, Description, created_at)` instead of the implicit uniqueness of
`Domain`, and `run_scan` inserts a new scan document every time. The report
command then takes the **most recent** scan for a domain unless it is given
`--scan-id`.

**This is the change with the widest blast radius.** The `domains` documents
are keyed by `Scanid`, so a second scan of the same domain creates a second
set of domain documents — which is correct, and is what the data model
already implies.

---

## 4. E2 — SARIF export

SARIF is the interchange format that GitHub code scanning, GitLab and
DefectDojo all read. The platform's findings carry a class, a severity, a
host, a path and a fingerprint — everything SARIF needs.

The export is a function over the finding repository:

```python
def to_sarif(findings, *, tool_name="B-Hunters", tool_version=__version__):
    """The findings as a SARIF 2.1.0 document."""
```

with one rule per canonical class, the findings as results, and the
fingerprint as the `partialFingerprints` value so that the same issue is
recognised across scans.

The rule metadata comes from `vuln_classes.py` — the canonical class names
map onto CWE identifiers through the table that is already there, so the
SARIF rules carry real CWE ids rather than invented ones.

---

## 5. Acceptance criteria

| # | Criterion |
|---|-----------|
| 1 | `b-hunters report -d example.com -o /tmp/out` writes a report whose Ports, Technology, Vulns and Paths sections match a direct Mongo query of the `reports` document. |
| 2 | An artefact of one scan is never written into the folder of another domain. |
| 3 | The command does not block when there is no terminal, and says which domains were still processing. |
| 4 | The same domain can be scanned twice, and the two scans have separate results. |
| 5 | `b-hunters report --sarif` writes a SARIF 2.1.0 document that a SARIF validator accepts. |
| 6 | The SARIF rules carry the CWE identifier the class maps to. |

---

## 6. Risks

| Risk | Mitigation |
|------|------------|
| Retiring the command breaks a script that calls it | The shim exits 0 and prints where the report is now. The platform's API serves the same information. |
| The re-scan change breaks the workers' correlation | The `Scanid` is already the correlation key and the workers already read it from the persistent payload. A new scan is a new `Scanid`, and nothing else changes. |
| The SARIF rules are wrong | The CWE identifiers come from the table the platform already uses to normalise a class; the SARIF validator is run in CI. |
