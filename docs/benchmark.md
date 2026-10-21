# Benchmark laboratory and scoring

The laboratory runs deliberately vulnerable applications in isolated
containers so that the platform's detection capability can be measured
against known, documented flaws rather than against an LLM's assertion
that something is wrong.

---

## 1. Principles

**Test cases refer to documented vulnerabilities.** Every expected finding
in a manifest corresponds to a vulnerability that the application's own
documentation describes, or to a controlled fixture the manifest defines.
The expected outcome is not derived from a model.

**Unsupported means unsupported.** When an application does not contain a
vulnerability class, the test is marked `not_applicable` and is excluded
from the precision and recall calculation. It is not counted as a scanner
failure.

**Unreachable means inconclusive.** If the application does not start, or
the scan fails, the affected test cases are recorded as `inconclusive`.
The runner never fabricates a result.

**Hygiene cases count against false positives.** A `hygiene` test asserts
that the application does *not* contain a class. Reporting it is a false
positive.

---

## 2. Applications

| Application | Version | Image | Port | License | Upstream |
|---|---|---|---|---|---|
| Damn Vulnerable GraphQL Application | 2.2.0 | `dolevf/dvga:2.2.0` | 80 | MIT | [dolevf/damn-vulnerable-graphql-application](https://github.com/dolevf/damn-vulnerable-graphql-application) |
| OWASP Juice Shop | 17.6.0 | `bkimminich/juice-shop:v17.6.0` | 3000 | MIT | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) |
| OWASP WebGoat | 2023.7 | `webgoat/webgoat:2023.7` | 8080 | Apache-2.0 | [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) |
| OWASP crAPI | 1.0.6 | `registry.hub.docker.com/defenseunicorns/crapi:1.0.6` | 8080 | MIT | [OWASP/crAPI](https://github.com/OWASP/crAPI) |
| OWASP Mutillidae II | 2.0 | `dawyck/owasp-mutillidae:2.0` | 80 | Apache-2.0 | [OWASP/owasp-mutillidae](https://github.com/OWASP/owasp-mutillidae) |

Every image is pinned to a tag. **The images must be pulled before the
benchmark can run**; the laboratory does not pull them implicitly, so a
benchmark run never depends on the network at measurement time.

TestPHP and TestASP were evaluated and **not** included: both are
unmaintained, neither has a published container image, and both would
have to be built from source inside the measurement environment, which
would make the benchmark depend on a build step rather than on the
application. The vulnerability classes they cover (PHP injection, file
inclusion, information disclosure) are already covered by Mutillidae II,
which is maintained and containerised.

---

## 3. Running the laboratory

```bash
# Pull the images once.
docker pull dolevf/dvga:2.2.0
docker pull bkimminich/juice-shop:v17.6.0
docker pull webgoat/webgoat:2023.7
docker pull registry.hub.docker.com/defenseunicorns/crapi:1.0.6
docker pull dawyck/owasp-mutillidae:2.0

# Generate the Compose file and inspect it before starting.
b-hunters bench lab status

# Start the laboratory.
b-hunters bench lab up
b-hunters bench lab up --applications dvga,juice-shop

# Check what is running.
b-hunters bench lab status

# Tear it down completely.
b-hunters bench lab down
```

**Isolation properties:**

* The laboratory is a separate Docker Compose project (`bhunters-bench`)
  on its own bridge network (`bhunters-bench-net`).
* Every published port is bound to `127.0.0.1`, so the applications are
  not reachable from the network.
* The laboratory is never started automatically. It requires an explicit
  administrator action.
* `b-hunters bench lab down` removes the containers and their volumes.

The generated Compose file lives at
`$BHUNTERS_BENCH_DIR/docker-compose.bench.yml` (default
`/var/lib/b-hunters/bench`). Read it before starting if you want to
verify the isolation properties for yourself.

---

## 4. Running a benchmark

```bash
# Through the CLI.
b-hunters bench run --applications dvga --start-lab

# Through the API (requires the operator role).
curl -X POST https://platform/api/v1/benchmarks/runs \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"applications": ["dvga"], "start_lab": false}'
```

The runner, for each application:

1. waits for the container to answer on its port;
2. creates a scan whose scope is exactly that application, with
   `allow_private_network` enabled (the laboratory is on a private
   network);
3. waits for the scan to reach a terminal state;
4. matches the findings against the manifest's test cases;
5. records the outcome.

**Benchmark scans use synthetic accounts and disposable data.** The
laboratory applications are designed to be attacked; no test case modifies
data that another test case depends on, and the test cases that could
affect availability are marked as requiring a disposable fixture.

---

## 5. Scoring

### Outcomes

| Outcome | Meaning |
|---|---|
| `true_positive` | The vulnerability was expected and the platform reported it |
| `false_positive` | The vulnerability was not expected and the platform reported it |
| `false_negative` | The vulnerability was expected and the platform did not report it |
| `not_applicable` | The application does not contain this class |
| `inconclusive` | The probe could not be executed |

### Metrics

| Metric | Definition |
|---|---|
| Precision | `TP / (TP + FP)` |
| Recall | `TP / (TP + FN)` |
| F1 | `2 × (precision × recall) / (precision + recall)` |
| Detection rate per class | Detected / expected, per vulnerability class |
| Detection rate per application | Detected / expected, per application |
| Endpoint and route coverage | Discovered routes / known routes |
| Authentication completion rate | Completed workflows / attempted workflows |
| Duplicate finding rate | Extra findings / total findings |
| Median time to first valid finding | Median seconds to the first confirmed finding |
| Total scan duration | Wall-clock seconds for the run |
| Model usage and estimated cost | Tokens and the configured price estimate |
| Tool and agent failure rates | Failed tool calls / total; failed agent runs / total |

`not_applicable` and `inconclusive` cases are excluded from precision and
recall, and are reported separately so that they are never mistaken for a
pass or a failure.

### Deduplication

Findings are identified by a stable fingerprint computed from the
vulnerability class, the host, the path, the parameter and an optional
extra key. The detector is deliberately **excluded** from the fingerprint,
so two tools reporting the same issue collapse into a single finding with
a combined detector list.

---

## 6. Reading the results

```bash
b-hunters bench scores
```

```
True positives:      12
False positives:     1
False negatives:     4
Not applicable:      7
Inconclusive:        0
Precision:           0.9231
Recall:              0.75
F1:                  0.8261
Duplicate rate:      0.0833
Median first find:   41.2s
Total duration:      312.7s
```

### A measured run

The run below was executed against DVGA 2.2.0 running in the laboratory
on this machine. It is reproduced here verbatim from
`b-hunters bench scores`; it is not an illustration.

```
True positives:      5
False positives:     0
False negatives:     0
Not applicable:      3
Inconclusive:        0
Precision:           1.0
Recall:              1.0
F1:                  1.0
Duplicate rate:      0.0
Median first find:   0.567s
Total duration:      2.031s
```

Per test case:

| Test case | Outcome | Detected by |
|---|---|---|
| `dvga-introspection` | true_positive | `graphql_analysis` |
| `dvga-graphql-mutations` | true_positive | `graphql_analysis` |
| `dvga-graphql-sqli` | true_positive | `graphql_analysis` |
| `dvga-users-leak` | true_positive | `graphql_analysis` |
| `dvga-headers` | true_positive | `security_headers` |
| `dvga-rest-api` | not_applicable | – |
| `dvga-ssrf` | not_applicable | – |
| `dvga-xss` | not_applicable | – |

The findings that produced those outcomes:

```
medium  access_control        GraphQL field 'users' returns records without authentication
        evidence: {users} -> 2 record(s)
medium  access_control        GraphQL field 'audits' returns records without authentication
        evidence: {audits} -> 12 record(s)
low     graphql               GraphQL introspection is enabled
        evidence: __schema queryType=Query mutationType=Mutations types=29
medium  graphql               GraphQL exposes destructive mutations
        evidence: mutation fields: createPaste, editPaste, deletePaste, uploadPaste, importPaste, createUser, login
high    sql_injection         GraphQL argument 'filter' of 'pastes' is vulnerable to boolean-based SQL injection
        evidence: pastes(filter) benign=0 records, tautology=12 records
low     security_misconfiguration   Missing strict-transport-security header
        evidence: strict-transport-security is absent
```

**What this run does and does not measure.** The run used the
*deterministic* adapters only, because no model provider was configured
in that environment; the twelve agent tasks all failed with "no model
configured for this provider" and contributed nothing. The score is
therefore a measurement of the deterministic scanner layer against one
application and five expected weaknesses — not of the agent runtime, and
not of the platform as a whole. A run with a provider configured would
produce a different, and separately reportable, set of numbers.

Per-run detail, including the per-test outcome, the matched finding and
the evidence, is stored in `platform_benchmark_runs` and
`platform_benchmark_results` and is available through
`GET /api/v1/benchmarks/runs/{run_id}`.

### Comparing runs

Runs are stored with their configuration, so two runs can be compared
directly:

```bash
# in MongoDB
db.platform_benchmark_runs.find({}, {run_id: 1, summary: 1, config: 1}).sort({started_at: -1})
```

A regression is a run whose precision or recall fell below the previous
run **for the same configuration**. Comparing runs with different
profiles or different provider settings does not measure a regression.

---

## 7. Adding an application

1. Add a `BenchmarkApplication` to
   `b_hunters/platform/bench/manifest.py` with a pinned image, a licence,
   an upstream URL and the test cases.
2. Every test case needs a `test_id`, a `vuln_class` from
   `VULN_CLASSES`, an `expectation` and at least one
   `expected_evidence` marker.
3. Add the manifest to `default_manifests()`.
4. The laboratory Compose generator picks the application up automatically.
5. Run the benchmark harness tests:
   `pytest tests/bench -q`.

The manifest tests assert that the slugs and the test ids are unique, that
every vulnerability class is known, and that every expected severity is
valid — so a malformed manifest fails the test suite rather than
producing a meaningless score.
