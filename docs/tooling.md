# The tooling: what is in the fleet, and what is missing

A survey of the GitHub ecosystem against the seven gaps a verification
run measured, in the order of how much each closes.

## The gaps

| # | The gap | The cause |
|---|---|---|
| 1 | Eight of twelve agent roles never started | Orchestration, not tooling: the budget was gone before the last roles had a slot |
| 2 | A SQL injection in a live search endpoint was missed | sqlmap was pointed at the root URL and asked for level 1 / risk 1 |
| 3 | No JavaScript bundle analysis | The fleet extracts endpoints from JavaScript; nothing analyses what is *in* it |
| 4 | Six documented vulnerabilities are unreachable | They are behind a login, and there was no login |
| 5 | Out-of-band vulnerabilities cannot be confirmed | There is no callback server of the platform's own |
| 6 | The header and misconfiguration checks are shallow | The platform checks a handful of headers itself |
| 7 | The findings are grouped and scored wrongly | The agent roles write their vulnerability class in free text |

## What the survey found

### Add

| Tool | Why | Constraint check |
|---|---|---|
| **[ffuf](https://github.com/ffuf/ffuf)** (16,960★, MIT, 2026-09) | The fuzzing engine the fleet lacks. `paramspider` finds parameter *names*, `dirsearch` brute-forces *paths*; nothing mutates a *value*, which is what an object-level authorisation flaw needs. `ffuf -w ids.txt -u "https://target/rest/basket/FUZZ" -H "Cookie: token=$SESSION" -mc all -fc 401,404 -json -noninteractive` | Headless, JSON output, no account |
| **[interactsh](https://github.com/projectdiscovery/interactsh)** (4,610★, MIT, 2026-10) | The OAST server *and* client for out-of-band findings. `interactsh-client -server oob.example.com -token <token> -json` emits JSON Lines, so an agent can *confirm* a blind finding instead of guessing | Needs a public domain with delegated nameservers — the platform's own callback service is the better answer for a single operator |
| **[retire.js](https://github.com/RetireJS/retire.js)** (4,195★, 2026-10) | Vulnerable library versions in a JavaScript bundle — the thing bundle analysis should actually produce. `retire --path ./js-bundle/ --outputformat json --outputpath retire.json` | The site-scanner variant is 11★; the CLI is the right tool |
| **[gitleaks](https://github.com/gitleaks/gitleaks)** (30,523★, MIT, 2026-10) | Secrets in the bundle. `gitleaks detect --source ./js-bundle/ --report-format json` | MIT, unlike trufflehog's AGPL. Trufflehog also *verifies* a key against the provider, which is worth more — but it is network copyleft |
| **[naabu](https://github.com/projectdiscovery/naabu)** (6,339★, MIT, 2026-10) | Fast port discovery in front of nmap, and the same output conventions as nuclei and katana. `naabu -host target -p top-1000 -j -silent -o ports.jsonl` | Not a nmap replacement: a pre-filter |

### Use what is already there, better

| Tool | The flag that closes a gap |
|---|---|
| **katana** (17,772★) | `-jsl` parses the JavaScript for endpoints, `-jc` crawls it, `-H` sends the session. Already partly on; the depth and the concurrency were not |
| **nuclei** (32,466★) | `-iserver` / `-itoken` point it at a callback server instead of the public oast.pro — today any out-of-band detection depends on a third party |
| **sqlmap** (38,817★) | `--level=3 --risk=2 --crawl=2 --technique=BEUSTQ --ignore-code=401`. It has no crawler of its own, so it must be handed the parameterised URL the crawler found |
| **wapiti** (1,900★) | It already has `--cookie`, `--auth` and `--login-credentials`: the login gap may be reachable without a new worker |
| **dalfox** (5,340★) | It already emits JSON, JSONL and SARIF |

### Retire

| Tool | Why |
|---|---|
| **gospider** | `jaeles-project/gospider` has not been committed to since April 2024. `katana` is its successor and is already in the fleet. Every reference is listed in §"The references" below |
| **waybackurls** | The wayback worker already runs `waymore`, which pulls from the Wayback Machine, CommonCrawl, urlscan.io and AlienVault OTX at once. The stale tool was retired from the worker |
| **xray** | `chaitin/xray` was last pushed in October 2024 and it is a host-side scanner, not a web one. It does not close any of these gaps |

### Not worth it

`arachni`, `w3af`, `noseyparker` and `mozilla/http-observatory` — all archived.
`jsluice`, `LinkFinder`, `waybackurls`, `gf`, `unfurl`, `corsy`, `SecretFinder` — all stale
for years. `dnschef` — the best interactsh alternative, but last pushed in 2024.
`requestrepo` — excellent, but 546★ is below the bar this platform sets.
`Smap` — needs a Shodan API key. `Snyk`, `Burp Suite Pro` — need accounts.
`jsql-injection` — a GUI. `zmap` — raw sockets and an Internet-scale design.
`nikto` — slow, noisy, and duplicates nuclei's misconfiguration coverage.
`retire-site-scanner` — 11★.

`ZAP` deserves its own note: it is the broadest gap-closer available —
a login framework, hundreds of passive rules, its own callback service and
SARIF output. It was not adopted, for two reasons: the JVM image is
heavy and its active scan is slow, and the scan's budget is the
constraint here. Its *passive* mode would fit, but its rules overlap
nuclei's misconfiguration coverage, and the header and cookie rules it
adds are the ones the platform can check itself.

## What no tool closes

**The budget.** More workers make it worse: seventeen already compete
for it. The fixes are orchestration, and they are in the platform:

* every worker is bounded — a rate, a concurrency, a timeout — so that
  no single tool can spend the budget of the scan;
* the roles start in the order of their yield, not in the order they
  happen to be listed;
* the roles that *judge* the findings keep a reserved share of the
  budget, because a finding without a verdict is a guess.

**The login.** A tool can carry a session; it cannot obtain one. The
identity vault and the login recorder obtain it, and the survey's
finding is that every tool in the fleet already accepts the session
once it exists — which is why the recorder was built before another
worker was added.

## The references to gospider

Removing gospider from the fleet touches these places:

* `docker-compose.platform.yml` — the service
* `b_hunters/platform/scanners/registry.py` — the adapter and the spec
* `b_hunters/platform/scanners/worker_output.py` — the worker that owns
  the link field
* `b_hunters/platform/agents/orchestrator.py` — the worker list
* `dashboard/workers.py` — the dashboard's worker list
* `tools/verify_workers.py` — the verification script
* `scripts/start_worker_stack.sh` — the development stack
* `b_hunters/platform/bench/workers.py` — the path-list prefix
* `docs/workers.md`, `docs/architecture-audit.md`,
  `docs/implementation-report.md` — the documentation
