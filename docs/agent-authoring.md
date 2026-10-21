# Authoring an agent

An agent is a **declaration**, not code. The platform's runtime executes
it; an administrator can create and version one from the UI without
touching the code base.

---

## 1. The pieces of a definition

```json
{
  "name": "Injection analyst",
  "role": "vuln_injection",
  "system_prompt": "You look for injection vulnerabilities…",
  "instructions": "Compare a benign value with one altered value…",
  "model_ref": "local-llm:qwen2.5-coder",
  "tools": ["http_request", "compare_responses", "list_findings"],
  "permissions": {
    "capabilities": ["network", "read_files"],
    "tools": ["http_request", "compare_responses", "list_findings"],
    "denied_tools": [],
    "escalation_capabilities": [],
    "max_output_bytes": 524288
  },
  "budget": {
    "max_rounds": 8,
    "max_tool_calls": 50,
    "max_tokens": 150000,
    "max_wall_clock_seconds": 900
  },
  "output_schema": {},
  "enabled": true
}
```

| Field | Meaning |
|---|---|
| `name` | Display name |
| `role` | Role identifier; must match a role the runtime knows |
| `system_prompt` | The role's own instructions. The shared operating policy is prepended automatically |
| `instructions` | Supplementary notes shown in the workspace |
| `model_ref` | An optional model override for this role |
| `tools` | The tools this agent may call. An empty list means "no tools" |
| `permissions` | The capability model |
| `budget` | The four independent limits |
| `output_schema` | The JSON schema the agent's answer must satisfy |
| `enabled` | Whether the agent participates in scans |

---

## 2. Capabilities

A capability is a permission class. A tool declares the capabilities it
needs; an agent must hold them.

| Capability | Grants |
|---|---|
| `network` | Outbound HTTP to in-scope targets |
| `read_files` | Reading files in the agent's workspace |
| `write_files` | Writing files in the agent's workspace |
| `shell` | Running allow-listed commands in the workspace sandbox |
| `package_install` | Installing packages — **never granted by any built-in role** |
| `external_download` | Fetching arbitrary remote resources |
| `state_changing` | Requests that mutate the target |

`denied_tools` is applied last and always wins. `escalation_capabilities`
lists capabilities the role may request under explicit human approval; the
built-in roles leave it empty.

**The rule of least surprise.** If a role does not need a capability, it
does not get it. The `recon` role cannot run a shell command. The
`verifier` cannot write files. The `adjudicator` cannot touch the network.

---

## 3. The output schema

The agent's final answer is a JSON object. The default schema is:

```json
{
  "conclusion": "What you concluded, in 1-5 sentences.",
  "confidence": "none | low | medium | high | confirmed",
  "observations": ["Concrete observations that back the conclusion."],
  "uncertainty": "What you could not determine and why.",
  "next_step": "The single most useful next action, or empty.",
  "findings": [
    {
      "title": "…",
      "vuln_class": "…",
      "severity": "critical | high | medium | low | info",
      "host": "…",
      "path": "…",
      "parameter": "…",
      "cwe": "CWE-89",
      "affected_url": "…",
      "summary": "…",
      "confidence": 0.7,
      "remediation": "…"
    }
  ],
  "delegate": { "role": "…", "objective": "…", "target": "…" }
}
```

The verifier uses a different schema with a `verdict`
(`confirmed | likely | unverified | inconclusive | rejected`) and a
`reproduction` field.

**A finding proposed by an agent is always created as `unverified`.** Only
the verification workflow can change that, and it does so from evidence,
not from the proposing agent's confidence.

---

## 4. Writing a good system prompt

The shared operating policy already covers scope, safety, untrusted
content, evidence, secrets and budgets. Your prompt should cover what is
*specific to the role*.

Good:

> You look for server-side request forgery and path traversal. For SSRF,
> use the controlled callback host the platform provides, or an in-scope
> host that is known to be reachable, and never a public scanning service.
> For path traversal, use a non-existent, obviously inert path such as a
> unique marker with traversal segments, and look for evidence that the
> marker was resolved rather than rejected. Never attempt to read files
> such as /etc/passwd or private keys — demonstrating that the traversal
> is filtered is the goal, not reading the target's filesystem.

Bad:

> You are a penetration tester. Find vulnerabilities. Be thorough.

The difference is that the good prompt says what to *do*, what *not* to
do, and what evidence to look for. "Be thorough" produces unbounded
requests and unbounded tokens; the budget enforces the limit, but the
prompt should not ask for it.

---

## 5. Versioning

Definitions are immutable. Creating a definition with the same
`(name, role)` produces a new version. A scan records the version it
used, so a scan can be reproduced exactly.

To change a built-in role:

1. Create a new definition with the same `role` and the tools,
   permissions and budget you want.
2. Assign it to a scan profile.
3. The built-in version remains available for older scans.

---

## 6. Testing a new agent

```bash
# 1. The definition must load.
b-hunters admin seed-roles

# 2. The role must be reachable.
curl -s -H "Cookie: $COOKIE" https://platform/api/v1/admin/agent-roles | jq '.roles[] | select(.role=="your_role")'

# 3. Run a scan with only that role and read the agent's conclusion.
```

Then check the *Agent workspace* page: the agent's messages, its tool
calls and its conclusion are all persisted and visible.

---

## 7. What an agent may not do

Even with a valid definition, an agent cannot:

* contact a host outside the scan's authorised list;
* use a tool that its role was not granted;
* read or write outside its own workspace;
* run a program that is not on the shell allow-list;
* install a package or download and execute remote code;
* mark its own finding as confirmed;
* exceed its budget.

These are enforced in the tool gateway, not by the prompt. The prompt
states them so that the model does not waste turns discovering them.
