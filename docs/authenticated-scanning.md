# Scanning with the target's own session

Most of what an application actually exposes is behind a login. The
WebGoat lessons, an admin panel, a customer's own data — six of the
vulnerabilities a verification run measured were unreachable because
the platform had no way to log in.

The platform logs in with an **identity**: a stored account, its
credentials encrypted, and the session it captured.

## The vault

An identity holds:

| Field | What it is |
|---|---|
| `name` | what the operator calls it |
| `kind` | `form`, `header`, `cookie` |
| `login_url` | where the login form is |
| `username`, `password` | the credentials, encrypted |
| `totp_secret` | for an account with a one-time password, encrypted |
| `username_field`, `password_field` | the names of the form fields |
| `success_url`, `success_selector` | what a successful login looks like |
| `verify_url`, `verify_selector`, `verify_text` | a page that *requires* the session |
| `headers`, `cookies` | for an identity that is a header or a cookie |

The credentials are encrypted with the deployment's key
(`BHUNTERS_SECRET_KEY`, AES-GCM). **The API never decrypts.** It
stores, it masks, it returns a mask. The runner decrypts, and only the
runner.

```bash
curl -X POST http://bhunter/api/v1/identities \
  -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d '{
    "name": "the test account",
    "kind": "form",
    "login_url": "http://172.25.0.13:3000/rest/user/login",
    "username": "alice@example.test",
    "password": "...",
    "username_field": "email",
    "password_field": "password",
    "verify_url": "http://172.25.0.13:3000/rest/user/whoami"
  }'
```

## The recorder

The recorder runs in the runner, in a job of its own:

```bash
curl -X POST http://bhunter/api/v1/identities/<id>/login -H "X-CSRF-Token: $CSRF"
# 202 {"job_id": "..."}
```

It fills the target's login form, keeps the session and checks it
against the identity's `verify_url` — a page that *requires* the
session. A `success_url` that is also reachable without one proves
nothing, so the check is made against the protected page.

The session is stored encrypted on the identity and handed to the
workers with the task they receive.

## The browser is inside the scope

The recorder drives a browser, and a browser can reach anything the
page can. Two rules keep it honest:

* every request the page makes — document, XHR, fetch, WebSocket — is
  checked against the scan's `ScopePolicy` before it leaves, including
  every redirect hop;
* the service worker is blocked, because a service worker is a second
  network stack inside the page that the request hook does not see.

The check is the platform's own `ScopeEnforcer` — the same one every
other request path uses. A browser that had its own idea of the scope
would be a second answer to the same question.

## The preflight

Before a scan that names an identity runs, the session is checked. If
it is missing, expired or failing, it is refreshed through the
recorder.

A refresh that fails **fails the scan**, unless the template says:

```json
{ "on_login_failure": "continue_unauthenticated" }
```

Either way a notification is sent: an operator who asked for an
authenticated scan has to hear that it did not get one.

The check is before the scan, not during it. A scan that finds out in
the worker phase that its session has expired spends the whole worker
phase on a target it cannot reach.

## The comparison

An object-level authorisation flaw is invisible to a single session: the
request that is refused to you is the request that is allowed to
somebody else.

A scan may name **two** identities. The first is the primary one; the
second is what the `compare_access` tool uses: it makes the same
request as each of them and puts the answers side by side. When they
differ, that difference is the evidence.

```bash
curl -X POST http://bhunter/api/v1/scans -H "X-CSRF-Token: $CSRF" -d '{
  "name": "the authenticated scan",
  "targets": {"urls": ["http://172.25.0.13:3000/"], "authorized_hosts": ["172.25.0.13"]},
  "identity_ids": ["id-alice", "id-bob"]
}'
```

## What the workers get

The session travels with the task the workers receive, in an `auth`
payload: the cookies and the headers. The values are the target's and
they are never in the report, never in the database, never in a log
line.

Every worker that supports custom headers takes them: nuclei
(`-H`), katana (`-H`), sqlmap (`--headers`), dalfox (`-H`), ffuf
(`-H`). The rest ignore the payload and are unaffected.

## The browser the agents drive

The agents have a browser of their own: `goto`, `click`, `fill`,
`press`, `wait`, `extract_text`, `extract_html`, `screenshot` and
`session_status`.

There is no action that reads the session and no action that runs
JavaScript in the page. A model that can read the cookies can carry
them away, and a model that can run code in the page can do anything
the page can. The outputs are stripped of anything that looks like a
credential, and a screenshot becomes an artifact the operator can
look at.

## The browser crawler

`browser_crawl` crawls the target the way a page uses it, not the way
a link does: it follows the links, the endpoints the page fetches over
XHR or fetch, and the hash routes it navigates to. An application whose
API is only reachable from its own front end is invisible to a crawler
that only follows links.
