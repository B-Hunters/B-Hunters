# The identity vault

A scan can log in. The credentials it uses are the target's secrets, and
they live in the vault: an identity is a named set of credentials — a
username and a password, a bearer token, a cookie, a header — that a
scan can name.

## What an identity holds

```
identity_id, name, kind (form | basic | bearer | cookie | header),
login_url, username, username_field, password_field,
success_url, success_selector,
verify_url, verify_selector, verify_text,
password_ciphertext, totp_secret_ciphertext,
headers_ciphertext, cookies_ciphertext, storage_state_ciphertext,
status, last_login_at, last_used_at, session_expires_at,
created_at, updated_at
```

Every secret is encrypted with the deployment's `BHUNTERS_SECRET_KEY`
before it is stored. The API accepts a credential and never returns it:
the response says whether the identity *has* a password, not what it is.

## Why a deployment without a key refuses a credential

A secret in the clear is worse than no secret: it is copied into a
backup, a log, an export. The vault refuses to store a credential when
the deployment has no key, rather than storing it in the clear.

## The session

The login recorder captures the browser state of a session — the
cookies and the local storage — and stores it encrypted on the identity.
The session is what the workers and the agents use.

The identity names a `verify_url`: a page that **requires** the session.
A `success_url` that is also reachable without one proves nothing, so
the recorder checks the protected page and not the page it was sent to.

## How a scan uses an identity

The scan names the identities it uses:

```json
{"identity_ids": ["id-abc"]}
```

The first is the primary one; a second is what an access-control
comparison uses.

The runner decrypts the session and hands it to the workers with the
task they receive:

```
karton task payload: {"domain": ..., "auth": {"cookies": {...}, "headers": {...}}}
```

The workers read it with `BHunters.auth_headers(task)` and pass it to
their tools — nuclei with `-H "name: value"`, sqlmap with its cookie
option, and so on. The session is never written into the report and
never leaves the process that needs it.

## The API

| Method | Path | What it does |
|---|---|---|
| POST | `/api/v1/identities` | Store an identity; the secrets go in and do not come out |
| GET | `/api/v1/identities` | Every identity, without its secrets |
| GET | `/api/v1/identities/{id}` | One identity, without its secrets |
| PATCH | `/api/v1/identities/{id}` | Change an identity |
| DELETE | `/api/v1/identities/{id}` | Remove it, with its secrets |
| POST | `/api/v1/identities/{id}/login` | Queue a login: `202` and a job id |
| GET | `/api/v1/identities/{id}/status` | Whether it has a session, and when it was used |

The login is queued rather than run: the recorder needs the browser and
the credentials, and the API does not decrypt. The runner does both.

## The recorder

The recorder runs in the runner, in a job of its own:

```bash
b-hunters admin ... # or the API:
curl -X POST http://bhunter/api/v1/identities/<id>/login
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
