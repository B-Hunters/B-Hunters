# The out-of-band callback service

A blind vulnerability cannot be confirmed by looking at the response.
An SSRF that fetches a URL the platform controls, a blind XSS that
loads an image, a command injection that answers on another host — the
evidence is the target reaching back.

The platform runs its own callback service for this. It is the only
part of the platform that is exposed to the outside world, and it is
narrow on purpose.

## Why the platform's own

A public out-of-band service (oast.pro, interactsh.com and the rest)
works, and it is what most tools use by default. Two reasons not to:

* **A public service sees every test the operator runs.** The target's
  hostname, the token in the URL, the time of the test — all of it
  belongs to a third party.
* **It cannot be pointed at a private network.** The address has to be
  reachable by the *target*, which on a laboratory network means a
  hostname the target can resolve. A public service cannot be.

The platform's own service is the operator's own machine, on the
operator's own network, and the operator's traffic stays there.

## How it works

```bash
# The service runs as its own container.
docker compose -f docker-compose.platform.yml up -d callbacks

# The address the target reaches.
BHUNTERS_CALLBACK_BASE_URL=http://<the-host>:8081
```

An agent asks the `create_callback` tool for an address:

```python
create_callback(label="the ssrf in the image url")
# {"url": "http://<the-host>:8081/cb/<32 random bytes>", ...}
```

It puts the address in the request it is testing, and then asks
`list_callbacks` what came back. A callback that arrives is the
evidence that the finding reproduces; a finding with no callback is a
hypothesis.

The tools are only offered to the roles that can use them: the SSRF
role, which is the role whose whole job is to make the target fetch a
URL the operator controls.

## What the service records

| Field | What it is |
|---|---|
| `method` | the method of the request |
| `path` | the path it came to |
| `headers` | the headers it carried, up to 64 of them |
| `body` | the body, up to 4 KiB |
| `source` | where it came from |
| `at` | when it arrived |
| `count` | how many times it arrived |

The same token and the same path is one callback that happened more than
once: the count says how many times, and the first arrival says when.

## The rules it follows

* **A token is unguessable.** 32 bytes, URL-safe. A callback service
  that answers on a guessable token is an open relay.
* **A token expires.** Twenty-four hours by default. An expired token
  records nothing.
* **Only the path of a live token answers.** Every other path is a
  404, and the service does not confirm that a token exists. It cannot
  be used as a general proxy or as a place to put something.
* **The body is bounded.** 64 KiB read, 4 KiB kept. A callback can
  carry anything, and the platform is not a place to keep it.

## The database

| Collection | What it holds |
|---|---|
| `platform_callback_tokens` | the tokens: the label, the scan, the expiry |
| `platform_callbacks` | the hits: the method, the path, the headers, the body, the source |

## What is not here

There is no DNS service and no SMTP sink. A vulnerability that reaches
back over DNS or over email is not confirmed by this service; it would
need a different one. The HTTP callback covers the common case — an
SSRF that fetches a URL, an XSS that loads an image — and the platform
says so rather than pretending to cover the rest.
