# B-Hunters 1.5.0 — what changed

The release that gives the path scanners something to test, and that
stops the platform from saying a scanner found nothing when it never
looked at anything.

## The scanning

**The routes a bundle hides.** The REST surface of a single-page
application is not a set of links: it is strings inside the JavaScript
bundle. A crawler follows links, so it never sees them, and a scanner
that tests parameters has nothing to test. Against the running Juice
Shop the crawler now recovers **111 routes** from the 1.2 MB bundle,
among them the endpoint the benchmark had recorded as missed:

```
GET /rest/products/search  params=('q',)
  -> http://172.25.0.13:3000/rest/products/search?q=
```

The routes are read out of the bundle statically. Nothing is executed
and nothing is fetched. A template literal is handled, so a route
written as `` `${this.hostServer}/rest/products/search?q=${t}` `` is
recovered with its parameter, and the result is the form the scanner's
own filter keeps and can vary.

**The routes are recorded where the console shows them.** They are
written into the asset inventory as `api` assets, with the bundle they
came from. They are not pages: they are never fetched, and they do not
count against the crawl's limit.

## The reporting

**A scanner that was handed nothing is not a scanner that found
nothing.** The path scanners filter the crawler's list down to the URLs
that carry a parameter. For the laboratory the filter left **nothing** —
fifteen URLs crawled, none with a parameter — so the scanner exited in
eighty-three milliseconds having tested nothing, and the platform
reported it as *"ran, found nothing"*.

That was a false clean bill of health for work that never happened. The
count was already computed by `candidates()` and thrown away by
`_status()`. It is now recorded with the worker's outcome, and there is
a sixth reason:

| Reason | Meaning |
|---|---|
| `ran, had nothing to test` | it is a path scanner, it ran, it produced no finding, and the crawler found no URL with a parameter for it to test |

This is the same rule the platform already applies to the agent roles,
where a role that was cut off by the deadline must not look like a role
that found nothing.

## The artefacts

**A published artefact is a task resource.** The platform's benchmark
harness wrote the path list with a bare S3 client, so no task referenced
it and the Karton collector removed it. The mechanism now lives in
`b_hunters/artifacts.py`, with the key convention in one place, and a
test asserts that it agrees with the workers' own `encode_filename` —
byte for byte, including the shortening of a very long name. A producer
that names an artefact differently writes to a key the consumer never
reads.

## The documentation

The architecture audit was written against the upstream organisation and
is six months behind the running system. The issue list has been
rebased against the running system, and the specs for what is left are
in `docs/superpowers/specs/`:

| Spec | Covers |
|---|---|
| `2026-11-16-rebaseline-design.md` | the issue list, and the root cause of the scanners that produced nothing |
| `2026-11-16-scanner-handoff-integrity-design.md` | the scanner handoff, the routes, the finding classes |
| `2026-11-16-supply-chain-and-secrets-design.md` | the committed binary, the credentials, the licences |
| `2026-11-16-quality-gates-design.md` | the frontend tests, the type check, the destructive verification script, the database that is killed under load |
| `2026-11-16-agent-lifecycle-design.md` | the roles that spend every round, the applications that cannot be scanned |
| `2026-11-16-legacy-cli-report-design.md` | the legacy report, which reads the wrong collection |

**The version.** The package carried a second copy of the version
number, and the API answered the health check with a literal. Both
drifted from the release — the package said 1.4.0 and the health check
said 1.3.0, in the same image. There is now one version, and a test
walks the source for a version literal so that a second copy cannot be
added quietly. `1.4.1` is `1.4.0` with that fix; the scanning and the
reporting are the same.

## The fleet

**A scan runs the workers it asked for.** The Karton router hands a
task to every consumer whose filters match it, so a task for
`subdomain`/`new` reached thirteen workers whatever the scan asked
for. The native adapters had always respected the profile's scanner
list; the workers did not — so a recon scan ran sqlmap, xray and ffuf
against the target as well, at the same time.

The list of the workers a scan wants now travels with the task, and a
worker that is not on it ends the task without touching the target —
the same way Karton ends a task whose binds are no longer valid.

**The database does not grow for ever.** The job that deletes the
expired events, artefacts and sessions was written and never called:
every scan left all three behind, and only an operator with a shell
could remove them. The runner runs it now, once an hour.

**The report keeps the metadata, not the bodies.** The screenshot
worker wrote the body of every page, the cookie jar and the network
log into the report. The body is large, it is the page the target
serves to an anonymous visitor, and the cookies in it are the target's
own session — which does not belong in a database that every later
scan reads back.

## The scope

**A scan can name the hosts it must not touch.** A bug bounty programme
names the assets that are out of scope, and the wildcard that covers the
domain covers them too — so the exclusions have to be said separately,
or a scan of `*.rapyd.net` would touch `support.rapyd.net`, which the
programme rules out explicitly.

They are enforced in two places, because the workers are separate
containers that discover hosts of their own: the platform refuses the
target outright, and the workers inherit the list with the task and
refuse the host before they send their first request.

**A wildcard is a host the platform can authorise.** The scope engine
has always matched `*.example.com` — the form a programme uses to cover
a domain — but the API's validator rejected it, so the most useful way
of expressing a scope could never be said. `docs/configuration.md` §7.

## The load

**The load a worker puts on a target is the operator's choice.** sqlmap,
dalfox and the template scanner each had a fixed number of requests in
flight. A scan of a laboratory and a scan of a production asset are not
the same job.

The 1.3.0 notes are in `docs/release-notes-1.3.0.md`.
