# The asset inventory

The platform used to keep the URLs it found as a flat list inside the
worker output, where the JavaScript files were filed under a generic
kind and the images were not collected at all. A scan of WebGoat
persisted 15 URLs, 7 paths, 123 findings, 1 technology and 22
screenshots — and no JavaScript file and no image.

The inventory is one collection of every URL the platform knows about a
target, with the kind of the URL, where it came from and what it is.

## The three sources

| Source | What it finds |
|---|---|
| The `asset_crawl` adapter | Every URL the target links to or calls, fetched in scope |
| The scanner workers | The URLs, paths and JavaScript files the seventeen workers reported |
| The fingerprinters | Every URL the service-fingerprinting adapter fingerprinted |

The merge runs at the end of the worker phase and folds the three into
one row per URL. A URL that the crawler found *and* that `katana`
reported is **one row** whose `sources` lists both — the deduplication
is by the normalised URL, so the count of the assets is the count of
the URLs and not the count of the observations.

## The classification

Each asset has a `kind`:

| Kind | What it is |
|---|---|
| `page` | An HTML document |
| `js` | A JavaScript file |
| `image` | An image the target serves |
| `css` | A stylesheet |
| `api` | An API endpoint: a JSON or XML response, or a path that looks like one |
| `other` | Everything else |

The classification is by the response content type first, by the file
extension when there was no content type, and by the path for a URL
that was never fetched.

Each asset also has a `scope`: `first_party` for a URL on an
authorised host, `external` for a reference to a third party. An
external reference is **recorded and never fetched** — a scan does not
send a request to a CDN because a page links to it. The JavaScript tab
hides the third-party files by default: "which JavaScript files does
this site serve" must not answer with jQuery from a CDN.

## The collection

`b_hunters/platform/assets.py` holds the normalisation and the
classification:

* `normalise_url(url)` — lowercases the scheme and the host, drops the
  default port, normalises the path, drops the fragment, sorts the
  query and **redacts the credential-shaped query parameters**. A token
  in a query string does not become a stored secret. It also drops the
  userinfo, because a password in a URL must not reach the database.
* `redact_query(query)` — replaces the value of a parameter whose name
  looks like a credential with `[REDACTED]`.
* `classify(content_type=..., url=..., path=...)` — the kind of a URL.
* `is_external(url, authorized_hosts)` — whether the URL is outside the
  scope. It uses the platform's own host matching, so the wildcard
  rule is not implemented twice.

## The crawler

The `asset_crawl` adapter is a native adapter: it runs inside the
platform, in the scanner phase, through the same `ScopeEnforcer` as
everything else. It follows the same-origin links and the same-origin
`fetch`/XHR targets it can see in a response, and it records the
`src`/`href` attributes. It does not execute JavaScript.

Its limits: **2000 assets per scan, depth 3, 256 KB read per
response**, GET only, in scope only, at the scan's own rate limit and
concurrency.

It runs in a **second wave** of the native adapters, after the
fingerprinters. The reason is the seed list: the crawler starts from
the scan targets and from the URLs the fingerprinters recorded, and
every native adapter used to run in one concurrent gather, so those
rows did not exist yet when the crawler started.

## What is stored

One row per URL:

```
asset_id, scan_id, url, host, path, kind, scope, status_code,
content_type, size_bytes, depth, sources, source, discovered_from,
extension, first_seen_at, last_seen_at
```

**Metadata only.** No body, no image byte, no request. The inventory
tells you what the target serves and where it came from; it is not a
copy of the target.

## The agents

The `list_assets` tool used to read `context.metadata["assets"]`, a
dictionary nothing ever populated, so it always returned zero. It now
reads the inventory, with the old kind names kept as aliases
(`javascript` is `js`) and the result carrying a `by_kind` count so an
agent can see the shape of the surface before listing it.

## The API

```
GET /api/v1/scans/{scan_id}/assets?kind=&scope=&limit=&offset=
```

It returns the assets, the count of what it returned and the count per
kind for the whole scan — the counts describe the inventory, not the
filter.

## The console

Three tabs: **URLs** (the whole inventory with a type filter and a
first-party/third-party toggle), **JS** (the JavaScript files, first
party by default) and **Images** (the images the target serves).
