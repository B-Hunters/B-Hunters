# B-Hunters 1.5.2 — what changed

The release that believes what a host says, and that lets the discovery
worker do its job.

## The load a target is under

**A host that says "not now" is not asked again.** The edge of the
target answered `429` and, in the header, said for how long it wanted
to be left alone: `retry-after: 51804` — fourteen hours. The scanner
read the `429`, drained its token bucket, and carried on asking, and
every question it asked extended the block.

The answer is kept now:

* the `Retry-After` header is read, whether it counts seconds or names
  a moment (`parse_retry_after`);
* the policy holds the pause per host (`ScopeEnforcer.pause_host`), and
  no request to that host is made while the pause runs;
* the crawl leaves the host alone for the rest of the scan and says so
  in its report — a crawl that waits fourteen hours inside a scan is a
  crawl that never finishes.

**The findings of every host of a scan are read.** The discovery
worker gives every host it finds a report of its own, because that is
where the workers write what they find. The platform read only the
report of the target, so the findings of a subdomain were in the
database and never in the scan.

## The discovery

**The discovery worker never discovered anything.** The platform
publishes one task — the domain to scan — and the discovery worker is
the head of the chain. Its `single` path, the one the platform always
takes, seeded the report of the target and republished the target: it
never ran a discovery tool. Subfinder, assetfinder, findomain, vita
and Sublist3r sat in the image and none of them was ever executed.

A scan of `*.rapyd.net` found **zero** subdomains, and the only host
it ever looked at was the one that was named. The discovery now runs
in that path as well, and every host it finds is handed to the rest of
the fleet — with a report of its own, and only if the scope allows it.

## The scans that never ended

**A scan that is stopped before it runs now ends.** The stop endpoint
cancelled the job and set the scan to `stopping`. The runner that
would have noticed the stop was never going to run, so the scan said
`stopping` for ever — and the console cannot tell that from a scan that
is still going. A scan that never ran is now cancelled by the stop
itself.

## The fleet

**A bind left behind by a worker that has stopped is released.** The
platform had one: `B-Hunters-GoSpider`, retired in `6da191f`. It did
no harm — the bridge stopped counting a bound queue with no consumer
as a running worker — but the queue state was a lie.

**A test that had been failing since the last release now passes.** The
online-detection change altered the contract of `_queues()`, and the
integration test's fake was not updated with it, so the suite has been
red on that one test since.

## The tests

```
tests/unit/test_retry_after.py          10 tests
tests/unit/test_karton_bridge.py        15 tests
tests/integration/test_online_identities.py  5 tests
tests/integration/test_scan_jobs.py     the stop of a scan that never ran
tests/unit/test_subrecon_discovery.py   4 tests
```
