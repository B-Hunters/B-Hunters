"""Central scope enforcement.

This module is the single choke point that every HTTP-capable code path in
B-Hunters must pass through: scanner adapters, agent tools, the browser
automation tool, and the Karton workers.

Design rules (see ``docs/threat-model.md``):

* Only hosts that the operator explicitly authorised may be contacted.
* Every resolved IP address is validated, not just the hostname, so a DNS
  record that flips to ``127.0.0.1`` between validation and connection
  (DNS rebinding) cannot reach a loopback service.
* Loopback, private, link-local, CGNAT, multicast and cloud-metadata
  destinations are refused unless an isolated-lab configuration explicitly
  opts in.
* Redirects are validated hop by hop; a redirect may never widen the scope.
* Request rates, concurrency, payload sizes, response sizes and the total
  scan duration are bounded.
* State-changing requests require an explicit policy flag.

A prompt telling an agent to "only scan in-scope hosts" is *not* a control.
This module is.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

#: Cloud metadata endpoints that must never be reachable.
METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP / OpenStack
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud (legacy)
        "fd00:ec2::254",  # AWS IMDSv6
    }
)

#: Suffixes that resolve to loopback on many systems.
_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


class ScopeViolation(Exception):
    """Raised when an operation would leave the authorised scope."""

    def __init__(self, message: str, *, url: str = "", host: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.url = url
        self.host = host


@dataclass(frozen=True)
class ScopePolicy:
    """The set of destinations a scan is allowed to touch."""

    #: Explicitly authorised hosts.  ``*.example.com`` wildcards are allowed.
    authorized_hosts: tuple[str, ...] = ()
    #: Optional allow-list of TCP ports.  Empty means "any port on an
    #: authorised host".
    authorized_ports: tuple[int, ...] = ()
    #: URL path prefixes that must never be requested.
    excluded_paths: tuple[str, ...] = ()
    #: Hosts that are explicitly denied even if a wildcard would match.
    denied_hosts: tuple[str, ...] = ()
    #: Allow connections to loopback/private/link-local/metadata addresses.
    #: Only ever enable this for an isolated laboratory network.
    allow_private_network: bool = False
    #: Allow plain ``http://``.
    allow_http: bool = True
    #: Allow requests that mutate server state (POST/PUT/PATCH/DELETE).
    allow_state_changing: bool = False
    #: HTTP methods considered non-mutating.
    safe_methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    #: Maximum requests per second towards a single host.
    max_requests_per_second: float = 10.0
    #: Maximum simultaneous in-flight requests.
    max_concurrency: int = 16
    #: Maximum number of bytes read from a single response body.
    max_response_bytes: int = 8 * 1024 * 1024
    #: Maximum number of redirects followed for a single request.
    max_redirects: int = 5
    #: Default per-request timeout in seconds.
    timeout: float = 20.0
    #: Absolute wall-clock budget for the whole scan.
    max_duration_seconds: int = 3600

    def matches_host(self, host: str) -> bool:
        """Return ``True`` when *host* is covered by the authorised list."""
        if not self.authorized_hosts:
            return False
        host = _normalize_host(host)
        for denied in self.denied_hosts:
            if _host_matches(host, _normalize_host(denied)):
                return False
        for pattern in self.authorized_hosts:
            if _host_matches(host, _normalize_host(pattern)):
                return True
        return False

    def is_path_excluded(self, path: str) -> bool:
        normalized = path or "/"
        for excluded in self.excluded_paths:
            if not excluded:
                continue
            if normalized.startswith(excluded):
                return True
        return False


def _normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        # Normalise IDNs to their ASCII form so wildcards behave.
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return host


def _host_matches(host: str, pattern: str) -> bool:
    """Match *host* against *pattern* supporting a leading ``*.`` wildcard.

    A ``*.example.com`` pattern matches the *subdomains* of ``example.com``
    but deliberately not the apex ``example.com`` itself.  Including the
    apex would widen the scope beyond what an operator who wrote
    ``*.example.com`` intended, so the apex has to be authorised
    explicitly.
    """
    if not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    if "*" in pattern:
        return fnmatch.fnmatchcase(host, pattern)
    return host == pattern


def is_blocked_ip(ip: str) -> bool:
    """Return ``True`` when *ip* belongs to a range that must not be reached."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return is_blocked_ip(str(address.ipv4_mapped))
        if address.sixtofour is not None:
            return is_blocked_ip(str(address.sixtofour))
        if address.teredo is not None:
            return is_blocked_ip(str(address.teredo[1]))
        if address.is_loopback:
            return True
        if address.is_link_local:
            return True
        if address.is_private:
            return True
        if address.is_multicast:
            return True
        if address.is_reserved:
            return True
        if address.is_unspecified:
            return True
        if str(address) in METADATA_ADDRESSES:
            return True
        return False

    if address.is_loopback:
        return True
    if address.is_private:
        return True
    if address.is_link_local:
        return True
    if address.is_multicast:
        return True
    if address.is_reserved:
        return True
    if address.is_unspecified:
        return True
    # Carrier grade NAT (100.64.0.0/10) - not covered by ``is_private``.
    if address in ipaddress.ip_network("100.64.0.0/10"):
        return True
    if str(address) in METADATA_ADDRESSES:
        return True
    return False


@dataclass
class ScopeDecision:
    """Outcome of a scope evaluation."""

    allowed: bool
    reason: str = ""
    url: str = ""
    host: str = ""
    resolved_ips: tuple[str, ...] = ()
    port: int | None = None

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed


@dataclass
class ResolvedTarget:
    """A validated destination with pinned IP addresses."""

    host: str
    port: int
    addresses: tuple[str, ...]
    pinned: str | None = None


class TokenBucket:
    """Simple thread-safe token bucket used to bound request rates."""

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(0.01, float(rate))
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, amount: float = 1.0, timeout: float = 30.0) -> bool:
        """Block until *amount* tokens are available.  Returns ``False`` on timeout."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= amount:
                    self._tokens -= amount
                    return True
                deficit = amount - self._tokens
                wait = deficit / self.rate
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.25))

    def penalise(self, amount: float = 1.0) -> None:
        """Drain tokens (used when a host returns 429)."""
        with self._lock:
            self._tokens = max(0.0, self._tokens - amount)


class ScopeEnforcer:
    """Validates every outbound request against a :class:`ScopePolicy`."""

    def __init__(self, policy: ScopePolicy, *, resolver=None) -> None:
        self.policy = policy
        self._resolver = resolver or self._default_resolver
        self._buckets: dict[str, TokenBucket] = {}
        self._buckets_lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(max(1, policy.max_concurrency))
        self._started_at = time.monotonic()
        self.violations: list[dict] = []
        self._violations_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Time / concurrency budget
    # ------------------------------------------------------------------
    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._started_at

    @property
    def budget_exhausted(self) -> bool:
        return self.elapsed_seconds > self.policy.max_duration_seconds

    def acquire_slot(self, timeout: float = 30.0) -> bool:
        """Reserve a concurrency slot; ``False`` when the budget is exhausted."""
        if self.budget_exhausted:
            return False
        return self._semaphore.acquire(timeout=timeout)

    def release_slot(self) -> None:
        try:
            self._semaphore.release()
        except ValueError:  # pragma: no cover - defensive
            pass

    # ------------------------------------------------------------------
    # Host / IP validation
    # ------------------------------------------------------------------
    @staticmethod
    def _default_resolver(host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []
        return sorted({str(info[4][0]) for info in infos})

    def validate_ip(self, ip: str) -> tuple[bool, str]:
        if self.policy.allow_private_network:
            return True, ""
        if is_blocked_ip(ip):
            return False, f"address {ip} is in a blocked range (loopback/private/link-local/metadata)"
        return True, ""

    def check_host_allowed(self, host: str) -> tuple[bool, str]:
        normalized = _normalize_host(host)
        if not normalized:
            return False, "empty host"
        if not self.policy.matches_host(normalized):
            return False, f"host '{normalized}' is not in the authorised scope"
        if normalized in _LOCAL_HOSTNAMES and not self.policy.allow_private_network:
            return False, f"host '{normalized}' resolves to a local address"
        return True, ""

    # ------------------------------------------------------------------
    # URL evaluation
    # ------------------------------------------------------------------
    def evaluate_url(
        self,
        url: str,
        *,
        method: str = "GET",
        resolve: bool = True,
    ) -> ScopeDecision:
        """Evaluate *url* against the policy without performing any request."""
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            return ScopeDecision(False, f"malformed URL: {exc}", url=url)

        scheme = (parts.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return ScopeDecision(False, f"scheme '{scheme}' is not permitted", url=url)
        if scheme == "http" and not self.policy.allow_http:
            return ScopeDecision(False, "plain HTTP is disabled by policy", url=url)

        try:
            host = parts.hostname or ""
        except ValueError:
            return ScopeDecision(False, "malformed host in URL", url=url)
        port = parts.port or (443 if scheme == "https" else 80)

        allowed, reason = self.check_host_allowed(host)
        if not allowed:
            self._record_violation(url, host, reason)
            return ScopeDecision(False, reason, url=url, host=host, port=port)

        if self.policy.authorized_ports and port not in self.policy.authorized_ports:
            reason = f"port {port} is not in the authorised port list"
            self._record_violation(url, host, reason)
            return ScopeDecision(False, reason, url=url, host=host, port=port)

        if self.policy.is_path_excluded(parts.path or "/"):
            reason = f"path '{parts.path}' is excluded by scope"
            self._record_violation(url, host, reason)
            return ScopeDecision(False, reason, url=url, host=host, port=port)

        method = (method or "GET").upper()
        if method not in self.policy.safe_methods and not self.policy.allow_state_changing:
            reason = f"method {method} changes server state and is not permitted"
            self._record_violation(url, host, reason)
            return ScopeDecision(False, reason, url=url, host=host, port=port)

        if self.budget_exhausted:
            reason = "scan duration budget exhausted"
            return ScopeDecision(False, reason, url=url, host=host, port=port)

        resolved: tuple[str, ...] = ()
        if resolve:
            resolved, reason = self.resolve_and_validate(host)
            if not resolved:
                self._record_violation(url, host, reason)
                return ScopeDecision(False, reason, url=url, host=host, port=port)

        return ScopeDecision(True, "", url=url, host=host, resolved_ips=resolved, port=port)

    def resolve_and_validate(self, host: str) -> tuple[tuple[str, ...], str]:
        """Resolve *host* and validate every returned address."""
        normalized = _normalize_host(host)
        addresses = tuple(self._resolver(normalized) or ())
        if not addresses:
            return (), f"host '{normalized}' could not be resolved"
        for ip in addresses:
            ok, reason = self.validate_ip(ip)
            if not ok:
                return (), reason
        return addresses, ""

    def resolve_target(self, url: str) -> ResolvedTarget:
        """Resolve a URL to a pinned, validated destination."""
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addresses, reason = self.resolve_and_validate(host)
        if not addresses:
            raise ScopeViolation(reason, url=url, host=host)
        return ResolvedTarget(host=host, port=port, addresses=addresses, pinned=addresses[0])

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------
    def bucket_for(self, host: str) -> TokenBucket:
        key = _normalize_host(host)
        with self._buckets_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self.policy.max_requests_per_second)
                self._buckets[key] = bucket
            return bucket

    def throttle(self, host: str, timeout: float = 30.0) -> bool:
        return self.bucket_for(host).acquire(timeout=timeout)

    # ------------------------------------------------------------------
    # Redirect handling
    # ------------------------------------------------------------------
    def validate_redirect_chain(self, urls: Sequence[str], method: str = "GET") -> ScopeDecision:
        """Validate every hop of a redirect chain; scope may not widen."""
        for index, hop in enumerate(urls):
            decision = self.evaluate_url(hop, method=method)
            if not decision.allowed:
                return decision
            if index > self.policy.max_redirects:
                return ScopeDecision(
                    False,
                    f"redirect chain longer than {self.policy.max_redirects}",
                    url=hop,
                    host=decision.host,
                )
        return ScopeDecision(True, "", url=urls[-1] if urls else "")

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def _record_violation(self, url: str, host: str, reason: str) -> None:
        with self._violations_lock:
            self.violations.append({"url": url, "host": host, "reason": reason, "at": time.time()})

    def violation_count(self) -> int:
        with self._violations_lock:
            return len(self.violations)

    def recent_violations(self, limit: int = 50) -> list[dict]:
        with self._violations_lock:
            return list(self.violations[-limit:])


def build_policy_from_scan(
    *,
    authorized_hosts: Iterable[str],
    excluded_paths: Iterable[str] = (),
    authorized_ports: Iterable[int] = (),
    denied_hosts: Iterable[str] = (),
    allow_private_network: bool = False,
    allow_http: bool = True,
    allow_state_changing: bool = False,
    max_requests_per_second: float = 10.0,
    max_concurrency: int = 16,
    max_response_bytes: int = 8 * 1024 * 1024,
    max_duration_seconds: int = 3600,
    timeout: float = 20.0,
) -> ScopePolicy:
    """Build a :class:`ScopePolicy` from persisted scan fields."""
    return ScopePolicy(
        authorized_hosts=tuple(
            dict.fromkeys(str(h).strip().lower() for h in authorized_hosts if str(h).strip())
        ),
        excluded_paths=tuple(str(p) for p in excluded_paths if str(p)),
        authorized_ports=tuple(sorted({int(p) for p in authorized_ports})),
        denied_hosts=tuple(str(h).strip().lower() for h in denied_hosts if str(h).strip()),
        allow_private_network=allow_private_network,
        allow_http=allow_http,
        allow_state_changing=allow_state_changing,
        max_requests_per_second=max_requests_per_second,
        max_concurrency=max_concurrency,
        max_response_bytes=max_response_bytes,
        max_duration_seconds=max_duration_seconds,
        timeout=timeout,
    )
