"""Service and technology fingerprinting.

The question this module answers is *what is running on this URL, and which
version is it?* — the web server, the application stack, the framework, the
CMS, the CDN, the WAF.

The approach follows the OWASP Web Security Testing Guide (WSTG 4.1,
"Information Gathering" and "Fingerprint Web Server") and combines the
signals that the research identifies as the ones that actually work:

* **banner grabbing** — the ``Server``, ``X-Powered-By`` and vendor
  headers, with the version extracted from the banner;
* **cookie analysis** — a session cookie names the runtime;
* **meta tag analysis** — the ``generator`` meta tag names the CMS;
* **body markers** — ``/wp-content/`` is WordPress, ``X-Content-Type-Options``
  is ASP.NET, and so on;
* **known path probing** — a small, bounded set of GET requests for paths
  that only exist on a particular stack;
* **favicon hashing** — the MurmurHash3 of the base64-encoded favicon,
  the same value Shodan, FOFA and Censys index;
* **TLS certificate analysis** — the issuer names the appliance.

The module has no dependency beyond the standard library: the MurmurHash3
implementation is included so that the platform can fingerprint a target
without pulling in a binary.

The results are *services*, each with a name, a version, a category, the
signal that produced it and a confidence.  A version that was read out of a
banner is reported with a higher confidence than a version inferred from a
body marker.
"""

from __future__ import annotations

import base64
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

#: The confidence bands.  A value read out of a banner is certain; a value
#: inferred from a marker is a guess.
CONFIDENCE_CERTAIN = 0.95
CONFIDENCE_HIGH = 0.8
CONFIDENCE_MEDIUM = 0.6
CONFIDENCE_LOW = 0.4


# ----------------------------------------------------------------------
# MurmurHash3
# ----------------------------------------------------------------------
def mmh3_hash(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32, as used by Shodan, FOFA and Censys."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & 0xFFFFFFFC

    for index in range(0, rounded_end, 4):
        k1 = (
            (data[index] & 0xFF)
            | ((data[index + 1] & 0xFF) << 8)
            | ((data[index + 2] & 0xFF) << 16)
            | (data[index + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xFF) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if tail >= 1:
        k1 |= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return struct.unpack("<i", struct.pack("<I", h1))[0]


def favicon_hash(content: bytes) -> int:
    """The favicon hash the search engines index.

    The favicon is base64 encoded *with line breaks* — that is the
    encoding Shodan hashes, and it differs from the one-line encoding, so
    the difference matters.
    """
    encoded = base64.encodebytes(content)
    return mmh3_hash(encoded)


# ----------------------------------------------------------------------
# The signatures
# ----------------------------------------------------------------------
#: The standard version pattern: a number, optionally with more segments.
#:
#: It is used wherever the signature already knows the product and only
#: needs the version out of the banner.  A pattern that also captured the
#: product name was greedy enough to swallow the version - "nginx/1.25.3"
#: matched ``("nginx/1.25.", "3")``.
VERSION_PATTERN = r"(\d+(?:\.\d+){0,3}(?:[-.][A-Za-z0-9]+)*)"


@dataclass(frozen=True)
class Signature:
    """One fingerprint rule."""

    product: str
    category: str
    #: A regular expression whose first group yields the version.
    version_pattern: Optional[str] = None
    confidence: float = CONFIDENCE_HIGH


#: The headers that name the stack.
#:
#: The version pattern is version-only: the signature already knows the
#: product, so the pattern only has to find the version.  A pattern that
#: captured the product name as well was greedy enough to swallow the
#: version - "nginx/1.25.3" matched ``("nginx/1.25.", "3")``.
HEADER_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    ("server", Signature("Web server", "Web servers", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (
        "x-powered-by",
        Signature("Application stack", "Web frameworks", VERSION_PATTERN, CONFIDENCE_CERTAIN),
    ),
    ("x-aspnet-version", Signature("ASP.NET", "Web frameworks", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (
        "x-aspnetmvc-version",
        Signature("ASP.NET MVC", "Web frameworks", VERSION_PATTERN, CONFIDENCE_CERTAIN),
    ),
    (
        "x-aspnetcore-version",
        Signature("ASP.NET Core", "Web frameworks", VERSION_PATTERN, CONFIDENCE_CERTAIN),
    ),
    (
        "x-runtime-version",
        Signature("Microsoft .NET", "Web frameworks", VERSION_PATTERN, CONFIDENCE_CERTAIN),
    ),
    (
        "x-generator",
        Signature("Application stack", "Web frameworks", VERSION_PATTERN, CONFIDENCE_CERTAIN),
    ),
    ("x-drupal-cache", Signature("Drupal", "CMS", None, CONFIDENCE_CERTAIN)),
    ("x-powered-cms", Signature("CMS", "CMS", VERSION_PATTERN, CONFIDENCE_HIGH)),
    ("x-shopify-stage", Signature("Shopify", "E-commerce", None, CONFIDENCE_CERTAIN)),
    ("x-magento-tags", Signature("Magento", "E-commerce", None, CONFIDENCE_CERTAIN)),
    ("x-akamai-transformed", Signature("Akamai CDN", "CDN", None, CONFIDENCE_HIGH)),
    ("x-cf-ray", Signature("Cloudflare CDN", "CDN", None, CONFIDENCE_CERTAIN)),
    ("x-amz-cf-id", Signature("Amazon CloudFront", "CDN", None, CONFIDENCE_CERTAIN)),
    ("x-served-by", Signature("Fastly CDN", "CDN", None, CONFIDENCE_HIGH)),
    ("x-varnish", Signature("Varnish cache", "CDN", None, CONFIDENCE_HIGH)),
    ("x-iinfo", Signature("Imperva WAF", "WAF", None, CONFIDENCE_HIGH)),
    ("x-pingback", Signature("WordPress", "CMS", None, CONFIDENCE_HIGH)),
    ("x-azure-ref", Signature("Microsoft Azure", "Hosting", None, CONFIDENCE_HIGH)),
    ("x-amz-id", Signature("Amazon Web Services", "Hosting", None, CONFIDENCE_HIGH)),
    ("x-github-request-id", Signature("GitHub", "Hosting", None, CONFIDENCE_HIGH)),
    ("x-backend-server", Signature("Backend server", "Infrastructure", None, CONFIDENCE_MEDIUM)),
    (
        "access-control-allow-origin",
        Signature("Permissive CORS policy", "Configuration", None, CONFIDENCE_HIGH),
    ),
    ("x-graphql-toolkit", Signature("GraphQL", "Other", None, CONFIDENCE_MEDIUM)),
    ("x-powered-by-aspnet", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("via", Signature("Proxy", "Infrastructure", VERSION_PATTERN, CONFIDENCE_HIGH)),
)

#: The session cookies that name the runtime.
COOKIE_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    ("jsessionid", Signature("Java Servlet", "Languages", None, CONFIDENCE_HIGH)),
    ("phpsessid", Signature("PHP", "Languages", None, CONFIDENCE_HIGH)),
    ("asp.net_sessionid", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("asp.net_anon", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("laravel_session", Signature("Laravel", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("_sessionid", Signature("Ruby on Rails", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("_rails_session", Signature("Ruby on Rails", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("django_language", Signature("Django", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("csrftoken", Signature("Django", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("asp.net_cora", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("sess", Signature("Session framework", "Web frameworks", None, CONFIDENCE_LOW)),
)

#: The cookie *values* that name a feature rather than a stack.
COOKIE_VALUE_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    ("graphiql", Signature("GraphQL IDE enabled", "Other", None, CONFIDENCE_HIGH)),
    ("graphql", Signature("GraphQL", "Other", None, CONFIDENCE_MEDIUM)),
)

#: The ``generator`` meta tag.
META_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    (r"wordpress\s*([\d.]+)?", Signature("WordPress", "CMS", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (r"drupal\s*([\d.]+)?", Signature("Drupal", "CMS", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (r"joomla\s*([\d.]+)?", Signature("Joomla", "CMS", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (r"typo3\s*([\d.]+)?", Signature("TYPO3", "CMS", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (r"drupal\s*([\d.]+)?", Signature("Drupal", "CMS", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (r"prestashop\s*([\d.]+)?", Signature("PrestaShop", "E-commerce", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (r"magento\s*([\d.]+)?", Signature("Magento", "E-commerce", VERSION_PATTERN, CONFIDENCE_CERTAIN)),
    (r"concrete\s*cms", Signature("Concrete CMS", "CMS", None, CONFIDENCE_HIGH)),
    (r"grav\b", Signature("Grav", "CMS", None, CONFIDENCE_HIGH)),
)

#: The markers in the body.
BODY_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    ("/wp-content/", Signature("WordPress", "CMS", None, CONFIDENCE_HIGH)),
    ("/wp-includes/", Signature("WordPress", "CMS", None, CONFIDENCE_HIGH)),
    ("wp-json", Signature("WordPress", "CMS", None, CONFIDENCE_MEDIUM)),
    ("drupal.settings", Signature("Drupal", "CMS", None, CONFIDENCE_HIGH)),
    ("/sites/default/files", Signature("Drupal", "CMS", None, CONFIDENCE_HIGH)),
    ("joomla", Signature("Joomla", "CMS", None, CONFIDENCE_LOW)),
    ("typo3conf/", Signature("TYPO3", "CMS", None, CONFIDENCE_HIGH)),
    ("_next/static", Signature("Next.js", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("__next_data__", Signature("Next.js", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("ng-version", Signature("Angular", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("data-reactroot", Signature("React", "JavaScript frameworks", None, CONFIDENCE_HIGH)),
    ("__vue__", Signature("Vue.js", "JavaScript frameworks", None, CONFIDENCE_HIGH)),
    ("svelte-", Signature("Svelte", "JavaScript frameworks", None, CONFIDENCE_MEDIUM)),
    ("rails-", Signature("Ruby on Rails", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("csrfmiddlewaretoken", Signature("Django", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("asp.net", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("__viewstate", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("elmah.axd", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("kontact", Signature("Kontact", "Web frameworks", None, CONFIDENCE_LOW)),
    ("spring-boot", Signature("Spring Boot", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("whitelabel error page", Signature("Spring Boot", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("tomcat", Signature("Apache Tomcat", "Web servers", None, CONFIDENCE_MEDIUM)),
    ("jetty", Signature("Jetty", "Web servers", None, CONFIDENCE_MEDIUM)),
    ("werkzeug", Signature("Werkzeug", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("gin-gonic", Signature("Gin", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("laravel_session", Signature("Laravel", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("thinkphp", Signature("ThinkPHP", "Web frameworks", None, CONFIDENCE_MEDIUM)),
)

#: The paths that only exist on a particular stack.  The requests are
#: bounded: a handful of GET requests per target.
PATH_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    ("/wp-login.php", Signature("WordPress", "CMS", None, CONFIDENCE_CERTAIN)),
    ("/wp-admin/", Signature("WordPress", "CMS", None, CONFIDENCE_HIGH)),
    ("/xmlrpc.php", Signature("WordPress", "CMS", None, CONFIDENCE_HIGH)),
    ("/administrator/", Signature("Joomla", "CMS", None, CONFIDENCE_HIGH)),
    ("/core/", Signature("Drupal", "CMS", None, CONFIDENCE_MEDIUM)),
    ("/typo3/", Signature("TYPO3", "CMS", None, CONFIDENCE_MEDIUM)),
    ("/elmah.axd", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("/trace.axd", Signature("ASP.NET", "Web frameworks", None, CONFIDENCE_HIGH)),
    ("/server-status", Signature("Apache httpd", "Web servers", None, CONFIDENCE_HIGH)),
    ("/server-info", Signature("Apache httpd", "Web servers", None, CONFIDENCE_HIGH)),
    ("/.well-known/security.txt", Signature("security.txt", "Other", None, CONFIDENCE_LOW)),
    ("/actuator", Signature("Spring Boot", "Web frameworks", None, CONFIDENCE_MEDIUM)),
    ("/graphql", Signature("GraphQL", "Other", None, CONFIDENCE_MEDIUM)),
)

#: The certificate issuers that name the appliance.
TLS_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    ("weblogic", Signature("Oracle WebLogic", "Application servers", None, CONFIDENCE_HIGH)),
    ("isag2go", Signature("IBM HTTP Server", "Web servers", None, CONFIDENCE_HIGH)),
    ("bigip", Signature("F5 BIG-IP", "Load balancers", None, CONFIDENCE_HIGH)),
    ("barracuda", Signature("Barracuda", "WAF", None, CONFIDENCE_HIGH)),
    ("fortinet", Signature("Fortinet FortiGate", "Firewalls", None, CONFIDENCE_HIGH)),
    ("cisco", Signature("Cisco", "Network appliances", None, CONFIDENCE_MEDIUM)),
    ("juniper", Signature("Juniper", "Network appliances", None, CONFIDENCE_MEDIUM)),
    ("pf sense", Signature("pfSense", "Firewalls", None, CONFIDENCE_HIGH)),
    ("mcafee", Signature("McAfee", "WAF", None, CONFIDENCE_MEDIUM)),
)

#: The favicon hashes that are worth carrying in the platform.  The full
#: dataset is thousands of entries; these are the ones that identify a
#: stack often enough to be worth the lookup.  A larger dataset can be
#: supplied at run time.
FAVICON_HASHES: dict[int, Signature] = {
    # WordPress
    1945798795: Signature("WordPress", "CMS", None, CONFIDENCE_MEDIUM),
    1126633625: Signature("WordPress", "CMS", None, CONFIDENCE_MEDIUM),
    # Drupal
    2348156596: Signature("Drupal", "CMS", None, CONFIDENCE_MEDIUM),
    # Joomla
    1122976580: Signature("Joomla", "CMS", None, CONFIDENCE_MEDIUM),
    # Tomcat / Java
    741585733: Signature("Apache Tomcat", "Application servers", None, CONFIDENCE_LOW),
    # Nginx
    1862753093: Signature("Nginx", "Web servers", None, CONFIDENCE_LOW),
    # GitLab
    1265477436: Signature("GitLab", "Web applications", None, CONFIDENCE_MEDIUM),
    # Grafana
    1889549615: Signature("Grafana", "Web applications", None, CONFIDENCE_MEDIUM),
    # Portainer
    1462892552: Signature("Portainer", "Management consoles", None, CONFIDENCE_MEDIUM),
}

#: The favicon paths to probe.
FAVICON_PATHS: tuple[str, ...] = ("/favicon.ico", "/static/favicon.ico", "/favicon.png")


# ----------------------------------------------------------------------
# The result
# ----------------------------------------------------------------------
@dataclass
class Service:
    """One identified service."""

    name: str
    category: str = "Unknown"
    version: str = ""
    confidence: float = CONFIDENCE_MEDIUM
    source: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": round(self.confidence, 3),
            "source": self.source,
            "evidence": self.evidence[:500],
        }

    @property
    def key(self) -> tuple[str, str]:
        return (self.name.lower(), self.version)


@dataclass
class Fingerprint:
    """The fingerprint of one URL."""

    url: str
    host: str = ""
    status_code: int = 0
    title: str = ""
    server: str = ""
    services: list[Service] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    favicon_hash: int = 0
    tls: dict[str, str] = field(default_factory=dict)
    probes: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "status_code": self.status_code,
            "title": self.title,
            "server": self.server,
            "services": [service.to_dict() for service in self.services],
            "headers": self.headers,
            "cookies": self.cookies,
            "favicon_hash": self.favicon_hash,
            "tls": self.tls,
            "probes": self.probes,
            "error": self.error,
        }


# ----------------------------------------------------------------------
# The detection
# ----------------------------------------------------------------------
_VERSION_RE_CACHE: dict[str, re.Pattern[str]] = {}


def _version_pattern(pattern: str) -> re.Pattern[str]:
    compiled = _VERSION_RE_CACHE.get(pattern)
    if compiled is None:
        compiled = re.compile(pattern, re.IGNORECASE)
        _VERSION_RE_CACHE[pattern] = compiled
    return compiled


def extract_version(text: str, pattern: Optional[str]) -> str:
    """Pull the version out of a banner."""
    if not pattern or not text:
        return ""
    match = _version_pattern(pattern).search(text)
    if not match:
        return ""
    groups = [group for group in match.groups() if group]
    if not groups:
        return ""
    # A banner like "nginx/1.25.3" yields the name in group one and the
    # version in group two; prefer the group that looks like a version.
    for group in groups:
        candidate = group.strip()
        if re.match(r"^v?\d[\w.\-+]*$", candidate):
            return candidate.lstrip("vV")
    return groups[0].strip()


def _add(services: list[Service], service: Service) -> None:
    """Add a service, keeping the most confident version."""
    for existing in services:
        if existing.key == service.key:
            if service.confidence > existing.confidence:
                existing.confidence = service.confidence
                existing.source = service.source
                existing.evidence = service.evidence
            return
        if existing.name.lower() == service.name.lower() and not existing.version and service.version:
            existing.version = service.version
            existing.confidence = service.confidence
            existing.source = service.source
            existing.evidence = service.evidence
            return
    services.append(service)


def detect_from_headers(headers: dict[str, str], services: list[Service]) -> None:
    """Banner grabbing: the headers that name the stack."""
    lowered = {key.lower(): value for key, value in headers.items()}
    for header, signature in HEADER_SIGNATURES:
        value = lowered.get(header)
        if not value:
            continue
        _add(
            services,
            Service(
                name=signature.product,
                category=signature.category,
                version=extract_version(value, signature.version_pattern),
                confidence=signature.confidence,
                source=f"header:{header}",
                evidence=f"{header}: {value}"[:300],
            ),
        )


def detect_from_cookies(cookies: str, services: list[Service]) -> list[str]:
    """Cookie analysis: the session cookie names the runtime."""
    names: list[str] = []
    for part in (cookies or "").split(";"):
        name, _, value = part.strip().partition("=")
        name = name.strip().lower()
        if not name:
            continue
        names.append(name)
        for cookie, signature in COOKIE_SIGNATURES:
            if name == cookie:
                _add(
                    services,
                    Service(
                        name=signature.product,
                        category=signature.category,
                        confidence=signature.confidence,
                        source=f"cookie:{name}",
                        evidence=f"Set-Cookie: {name}"[:300],
                    ),
                )
        lowered = value.strip().lower()
        for marker, signature in COOKIE_VALUE_SIGNATURES:
            if marker in lowered:
                _add(
                    services,
                    Service(
                        name=signature.product,
                        category=signature.category,
                        confidence=signature.confidence,
                        source=f"cookie-value:{name}",
                        evidence=f"Set-Cookie: {name}={value[:60]}"[:300],
                    ),
                )
    return names


def detect_from_meta(body: str, services: list[Service]) -> None:
    """The ``generator`` meta tag names the CMS."""
    for match in re.finditer(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", body, re.IGNORECASE
    ):
        content = match.group(1)
        for pattern, signature in META_SIGNATURES:
            if re.search(pattern, content, re.IGNORECASE):
                _add(
                    services,
                    Service(
                        name=signature.product,
                        category=signature.category,
                        version=extract_version(content, signature.version_pattern),
                        confidence=signature.confidence,
                        source="meta:generator",
                        evidence=f"generator: {content}"[:300],
                    ),
                )
                break


def detect_from_body(body: str, services: list[Service]) -> None:
    """The markers in the body."""
    lowered = body.lower()
    for marker, signature in BODY_SIGNATURES:
        if marker.lower() in lowered:
            _add(
                services,
                Service(
                    name=signature.product,
                    category=signature.category,
                    confidence=signature.confidence,
                    source=f"body:{marker}",
                    evidence=f"body contains '{marker}'"[:300],
                ),
            )


def detect_from_tls(tls: dict[str, str], services: list[Service]) -> None:
    """The certificate issuer names the appliance."""
    haystack = " ".join(str(value) for value in tls.values()).lower()
    for marker, signature in TLS_SIGNATURES:
        if marker in haystack:
            _add(
                services,
                Service(
                    name=signature.product,
                    category=signature.category,
                    confidence=signature.confidence,
                    source=f"tls:{marker}",
                    evidence=f"certificate mentions '{marker}'"[:300],
                ),
            )


def detect_from_favicon(hash_value: int, services: list[Service]) -> None:
    """The favicon hash identifies the product."""
    signature = FAVICON_HASHES.get(hash_value)
    if signature is None:
        return
    _add(
        services,
        Service(
            name=signature.product,
            category=signature.category,
            confidence=signature.confidence,
            source="favicon:mmh3",
            evidence=f"favicon mmh3 hash {hash_value}"[:300],
        ),
    )


def title_of(body: str) -> str:
    """The page title."""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:300]
