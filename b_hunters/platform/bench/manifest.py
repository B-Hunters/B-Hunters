"""Benchmark manifests.

Each manifest describes one deliberately vulnerable application: how to run
it, how to tell that it is healthy, which documented vulnerabilities it
contains, and what a scanner is expected to find.

Two rules shape the manifests:

* A test case must refer to a **documented** vulnerability or a controlled
  fixture.  The expected outcome is derived from the application's own
  documentation, not from an LLM's assertion.
* When an application does not contain a vulnerability class, the test is
  marked ``not_applicable`` rather than being counted as a scanner failure.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

#: The canonical vulnerability taxonomy.
#:
#: Every adapter, every agent and every benchmark test case uses these
#: names, so that a finding can be matched to a test case and aggregated
#: across tools.
VULN_CLASSES = (
    "route_discovery",
    "javascript_analysis",
    "api_discovery",
    "authentication",
    "session_management",
    "access_control",
    "sql_injection",
    "xss",
    "ssti",
    "ssrf",
    "path_traversal",
    "security_misconfiguration",
    "tls_configuration",
    "graphql",
    "dependency_vulnerability",
    "exposed_secret",
    "spa_crawling",
)


@dataclass
class TestCase:
    """A single benchmark test case."""

    test_id: str
    name: str
    vuln_class: str
    #: ``expected`` - the vulnerability is present and must be found;
    #: ``not_applicable`` - the application does not contain this class;
    #: ``hygiene`` - the application is *not* expected to contain it, so a
    #: report is a false positive.
    expectation: str = "expected"
    #: The concrete request or observation that demonstrates the issue.
    probe: dict[str, Any] = field(default_factory=dict)
    #: What a correct detection looks like.
    expected_evidence: list[str] = field(default_factory=list)
    expected_severity: str = "medium"
    expected_cwe: str = ""
    #: URLs that must be reachable for the test to be meaningful.
    preconditions: list[str] = field(default_factory=list)
    #: Scenarios this application cannot support.
    unsupported: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkApplication:
    """One vulnerable application in the laboratory."""

    slug: str
    name: str
    version: str
    image: str
    port: int
    license: str
    upstream: str
    maintenance: str
    #: The digest of the image that was measured, when it is known.  A tag
    #: such as ``latest`` moves; a digest does not.
    digest: str = ""
    #: The port published on the loopback interface for convenience.  The
    #: scan always uses ``port``; this only affects a manual ``curl``.
    publish_port: int = 0
    description: str = ""
    #: Command or environment needed to start it.
    start_command: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    #: Path or command used to check that it is ready.
    healthcheck_path: str = "/"
    healthcheck_command: list[str] = field(default_factory=list)
    #: Base URL used inside the isolated network.
    internal_url: str = ""
    #: The name the application is reachable under from the worker network.
    internal_host: str = ""
    #: How long to wait for the container to become ready.
    startup_seconds: int = 60
    test_cases: list[TestCase] = field(default_factory=list)
    notes: str = ""
    available: bool = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["test_cases"] = [case.to_dict() for case in self.test_cases]
        data["test_count"] = len(self.test_cases)
        data["image_ref"] = self.image_ref
        return data

    @property
    def image_ref(self) -> str:
        """The reference to pull: the digest when known, otherwise the tag."""
        if self.digest:
            return f"{self.image}@{self.digest}"
        return self.image


def _case(
    test_id: str,
    name: str,
    vuln_class: str,
    *,
    expectation: str = "expected",
    probe: dict[str, Any] | None = None,
    evidence: list[str] | None = None,
    severity: str = "medium",
    cwe: str = "",
    preconditions: list[str] | None = None,
    unsupported: str = "",
    notes: str = "",
) -> TestCase:
    return TestCase(
        test_id=test_id,
        name=name,
        vuln_class=vuln_class,
        expectation=expectation,
        probe=probe or {},
        expected_evidence=evidence or [],
        expected_severity=severity,
        expected_cwe=cwe,
        preconditions=preconditions or [],
        unsupported=unsupported,
        notes=notes,
    )


def dvga_manifest() -> BenchmarkApplication:
    """Damn Vulnerable GraphQL Application.

    The expectations were verified against DVGA 2.2.0 running in the
    laboratory:

    * ``/graphql`` answers a full introspection query;
    * the ``users`` and ``audits`` query fields return records without a
      session;
    * the ``pastes(filter: ...)`` argument is concatenated into a SQL
      query, so a malformed value returns the generated SQL in the error;
    * ``/my_pastes`` and ``/audit`` render for an unauthenticated client;
    * no security response headers are sent.
    """
    return BenchmarkApplication(
        slug="dvga",
        name="Damn Vulnerable GraphQL Application",
        version="2.2.0",
        image="dolevf/dvga:2.2.0",
        digest="sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957",
        port=5013,
        license="MIT",
        upstream="https://github.com/dolevf/damn-vulnerable-graphql-application",
        maintenance="maintained",
        description=(
            "A deliberately vulnerable GraphQL application with introspection enabled, "
            "injection flaws and broken access control."
        ),
        # The application binds to WEB_HOST, which defaults to 127.0.0.1.
        # It must bind to every interface for the container port mapping to
        # reach it.
        environment={"WEB_HOST": "0.0.0.0"},
        healthcheck_path="/",
        startup_seconds=40,
        test_cases=[
            _case(
                "dvga-introspection",
                "GraphQL introspection is enabled",
                "graphql",
                probe={
                    "method": "POST",
                    "path": "/graphql",
                    "body": {"query": "{ __schema { types { name } } }"},
                },
                evidence=["__schema", "queryType", "mutationType"],
                severity="low",
                cwe="CWE-200",
            ),
            _case(
                "dvga-graphql-mutations",
                "Destructive GraphQL mutations are exposed",
                "graphql",
                probe={
                    "method": "POST",
                    "path": "/graphql",
                    "body": {"query": "{ __schema { mutationType { fields { name } } } }"},
                },
                evidence=["deleteAllPastes", "deletePaste", "mutation fields"],
                severity="medium",
                cwe="CWE-862",
            ),
            _case(
                "dvga-graphql-sqli",
                "The pastes filter argument leaks SQL",
                "sql_injection",
                probe={
                    "method": "POST",
                    "path": "/graphql",
                    "body": {"query": '{ pastes(limit: 10, filter: "x\' OR 1=1--") { id } }'},
                },
                evidence=["sqlite3", "SQL:", "OperationalError"],
                severity="high",
                cwe="CWE-89",
            ),
            _case(
                "dvga-users-leak",
                "The users query returns records without authentication",
                "access_control",
                probe={
                    "method": "POST",
                    "path": "/graphql",
                    "body": {"query": "{ users { id username } }"},
                },
                evidence=["users", "username"],
                severity="medium",
                cwe="CWE-306",
            ),
            _case(
                "dvga-headers",
                "Security response headers are absent",
                "security_misconfiguration",
                probe={"method": "GET", "path": "/"},
                evidence=["content-security-policy", "x-frame-options"],
                severity="low",
                cwe="CWE-693",
            ),
            _case(
                "dvga-rest-api",
                "The legacy REST API surface is not present",
                "api_discovery",
                expectation="not_applicable",
                probe={"method": "GET", "path": "/v1/notes"},
                evidence=["v1/notes"],
                severity="info",
                unsupported=(
                    "DVGA 2.2.0 exposes only the GraphQL endpoint and the HTML pages; the "
                    "/v1 REST surface of the 1.x releases was removed."
                ),
            ),
            _case(
                "dvga-ssrf",
                "There is no server-side fetch endpoint",
                "ssrf",
                expectation="not_applicable",
                probe={"method": "POST", "path": "/v1/fetch"},
                evidence=["fetch"],
                severity="info",
                unsupported="DVGA 2.2.0 has no server-side fetch endpoint.",
            ),
            _case(
                "dvga-xss",
                "Stored cross-site scripting in the paste content",
                "xss",
                expectation="not_applicable",
                probe={"method": "POST", "path": "/graphql", "body": {"query": "{ pastes { id } }"}},
                evidence=["<script"],
                severity="info",
                unsupported=(
                    "The paste content is stored and rendered as text by the application, so "
                    "the deterministic adapters do not exercise a scripting sink for it."
                ),
            ),
        ],
    )


def juice_shop_manifest() -> BenchmarkApplication:
    """OWASP Juice Shop."""
    return BenchmarkApplication(
        slug="juice-shop",
        name="OWASP Juice Shop",
        version="latest (digest pinned)",
        image="bkimminich/juice-shop:latest",
        digest="sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4",
        port=3000,
        publish_port=3300,
        license="MIT",
        upstream="https://github.com/juice-shop/juice-shop",
        maintenance="maintained",
        description=(
            "The most modern-looking vulnerable web application: a SPA with an API "
            "backend, covered by the OWASP Juice Shop challenge catalogue."
        ),
        healthcheck_path="/rest/products/search?q=ip",
        startup_seconds=90,
        test_cases=[
            _case(
                "js-api-discovery",
                "REST API routes are recoverable from the JavaScript bundle",
                "javascript_analysis",
                probe={"method": "GET", "path": "/js/main.js"},
                evidence=["/rest/", "api"],
                severity="info",
            ),
            _case(
                "juice-xss",
                "Reflected XSS in the search box",
                "xss",
                probe={"method": "GET", "path": "/search?q=%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E"},
                evidence=["<iframe"],
                severity="high",
                cwe="CWE-79",
            ),
            _case(
                "juice-sqli",
                "SQL injection in the product search",
                "sql_injection",
                probe={
                    "method": "GET",
                    "path": "/rest/products/search?q=apple%27%20UNION%20SELECT%20*%20FROM%20sqlite_master--",
                },
                evidence=["sqlite_master", "UNION", "error"],
                severity="high",
                cwe="CWE-89",
            ),
            _case(
                "juice-auth-bypass",
                "Admin area is reachable without authentication",
                "authentication",
                probe={"method": "GET", "path": "/administration"},
                evidence=["administration"],
                severity="high",
                cwe="CWE-306",
            ),
            _case(
                "juice-idor",
                "Basket contents of another user are readable",
                "access_control",
                probe={"method": "GET", "path": "/rest/basket/2"},
                evidence=["basket"],
                severity="high",
                cwe="CWE-639",
            ),
            _case(
                "juice-secret",
                "The application ships a known secret configuration",
                "exposed_secret",
                probe={"method": "GET", "path": "/"},
                evidence=["[security]"],
                severity="low",
            ),
            _case(
                "juice-headers",
                "Security headers are missing",
                "security_misconfiguration",
                probe={"method": "GET", "path": "/"},
                evidence=["content-security-policy"],
                severity="low",
                cwe="CWE-693",
            ),
        ],
    )


def webgoat_manifest() -> BenchmarkApplication:
    """OWASP WebGoat."""
    return BenchmarkApplication(
        slug="webgoat",
        name="OWASP WebGoat",
        version="latest (digest pinned)",
        image="webgoat/webgoat:latest",
        digest="sha256:95c23e70502d0e0e11a826a73889e2ca93f965171202c17c0c59353ba67be86a",
        port=8080,
        license="Apache-2.0",
        upstream="https://github.com/WebGoat/WebGoat",
        maintenance="maintained",
        description=(
            "A deliberately insecure teaching application with lesson-by-lesson "
            "vulnerabilities covering injection, XSS, broken access control and more."
        ),
        # WebGoat serves its lessons under the /WebGoat context path.
        healthcheck_path="/WebGoat",
        startup_seconds=120,
        test_cases=[
            _case(
                "webgoat-xss",
                "Cross-site scripting lesson",
                "xss",
                probe={"method": "GET", "path": "/webgoat/lesson/xss"},
                evidence=["xss"],
                severity="medium",
                cwe="CWE-79",
            ),
            _case(
                "webgoat-sqli",
                "SQL injection lesson",
                "sql_injection",
                probe={"method": "GET", "path": "/webgoat/lesson/sqli"},
                evidence=["sql"],
                severity="high",
                cwe="CWE-89",
            ),
            _case(
                "webgoat-idor",
                "Insecure direct object reference lesson",
                "access_control",
                probe={"method": "GET", "path": "/webgoat/lesson/idor"},
                evidence=["idor"],
                severity="high",
                cwe="CWE-639",
            ),
            _case(
                "webgoat-path-traversal",
                "Path traversal in the file handling lesson",
                "path_traversal",
                probe={"method": "GET", "path": "/webgoat/lesson/path_traversal"},
                evidence=["traversal"],
                severity="high",
                cwe="CWE-22",
            ),
            _case(
                "webgoat-spa-crawl",
                "Lesson routes are discoverable",
                "route_discovery",
                probe={"method": "GET", "path": "/"},
                evidence=["webgoat"],
                severity="info",
            ),
        ],
    )


def crapi_manifest() -> BenchmarkApplication:
    """OWASP crAPI."""
    return BenchmarkApplication(
        slug="crapi",
        name="OWASP crAPI",
        version="1.0.6",
        image="registry.hub.docker.com/defenseunicorns/crapi:1.0.6",
        port=8080,
        license="MIT",
        upstream="https://github.com/OWASP/crAPI",
        maintenance="maintained",
        description=(
            "A deliberately vulnerable API-first application focusing on the OWASP "
            "API Security Top 10: broken object level authorisation, excessive data "
            "exposure, mass assignment and JWT abuse."
        ),
        healthcheck_path="/",
        startup_seconds=120,
        test_cases=[
            _case(
                "crapi-bola",
                "Broken object level authorisation on the product API",
                "access_control",
                probe={"method": "GET", "path": "/api/v2/products"},
                evidence=["products"],
                severity="high",
                cwe="CWE-639",
            ),
            _case(
                "crapi-jwt",
                "JWT claims are not validated server side",
                "authentication",
                probe={"method": "GET", "path": "/api/v2/products"},
                evidence=["jwt", "token"],
                severity="high",
                cwe="CWE-347",
            ),
            _case(
                "crapi-mass-assignment",
                "Mass assignment on the profile endpoint",
                "access_control",
                probe={"method": "GET", "path": "/api/v2/users"},
                evidence=["user"],
                severity="high",
                cwe="CWE-915",
            ),
            _case(
                "crapi-api-discovery",
                "REST API endpoints are discoverable",
                "api_discovery",
                probe={"method": "GET", "path": "/"},
                evidence=["api"],
                severity="info",
            ),
            _case(
                "crapi-headers",
                "Security headers are missing",
                "security_misconfiguration",
                probe={"method": "GET", "path": "/"},
                evidence=["content-security-policy"],
                severity="low",
                cwe="CWE-693",
            ),
        ],
    )


def mutillidae_manifest() -> BenchmarkApplication:
    """OWASP Mutillidae II."""
    return BenchmarkApplication(
        slug="mutillidae",
        name="OWASP Mutillidae II",
        version="2.0",
        image="dawyck/owasp-mutillidae:2.0",
        port=80,
        license="Apache-2.0",
        upstream="https://github.com/OWASP/owasp-mutillidae",
        maintenance="maintained",
        description=(
            "A deliberately vulnerable PHP application with a large catalogue of "
            "classic web vulnerabilities and a useful false-positive surface."
        ),
        healthcheck_path="/",
        startup_seconds=45,
        test_cases=[
            _case(
                "muti-xss",
                "Reflected XSS in the news parameter",
                "xss",
                probe={"method": "GET", "path": "/index.php?page=news&news=<b>bh</b>"},
                evidence=["<b>bh</b>"],
                severity="medium",
                cwe="CWE-79",
            ),
            _case(
                "muti-sqli",
                "SQL injection in the news parameter",
                "sql_injection",
                probe={"method": "GET", "path": "/index.php?page=news&news=%27%20OR%20%271%27%3D%271"},
                evidence=["error", "sql", "select"],
                severity="high",
                cwe="CWE-89",
            ),
            _case(
                "muti-ssti",
                "Server-side template injection",
                "ssti",
                probe={"method": "GET", "path": "/index.php?page=home&news={{7*7}}"},
                evidence=["49"],
                severity="high",
                cwe="CWE-1336",
            ),
            _case(
                "muti-headers",
                "Security headers are missing",
                "security_misconfiguration",
                probe={"method": "GET", "path": "/"},
                evidence=["content-security-policy"],
                severity="low",
                cwe="CWE-693",
            ),
        ],
    )


def default_manifests() -> list[BenchmarkApplication]:
    """Every benchmark manifest the platform ships with."""
    return [
        dvga_manifest(),
        juice_shop_manifest(),
        webgoat_manifest(),
        crapi_manifest(),
        mutillidae_manifest(),
    ]


def manifests_as_dicts() -> list[dict[str, Any]]:
    return [manifest.to_dict() for manifest in default_manifests()]
