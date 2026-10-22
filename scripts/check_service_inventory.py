"""Run a scan through the platform and check the service inventory."""

import asyncio
import json
import sys

sys.path.insert(0, "/home/sniper/pentest/repos/B-Hunters")

from b_hunters.platform.agents.orchestrator import ScanContext, ScanProfile  # noqa: E402
from b_hunters.platform.api.routers.scans import _build_orchestrator  # noqa: E402
from b_hunters.platform.db.client import Database  # noqa: E402
from b_hunters.platform.db.repositories import ScanRepository, ServiceRepository  # noqa: E402
from b_hunters.platform.security.scope import ScopePolicy, ScopeEnforcer  # noqa: E402
from b_hunters.platform.settings import load_settings  # noqa: E402

TARGETS = [
    "http://bench-dvga:5013/",
    "http://bench-juice-shop:3000/",
    "http://bench-webgoat:8080/WebGoat/",
]
HOSTS = ["bench-dvga", "bench-juice-shop", "bench-webgoat"]


async def main() -> None:
    settings = load_settings()
    database = Database(settings)
    services = database

    from b_hunters.platform.api.deps import Services as ServiceContainer

    container = ServiceContainer(database, settings)
    orchestrator = _build_orchestrator(container)

    scan = container.scans.create(
        {
            "name": "service inventory check",
            "status": "queued",
            "created_by": "cli",
            "definition": {"targets": TARGETS},
            "scope": {"authorized_hosts": HOSTS, "allow_private_network": True},
        }
    )

    context = ScanContext(
        scan_id=scan.scan_id,
        name=scan.name,
        targets=list(TARGETS),
        authorized_hosts=list(HOSTS),
        profile=ScanProfile.default(),
        allow_private_network=True,
        max_duration_seconds=300,
    )
    result = await orchestrator.run(context)
    print("scan:", result)

    repository = ServiceRepository(database)
    print("\n=== THE PERSISTED SERVICE INVENTORY ===")
    for document in repository.list_for_scan(scan.scan_id):
        print(f"\n{document['url']}  status={document['status_code']} title={document['title'][:40]!r}")
        print(f"  server={document['server']!r} favicon_mmh3={document['favicon_hash']}")
        for service in document["services"]:
            print(
                f"  - {service['name']:<26} v{service.get('version') or '-':<10} "
                f"[{service['category']}] conf={service['confidence']} via {service['source']}"
            )
    print("\n=== SUMMARY ===")
    for entry in repository.summary(scan.scan_id)["services"]:
        print(f"  {entry['name']} {entry['version']} [{entry['category']}] x{entry['count']}")


asyncio.run(main())
