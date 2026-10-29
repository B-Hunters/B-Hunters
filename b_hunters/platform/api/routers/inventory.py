"""The asset inventory of a scan.

The inventory is what the platform knows about the surface of a target:
every URL the crawler found, every URL the workers reported, every URL
that was fingerprinted, and the JavaScript and image files among them.
The endpoint serves the whole inventory; the console filters it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..deps import CurrentUser, Services, current_user, get_services

router = APIRouter(prefix="/scans", tags=["assets"])


@router.get("/{scan_id}/assets")
async def scan_assets(
    scan_id: str,
    kind: str = "",
    scope: str = "",
    limit: int = 2000,
    offset: int = 0,
    user: CurrentUser = Depends(current_user),
    services: Services = Depends(get_services),
) -> dict[str, Any]:
    """The assets of a scan, with the count per kind.

    The ``kind`` filter takes the kinds of the inventory — ``page``,
    ``js``, ``image``, ``css``, ``api`` and ``other``.  The ``scope``
    filter takes ``first_party`` or ``external``.
    """
    from ...db.assets import AssetRepository

    if services.scans.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="the scan does not exist")

    repository = AssetRepository(services.db)
    items = repository.list_for_scan(
        scan_id,
        kind=kind,
        scope=scope,
        limit=max(1, min(limit, 5000)),
        offset=max(0, offset),
    )
    return {
        "scan_id": scan_id,
        "items": [{key: value for key, value in item.items() if key != "_id"} for item in items],
        "count": len(items),
        "counts": repository.counts_for_scan(scan_id),
    }
