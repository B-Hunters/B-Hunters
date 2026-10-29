"""The PDF report.

The report is written as HTML and printed.  Rendering it with the same
browser that renders the console keeps one layout, one stylesheet and
one set of facts in the PDF and on the screen, and it avoids a second
rendering stack that would have to learn the report's rules again.

The transcript makes the report large: a scan with twelve roles and a
few hundred tool calls carries megabytes of text.  Chromium can print
that, but not quickly, and a report endpoint that hangs is worse than a
report without a transcript.  The renderer therefore has a budget: when
the print takes longer than it may, the report is printed a second time
from the fallback HTML — the summary with the transcript as plain text
— and the caller is told which of the two it received.

The budget is enforced around the print, because the browser's own PDF
call takes no timeout: the print is a coroutine and the caller waits
for it with a deadline.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

log = logging.getLogger(__name__)

#: How long the print may take before the fallback is used.
DEFAULT_TIMEOUT_SECONDS = 120


class PdfRenderError(RuntimeError):
    """The report could not be printed."""


async def render_pdf_async(
    html: str,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    fallback_html: Optional[str] = None,
    fallback_timeout_seconds: int = 60,
) -> tuple[bytes, str]:
    """Print an HTML report.

    Returns the PDF bytes and which variant was printed: ``"full"`` or
    ``"fallback"``.  When there is no fallback and the print times out,
    the error is raised rather than returning a partial document.

    The fallback has a budget of its own: it is a much smaller
    document, and it has to print even when the full report did not.
    """
    try:
        return await _print(html, timeout_seconds), "full"
    except PdfRenderError as exc:
        if fallback_html is None:
            raise
        log.warning("the report took too long to print (%s); printing the fallback", exc)
        return await _print(fallback_html, fallback_timeout_seconds), "fallback"


def render_pdf(
    html: str,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    fallback_html: Optional[str] = None,
    fallback_timeout_seconds: int = 60,
) -> tuple[bytes, str]:
    """Print an HTML report from synchronous code.

    This cannot be called from inside a running event loop; the API
    route uses :func:`render_pdf_async` instead.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            render_pdf_async(
                html,
                timeout_seconds=timeout_seconds,
                fallback_html=fallback_html,
                fallback_timeout_seconds=fallback_timeout_seconds,
            )
        )
    raise PdfRenderError("render_pdf cannot be called from a running event loop")


async def _print(html: str, timeout_seconds: int) -> bytes:
    """Print one HTML document, within the budget."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - the browser is an image dependency
        raise PdfRenderError("Playwright is not installed") from exc

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                page = await browser.new_page()
                await page.set_content(html, wait_until="load", timeout=timeout_seconds * 1000)
                await page.emulate_media(media="print")
                data = await asyncio.wait_for(
                    page.pdf(
                        print_background=True,
                        prefer_css_page_size=True,
                        margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
                    ),
                    timeout=timeout_seconds,
                )
            finally:
                await browser.close()
    except asyncio.TimeoutError as exc:
        raise PdfRenderError(f"the report took longer than {timeout_seconds}s to print") from exc
    except PdfRenderError:
        raise
    except Exception as exc:
        raise PdfRenderError(f"the report could not be printed: {exc}") from exc

    if not data:
        raise PdfRenderError("the browser produced an empty document")
    return data


def report_metadata(document: bytes) -> dict[str, Any]:
    """What the printed document says about itself.

    A PDF starts with ``%PDF-``; a document that does not is not a
    document, and the API must not return it as one.
    """
    return {
        "bytes": len(document),
        "is_pdf": document[:5] == b"%PDF-",
        "pages_estimate": document.count(b"/Type /Page") or None,
    }
