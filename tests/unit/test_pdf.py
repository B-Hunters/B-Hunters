"""The PDF report."""

from __future__ import annotations

import pytest

from b_hunters.platform.pdf import PdfRenderError, render_pdf, report_metadata

pytest.importorskip("playwright", reason="the browser is an image dependency")

HTML = """<!doctype html><html><head><style>
@page { size: A4; margin: 12mm; }
body { font-family: sans-serif; }
</style></head><body><h1>Findings</h1><p>Three findings.</p></body></html>"""

FALLBACK = """<!doctype html><html><body><h1>Findings</h1>
<pre>the transcript as plain text</pre></body></html>"""


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            browser.close()
    except Exception:
        return False
    return True


@pytest.mark.skipif(not _chromium_available(), reason="no Chromium on this machine")
def test_a_report_is_printed_as_a_pdf():
    document, variant = render_pdf(HTML)
    assert variant == "full"
    assert document[:5] == b"%PDF-"
    assert len(document) > 500


@pytest.mark.skipif(not _chromium_available(), reason="no Chromium on this machine")
def test_the_printed_document_says_what_it_is():
    document, _ = render_pdf(HTML)
    meta = report_metadata(document)
    assert meta["is_pdf"] is True
    assert meta["bytes"] == len(document)


@pytest.mark.skipif(not _chromium_available(), reason="no Chromium on this machine")
def test_the_fallback_is_used_when_the_print_takes_too_long():
    # A timeout of zero cannot print anything, so the fallback is used.
    document, variant = render_pdf(HTML, timeout_seconds=0, fallback_html=FALLBACK)
    assert variant == "fallback"
    assert document[:5] == b"%PDF-"


def test_a_print_that_fails_without_a_fallback_is_an_error():
    with pytest.raises(PdfRenderError):
        render_pdf(HTML, timeout_seconds=0, fallback_html=None)
