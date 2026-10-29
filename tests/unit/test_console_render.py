"""The console's pages must not print "undefined".

A renderer that reads a variable it does not have prints ``undefined``
where a number belongs, and the page still looks like it works.  The
check runs the real renderers against real data and looks for the word.

The console is a set of ES modules now; the renderers are imported from
the modules that own them.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

WEB_JS = Path(__file__).resolve().parents[2] / "b_hunters" / "web" / "js"


def _module(path: Path) -> str:
    """The url node imports the module by."""
    return path.resolve().as_uri()


def _script() -> str:
    dashboard = _module(WEB_JS / "views" / "dashboard.js")
    scans = _module(WEB_JS / "views" / "scans.js")
    scan_detail = _module(WEB_JS / "views" / "scan-detail.js")
    components = _module(WEB_JS / "components.js")
    return f"""
import {{ renderRecentScans, renderToolHealth, renderProviders }} from '{dashboard}';
import {{ renderScanTable }} from '{scans}';
import {{ renderScanners }} from '{scan_detail}';
import {{ renderAgents }} from '{components}';

const scans = [{{scan_id: 's1', name: 'webgoat', status: 'completed',
  definition: {{targets: ['http://172.25.0.14:8080/WebGoat/']}}, created_at: 1}}];
const workers = [{{worker: 'B-Hunters-Nuclei', status: 'found', tasks: 3, items: 3,
  candidates: 0, output: [{{field: 'Vulns.Nuclei', count: 3, preview: 'x', truncated: false}}]}}];
const output = {{items: [{{worker: 'B-Hunters-Katana', kind: 'url', value: 'http://a/x'}}]}};
const pages = {{
  'recent scans': renderRecentScans(scans),
  'scan table': renderScanTable(scans),
  'scanners': renderScanners({{workers, summary: {{crawled_urls: 1, urls_with_parameters: 0}}}}, output),
  'tools': renderToolHealth([{{name: 'dalfox', version: '1.1.16', status: 'healthy', capabilities: ['xss']}}]),
  'providers': renderProviders([{{name: 'minimax', model: 'm', reachable: true, latency_ms: 12}}]),
  'agents': renderAgents([{{role: 'recon', status: 'idle', last_seen_at: 1, conclusion: 'x'}}], []),
}};
let bad = 0;
for (const [name, html] of Object.entries(pages)) {{
  if (String(html).includes('undefined')) {{
    console.error('the ' + name + ' page prints undefined');
    bad += 1;
  }}
}}
if (!pages.scanners.includes('What the scanners found')) {{
  console.error('the scanners page lost the saved output');
  bad += 1;
}}
if (!pages.scanners.includes('1 item(s) saved')) {{
  console.error('the scanners page does not count the saved items');
  bad += 1;
}}
process.exit(bad ? 1 : 0);
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_no_page_prints_undefined(tmp_path: Path) -> None:
    script = tmp_path / "check.mjs"
    script.write_text(_script())

    result = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr or result.stdout
