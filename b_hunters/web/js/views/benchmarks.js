/* The benchmark laboratory: the vulnerable applications it knows. */

import { api } from '../api.js';
import { el, setTitle } from '../components.js';
import { badge, escape } from '../format.js';

/** The benchmarks route. */
export async function benchmarksView() {
  setTitle('Benchmarks', 'Vulnerable application laboratory');
  const data = await api('/benchmarks').catch(() => ({ items: [] }));
  el('view').innerHTML = `
    <div class="alert info">The benchmark laboratory runs deliberately vulnerable applications on an isolated Docker network. See <code>docs/benchmark.md</code> for the setup and teardown procedure.</div>
    <div class="card"><div class="card-body tight"><div class="table-scroll">${renderBenchmarks(data.items || [])}</div></div></div>`;
}

/** The table of the benchmark manifests. */
export function renderBenchmarks(items) {
  if (!items.length) return '<div class="empty">No benchmark manifests are loaded. Run <code>b-hunters bench sync</code> to import them.</div>';
  return `<table><thead><tr><th>Application</th><th>Version</th><th>Image</th><th>Port</th><th>Tests</th><th>License</th><th>Status</th></tr></thead><tbody>
    ${items.map((item) => `<tr>
      <td>${escape(item.name)}<div class="small faint">${escape(item.slug)}</div></td>
      <td class="small">${escape(item.version)}</td>
      <td class="mono small">${escape(item.image)}</td>
      <td class="num">${escape(item.port)}</td>
      <td class="num">${(item.test_cases || []).length}</td>
      <td class="small faint">${escape(item.license)}</td>
      <td>${badge(item.available ? 'healthy' : 'draft')}</td>
    </tr>`).join('')}
  </tbody></table>`;
}
