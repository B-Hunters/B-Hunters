/* The scans list: every assessment, with a filter over name and target. */

import { api } from '../api.js';
import { el, setTitle } from '../components.js';
import { badge, escape, fmtTime } from '../format.js';
import { navigate } from '../router.js';

/** The scans route. */
export async function scansView() {
  setTitle('Scans', 'All assessments');
  const data = await api('/scans?limit=200');
  const items = data.items || [];
  el('view').innerHTML = `
    <div class="toolbar">
      <input class="filter-input" id="scan-filter" type="text" placeholder="Filter by name or target…">
      <select id="scan-status" style="max-width:170px">
        <option value="">All statuses</option>
        ${['queued', 'running', 'paused', 'completed', 'failed', 'cancelled'].map((s) => `<option value="${s}">${s}</option>`).join('')}
      </select>
      <div class="spacer"></div>
      <button class="btn primary" id="to-new-scan">New scan</button>
    </div>
    <div class="card"><div class="card-body tight"><div class="table-scroll" id="scan-table">${renderScanTable(items)}</div></div></div>`;

  el('to-new-scan').addEventListener('click', () => navigate('new-scan'));
  const filter = el('scan-filter');
  const statusSelect = el('scan-status');
  const apply = () => {
    const term = filter.value.toLowerCase();
    const wanted = statusSelect.value;
    const filtered = items.filter((scan) => {
      if (wanted && scan.status !== wanted) return false;
      if (!term) return true;
      const haystack = `${scan.name} ${(scan.definition?.targets || []).join(' ')}`.toLowerCase();
      return haystack.includes(term);
    });
    el('scan-table').innerHTML = renderScanTable(filtered);
  };
  filter.addEventListener('input', apply);
  statusSelect.addEventListener('change', apply);
}

/** The table of scans. */
export function renderScanTable(items) {
  if (!items.length) return '<div class="empty"><div class="big">No scans yet</div>Create your first assessment to get started.</div>';
  return `<table><thead><tr>
    <th>Name</th><th>Status</th><th>Targets</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Created by</th><th>Created</th>
  </tr></thead><tbody>
  ${items.map((scan) => {
    const counts = scan.finding_counts || {};
    return `<tr>
      <td><a href="#/scans/${escape(scan.scan_id)}">${escape(scan.name)}</a></td>
      <td>${badge(scan.status)}</td>
      <td class="mono small truncate">${escape((scan.definition?.targets || []).join(', ') || '-')}</td>
      <td class="num">${counts.critical ?? 0}</td>
      <td class="num">${counts.high ?? 0}</td>
      <td class="num">${counts.medium ?? 0}</td>
      <td class="num">${counts.low ?? 0}</td>
      <td class="small faint">${escape(scan.created_by)}</td>
      <td class="small faint nowrap">${fmtTime(scan.created_at)}</td>
    </tr>`;
  }).join('')}
  </tbody></table>`;
}
