/* The difference between this scan and the last one of the same target.
 *
 * The diff is only meaningful between two scans that asked the same
 * question.  When they did not, the view says so rather than showing a
 * difference that is not there.
 */

import { api } from '../api.js';
import { el } from '../components.js';
import { escape } from '../format.js';

/** One group of the diff. */
export function renderDiffGroup(title, items, describe) {
  if (!items || !items.length) {
    return `<div class="card-head"><h2>${escape(title)}</h2><span class="desc">none</span></div>`;
  }
  const rows = items
    .map(
      (item) => `<tr>
        <td>${escape(item.severity || '-')}</td>
        <td class="small">${escape(item.vuln_class || '-')}</td>
        <td class="small">${escape(item.title || '-')}</td>
        <td class="small faint">${escape(describe(item))}</td>
      </tr>`,
    )
    .join('');
  return `<div class="card-head"><h2>${escape(title)}</h2><span class="desc">${items.length}</span></div>
    <div class="table-scroll"><table>
      <thead><tr><th>Severity</th><th>Class</th><th>Finding</th><th>State</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

/** The whole diff. */
export function renderDiff(diff) {
  if (!diff || diff.comparable === false) {
    return `<div class="empty"><div class="big">The two scans are not comparable</div>
      <div class="desc">${escape((diff && diff.reason) || 'there is no earlier scan of this target')}</div></div>`;
  }
  const counts = diff.counts || {};
  return `<div class="card-head"><h2>What changed</h2>
      <span class="desc">${counts.new || 0} new · ${counts.not_observed || 0} not seen · ${counts.reopened || 0} reopened · ${counts.persistent || 0} still there</span></div>
    ${renderDiffGroup('New', diff.new, (item) => `first seen ${item.first_seen_at || ''}`)}
    ${renderDiffGroup('Reopened', diff.reopened, (item) => `last seen ${item.last_seen_at || ''}`)}
    ${renderDiffGroup('Not observed', diff.not_observed, (item) => item.observation_status || '')}
    ${renderDiffGroup('Still there', diff.persistent, (item) => item.triage_status || '')}`;
}

/** The changes tab of a scan. */
export async function renderDiffTab(scanId) {
  const body = el('scan-tab-body');
  body.innerHTML = '<div class="card"><div class="card-body"><div class="desc">Loading the difference…</div></div></div>';
  let diff = null;
  try {
    diff = await api(`/scans/${scanId}/diff`);
  } catch (error) {
    body.innerHTML = `<div class="empty"><div class="big">The difference is not available</div>${escape(error.message)}</div>`;
    return;
  }
  body.innerHTML = `<div class="card"><div class="card-body tight">${renderDiff(diff)}</div></div>`;
}
