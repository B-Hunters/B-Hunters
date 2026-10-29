/* Who took part in the scan, and how each role ended.
 *
 * The participation table answers the question the console could not
 * answer before: did every tool report?  A tool that ran and found
 * nothing is not the same as a tool that never ran, and the table says
 * which is which.
 */

import { api } from '../api.js';
import { el } from '../components.js';
import { escape } from '../format.js';

/** The badge of a participation reason. */
const REASON_BADGES = {
  'not connected': 'bg-secondary',
  'never dispatched': 'bg-secondary',
  'ran, found nothing': 'bg-secondary',
  errored: 'bg-danger',
  ran: 'bg-success',
  succeeded: 'bg-success',
  failed: 'bg-danger',
  'not selected': 'bg-secondary',
};

/** The participation table of the workers and the native adapters. */
export function renderParticipation(data) {
  const workers = data.workers || [];
  const adapters = data.native_adapters || [];
  if (!workers.length && !adapters.length) {
    return '<div class="empty"><div class="big">Nothing has taken part yet</div>'
      + 'The table fills in once the scan has dispatched its work.</div>';
  }

  const workerRows = workers.map((worker) => `<tr>
    <td class="mono small">${escape(worker.worker || '')}</td>
    <td><span class="badge ${REASON_BADGES[worker.reason] || 'bg-secondary'}">${escape(worker.reason || '-')}</span></td>
    <td class="num">${worker.tasks ?? '-'}</td>
    <td class="num">${worker.findings ?? '-'}</td>
    <td class="num">${worker.crashed_tasks ? escape(worker.crashed_tasks) : '-'}</td>
    <td class="small faint">${escape(worker.expected_version || '-')}</td>
  </tr>`).join('');

  const adapterRows = adapters.map((adapter) => `<tr>
    <td class="mono small">${escape(adapter.name || '')}</td>
    <td><span class="badge ${REASON_BADGES[adapter.status] || 'bg-secondary'}">${escape(adapter.status || '-')}</span></td>
    <td class="num">${adapter.items ?? '-'}</td>
    <td class="num">${adapter.findings ?? '-'}</td>
    <td class="num">-</td>
    <td class="small faint">${escape(adapter.version || '-')}</td>
  </tr>`).join('');

  const coverage = data.coverage || {};
  const coverageText = [
    coverage.workers ? `${coverage.workers.participated || 0} of ${coverage.workers.total || 0} workers took part` : '',
    coverage.native_adapters ? `${coverage.native_adapters.participated || 0} of ${coverage.native_adapters.total || 0} native adapters ran` : '',
  ].filter(Boolean).join(' · ');

  return `<div class="card-head"><h2>Tool participation</h2>
      <span class="desc">${escape(coverageText)}</span></div>
    <div class="table-scroll"><table>
      <thead><tr><th>Worker</th><th>Reason</th><th>Tasks</th><th>Findings</th><th>Crashed</th><th>Version</th></tr></thead>
      <tbody>${workerRows}</tbody>
    </table></div>
    ${adapterRows ? `<div class="card-head"><h2>Native adapters</h2></div>
    <div class="table-scroll"><table>
      <thead><tr><th>Adapter</th><th>Status</th><th>Items</th><th>Findings</th><th></th><th>Version</th></tr></thead>
      <tbody>${adapterRows}</tbody>
    </table></div>` : ''}`;
}

/** The outcome of every agent role. */
export function renderRoleTable(roles) {
  if (!roles || !roles.length) {
    return '<div class="empty"><div class="big">No role has run</div>'
      + 'The roles appear here once the agent phase starts.</div>';
  }
  const rows = roles.map((role) => `<tr>
    <td class="mono small">${escape(role.role || '')}</td>
    <td><span class="badge ${REASON_BADGES[role.status] || 'bg-secondary'}">${escape(role.status || '-')}</span></td>
    <td class="small">${escape(role.stop_reason || '-')}</td>
    <td class="num">${role.rounds ?? '-'}</td>
    <td class="num">${role.tool_calls ?? '-'}</td>
    <td class="num">${role.tokens ?? '-'}</td>
    <td class="num">${role.findings_raised ?? '-'}</td>
    <td class="num">${role.findings_confirmed ?? '-'}</td>
    <td class="small">${escape(role.conclusion || '')}</td>
    <td><button class="btn small" data-transcript="${escape(role.role || '')}">Transcript</button></td>
  </tr>`).join('');

  return `<div class="card-head"><h2>Agent roles</h2>
      <span class="desc">${roles.length} role(s)</span></div>
    <div class="table-scroll"><table>
      <thead><tr><th>Role</th><th>Status</th><th>Stop reason</th><th>Rounds</th><th>Tools</th>
        <th>Tokens</th><th>Findings</th><th>Confirmed</th><th>Conclusion</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

/** The transcript of one role: its messages and its tool calls. */
export function renderTranscript(messages, toolCalls) {
  if (!messages.length && !toolCalls.length) {
    return '<div class="empty">This role has said nothing.</div>';
  }
  const messageHtml = messages.map((message) => `<div class="card-body tight">
      <div class="small faint">${escape(message.kind || '')} ${escape(message.target || '')}</div>
      <div class="small">${escape(message.hypothesis || '')}</div>
      ${(message.observations || []).length
        ? `<div class="small faint">${(message.observations || []).map((o) => escape(o)).join('<br>')}</div>`
        : ''}
    </div>`).join('');

  const callHtml = toolCalls.map((call) => `<tr>
      <td class="mono small">${escape(call.tool || '')}</td>
      <td><span class="badge ${call.status === 'ok' ? 'bg-success' : 'bg-danger'}">${escape(call.status || '')}</span></td>
      <td class="num">${call.duration_ms ?? '-'}</td>
      <td class="mono small">${escape(call.output_summary || call.error || '')}</td>
    </tr>`).join('');

  return `${messageHtml ? `<div class="card-head"><h2>Messages</h2></div>${messageHtml}` : ''}
    ${callHtml ? `<div class="card-head"><h2>Tool calls</h2></div>
    <div class="table-scroll"><table>
      <thead><tr><th>Tool</th><th>Status</th><th>ms</th><th>Output</th></tr></thead>
      <tbody>${callHtml}</tbody>
    </table></div>` : ''}`;
}

/**
 * Open the transcript of a role.
 *
 * The transcript is fetched page by page: a role with hundreds of tool
 * calls has megabytes of text, and the console loads what the reader
 * asks for rather than the whole of it.
 */
export async function openTranscript(scanId, role, container) {
  container.innerHTML = '<div class="card-body"><div class="desc">Loading the transcript…</div></div>';
  const messages = [];
  const toolCalls = [];
  let cursor = '';
  for (let page = 0; page < 20; page += 1) {
    const query = new URLSearchParams({ role, limit: '200' });
    if (cursor) query.set('cursor', cursor);
    const data = await api(`/scans/${scanId}/transcript?${query.toString()}`);
    messages.push(...(data.messages || []));
    toolCalls.push(...(data.tool_calls || []));
    cursor = data.next_cursor || '';
    if (!cursor) break;
  }
  container.innerHTML = renderTranscript(messages, toolCalls);
}
