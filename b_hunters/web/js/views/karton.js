/* Karton: the queue, the consumers and the crashed tasks. */

import { api } from '../api.js';
import { el, setTitle } from '../components.js';
import { badge, escape, fmtDuration } from '../format.js';

/** The karton route. */
export async function kartonView() {
  setTitle('Karton & workers', 'Live queue and consumer state');
  const data = await api('/karton/state');
  if (!data.available) {
    el('view').innerHTML = `<div class="alert warn">Karton is not reachable: ${escape(data.error || 'unknown error')}</div>`;
    return;
  }
  const totals = data.totals || {};
  el('view').innerHTML = `
    <div class="grid cols-4">
      <div class="stat accent"><div class="label">Queues</div><div class="value">${totals.queues ?? 0}</div></div>
      <div class="stat ok"><div class="label">Online consumers</div><div class="value">${totals.online_workers ?? 0}</div></div>
      <div class="stat warn"><div class="label">Pending tasks</div><div class="value">${totals.pending_tasks ?? 0}</div></div>
      <div class="stat err"><div class="label">Crashed tasks</div><div class="value">${totals.crashed_tasks ?? 0}</div></div>
    </div>
    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Queues</h2><span class="desc">oldest task ${fmtDuration(totals.oldest_task_age_seconds)}</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderQueues(data.queues || [])}</div></div>
    </div>`;
}

/** The table of the queues. */
export function renderQueues(queues) {
  if (!queues.length) return '<div class="empty">No Karton queues are registered.</div>';
  return `<table><thead><tr><th>Queue</th><th>Consumers</th><th>Pending</th><th>Started</th><th>Crashed</th><th>Oldest task</th></tr></thead><tbody>
    ${queues.map((queue) => `<tr>
      <td class="mono">${escape(queue.queue)}</td>
      <td>${queue.online_consumers ? badge('healthy') : badge('failed')}</td>
      <td class="num">${queue.pending_tasks}</td>
      <td class="num">${queue.started_tasks}</td>
      <td class="num">${queue.crashed_tasks}</td>
      <td class="small faint">${fmtDuration(queue.oldest_task_age_seconds)}</td>
    </tr>`).join('')}
  </tbody></table>`;
}
