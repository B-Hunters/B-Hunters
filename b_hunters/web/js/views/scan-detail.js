/* One scan: its header, its tabs and the live activity. */

import { API, api } from '../api.js';
import { el, renderAgents, renderFindings, renderOutput, setTitle, toast } from '../components.js';
import { badge, escape, fmtTime } from '../format.js';
import { navigate } from '../router.js';
import { startStream } from '../stream.js';
import { renderAssetsTab } from './assets.js';
import { openTranscript, renderParticipation, renderRoleTable } from './participation.js';

/** The scan detail route. */
export async function scanDetailView(params) {
  const scanId = params.id;
  setTitle('Scan', scanId);
  const scan = await api(`/scans/${scanId}`);
  el('view').innerHTML = `
    <div class="card">
      <div class="card-head">
        <h2>${escape(scan.name)} ${badge(scan.status)}</h2>
        <div class="row">
          <button class="btn small" data-act="pause">Pause</button>
          <button class="btn small" data-act="resume">Resume</button>
          <button class="btn small danger" data-act="stop">Stop</button>
          <button class="btn small" data-act="export">Export</button>
        </div>
      </div>
      <div class="card-body">
        <div class="grid cols-4" style="margin-bottom:14px">
          <div class="stat"><div class="label">Findings</div><div class="value">${Object.values(scan.finding_counts || {}).reduce((a, b) => a + b, 0)}</div></div>
          <div class="stat"><div class="label">Tasks</div><div class="value">${Object.values(scan.task_counts || {}).reduce((a, b) => a + b, 0)}</div></div>
          <div class="stat"><div class="label">Agents</div><div class="value">${(scan.agents || []).length}</div></div>
          <div class="stat"><div class="label">Created</div><div class="value" style="font-size:15px">${fmtTime(scan.created_at)}</div></div>
        </div>
        <dl class="kv">
          <dt>Authorised hosts</dt><dd class="mono">${escape((scan.scope?.authorized_hosts || []).join(', '))}</dd>
          <dt>Targets</dt><dd class="mono">${escape((scan.definition?.targets || []).join(', '))}</dd>
          <dt>Excluded paths</dt><dd class="mono">${escape((scan.scope?.excluded_paths || []).join(', ') || 'none')}</dd>
          <dt>Created by</dt><dd>${escape(scan.created_by)}</dd>
        </dl>
      </div>
    </div>

    <div class="tabs" id="scan-tabs">
      <div class="tab active" data-tab="live">Live activity</div>
      <div class="tab" data-tab="tasks">Task graph</div>
      <div class="tab" data-tab="agents">Agents</div>
      <div class="tab" data-tab="messages">Collaboration</div>
      <div class="tab" data-tab="tools">Tool calls</div>
      <div class="tab" data-tab="scanners">Scanners</div>
      <div class="tab" data-tab="services">Services</div>
      <div class="tab" data-tab="urls">URLs</div>
      <div class="tab" data-tab="js">JS</div>
      <div class="tab" data-tab="images">Images</div>
      <div class="tab" data-tab="findings">Findings</div>
    </div>
    <div id="scan-tab-body"></div>`;

  el('scan-tabs').addEventListener('click', (event) => {
    const tab = event.target.closest('.tab');
    if (!tab) return;
    document.querySelectorAll('#scan-tabs .tab').forEach((node) => node.classList.remove('active'));
    tab.classList.add('active');
    renderScanTab(tab.dataset.tab, scanId);
  });

  document.querySelectorAll('[data-act]').forEach((button) => {
    button.addEventListener('click', async () => {
      const action = button.dataset.act;
      if (action === 'export') {
        window.open(`${API}/scans/${scanId}/report?format=html`, '_blank');
        return;
      }
      try {
        await api(`/scans/${scanId}/${action}`, { method: 'POST' });
        toast(`Scan ${action} requested.`, 'ok');
        setTimeout(() => navigate('scans/:id', { id: scanId }), 700);
      } catch (error) {
        toast(error.message, 'error');
      }
    });
  });

  renderScanTab('live', scanId);
  startStream(scanId);
}

/** Fill the body of the scan page with the tab that was picked. */
export async function renderScanTab(tab, scanId) {
  const body = el('scan-tab-body');
  if (tab === 'live') {
    body.innerHTML = `<div class="card"><div class="card-head"><h2>Event stream</h2><span class="desc" id="stream-state">connecting…</span></div><div class="card-body"><div class="log" id="event-log"></div></div></div>`;
    return;
  }
  if (tab === 'tasks') {
    const data = await api(`/scans/${scanId}/tasks`);
    body.innerHTML = `<div class="card"><div class="card-body tight"><div class="table-scroll">${renderTasks(data.tasks || [])}</div></div></div>`;
    return;
  }
  if (tab === 'agents') {
    const data = await api(`/scans/${scanId}/agents`);
    const calls = await api(`/scans/${scanId}/tool-calls?limit=2000`);
    let roles = [];
    try {
      const report = await api(`/scans/${scanId}/agents/report`);
      roles = report.roles || [];
    } catch {
      // The per-role report is not available on every deployment; the
      // live agent state below is still worth showing.
    }
    body.innerHTML = `<div class="card"><div class="card-body tight"><div class="table-scroll">${renderAgents(data.agents || [], calls.tool_calls || [])}</div></div></div>
      <div class="card"><div class="card-body tight">${renderRoleTable(roles)}</div></div>
      <div class="card" id="transcript-card"><div class="card-body"><div class="desc">Pick a role to read its transcript.</div></div></div>`;
    body.querySelectorAll('[data-transcript]').forEach((button) => {
      button.addEventListener('click', () => {
        openTranscript(scanId, button.dataset.transcript, el('transcript-card'));
      });
    });
    return;
  }
  if (tab === 'messages') {
    const data = await api(`/scans/${scanId}/messages?limit=300`);
    body.innerHTML = `<div class="card"><div class="card-head"><h2>Collaboration messages</h2><span class="desc">${data.count} messages</span></div><div class="card-body tight"><div class="table-scroll">${renderMessages(data.messages || [])}</div></div></div>`;
    return;
  }
  if (tab === 'tools') {
    const data = await api(`/scans/${scanId}/tool-calls?limit=300`);
    body.innerHTML = `<div class="card"><div class="card-head"><h2>Tool invocations</h2><span class="desc">${data.total} calls, ${data.failed} failed</span></div><div class="card-body tight"><div class="table-scroll">${renderToolCalls(data.tool_calls || [])}</div></div></div>`;
    return;
  }
  if (tab === 'scanners') {
    const data = await api(`/scans/${scanId}/scanners`);
    const output = await api(`/scans/${scanId}/worker-output?limit=300`);
    let participation = null;
    try {
      participation = await api(`/scans/${scanId}/participation`);
    } catch {
      // The participation table needs the facts of the worker phase; a
      // scan that has not dispatched anything has none yet.
    }
    body.innerHTML = (participation ? `<div class="card"><div class="card-body tight">${renderParticipation(participation)}</div></div>` : '')
      + renderScanners(data, output);
    const action = el('scan-these');
    if (action) action.addEventListener('click', () => scanTheseUrls(output));
    return;
  }
  if (tab === 'urls' || tab === 'js' || tab === 'images') {
    await renderAssetsTab(tab, scanId);
    return;
  }
  if (tab === 'services') {
    const data = await api(`/scans/${scanId}/services`);
    body.innerHTML = renderServices(data);
    return;
  }
  if (tab === 'findings') {
    const data = await api(`/findings?scan_id=${encodeURIComponent(scanId)}&limit=500`);
    body.innerHTML = `<div class="card"><div class="card-body tight"><div class="table-scroll">${renderFindings(data.items || [])}</div></div></div>`;
  }
}

/** The scanner workers and what they found. */
export function renderScanners(data, output) {
  const workers = data.workers || [];
  if (!workers.length) return '<div class="empty">No scanner workers are connected.</div>';
  const summary = data.summary || {};
  const ran = workers.filter((w) => w.tasks || w.output.length).length;
  const found = workers.filter((w) => w.status === 'found').length;
  const crawled = summary.crawled_urls ?? 0;
  const parameterised = summary.urls_with_parameters ?? 0;
  const states = {
    found: 'bg-success',
    'ran, found nothing': 'bg-secondary',
    running: 'bg-info',
    'did not run': 'bg-secondary',
  };
  const items = (output && output.items) || [];
  const urls = items.filter((item) => item.kind === 'url').map((item) => item.value);
  return `<div class="card-head"><h2>Scanner workers</h2><span class="desc">${ran} of ${workers.length} took part &middot; ${found} found something &middot; ${crawled} URL(s) crawled, ${parameterised} of them carry parameters</span></div>
  <table><thead><tr><th>Scanner</th><th>Status</th><th>Tasks</th><th>Items</th><th>What it found</th></tr></thead><tbody>
    ${workers.map((worker) => `<tr>
      <td class="mono small">${escape(worker.worker)}</td>
      <td><span class="badge ${states[worker.status] || 'bg-secondary'}">${escape(worker.status)}</span>${worker.candidates ? `<div class="faint small">${worker.candidates} candidate URL(s) carried parameters</div>` : ''}</td>
      <td class="num">${worker.tasks || 0}${worker.live_tasks && !worker.tasks ? ` <span class="faint small">(${worker.live_tasks} all scans)</span>` : ''}</td>
      <td class="num">${worker.items || '-'}</td>
      <td class="small">${(worker.output || []).length
        ? worker.output.map((item) => `<div><span class="mono faint">${escape(item.field)}</span> &middot; ${item.count} item(s)${item.truncated ? ' <span class="faint">(output cut at 20000 characters)</span>' : ''}</div>${renderOutput(item.preview)}</div>`).join('')
        : '<span class="faint">-</span>'}</td>
    </tr>`).join('')}
  </tbody></table>
  <div class="card-head"><h2>What the scanners found</h2><span class="desc">${items.length} item(s) saved</span></div>
  <div class="card-body">
    ${urls.length
      ? `<button class="btn" id="scan-these">Scan these ${urls.length} URL(s)</button>
         <div class="hint">A follow-up scan with these URLs as its targets: the native adapters and the agents work on the surface the crawler found, not only on the entry point.</div>`
      : '<div class="hint">The crawlers found no URL to scan again.</div>'}
    <div class="table-scroll"><table><thead><tr><th>Scanner</th><th>Kind</th><th>Value</th></tr></thead><tbody>
      ${items.slice(0, 300).map((item) => `<tr>
        <td class="mono small">${escape(item.worker)}</td>
        <td class="small">${escape(item.kind)}</td>
        <td class="mono small">${escape(item.value)}</td></tr>`).join('')}
    </tbody></table></div>
  </div>`;
}

/** The task graph of a scan. */
export function renderTasks(tasks) {
  if (!tasks.length) return '<div class="empty">No tasks have been created yet.</div>';
  return `<table><thead><tr><th>Task</th><th>Role</th><th>Status</th><th>Depends on</th><th>Attempts</th><th>Error</th></tr></thead><tbody>
    ${tasks.map((task) => `<tr>
      <td>${escape(task.title)}<div class="mono faint small">${escape(task.task_id)}</div></td>
      <td class="mono small">${escape(task.agent_role || task.kind)}</td>
      <td>${badge(task.status)}</td>
      <td class="small faint">${escape((task.depends_on || []).map((d) => d.split(':').pop()).join(', ') || '-')}</td>
      <td class="num">${task.attempts ?? 0}</td>
      <td class="small" style="color:var(--err)">${escape((task.error || '').slice(0, 120))}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/** The messages the agents exchanged. */
export function renderMessages(messages) {
  if (!messages.length) return '<div class="empty">No agent messages yet.</div>';
  return `<table><thead><tr><th>Seq</th><th>Kind</th><th>From</th><th>Target</th><th>Hypothesis</th><th>Confidence</th><th>Disposition</th></tr></thead><tbody>
    ${messages.map((message) => `<tr>
      <td class="num faint">${message.seq ?? ''}</td>
      <td>${badge(String(message.kind || '').replace(/_/g, ' '))}</td>
      <td class="mono small">${escape(message.sender_role)}</td>
      <td class="mono small truncate">${escape(message.target || '-')}</td>
      <td class="small">${escape((message.hypothesis || '').slice(0, 240))}</td>
      <td>${badge(message.confidence)}</td>
      <td class="small faint">${escape(message.disposition || '')}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/** The tool invocations of a scan. */
export function renderToolCalls(calls) {
  if (!calls.length) return '<div class="empty">No tool calls have been recorded yet.</div>';
  return `<table><thead><tr><th>When</th><th>Agent</th><th>Tool</th><th>Status</th><th>Duration</th><th>Detail</th></tr></thead><tbody>
    ${calls.map((call) => `<tr>
      <td class="small faint nowrap">${fmtTime(call.at)}</td>
      <td class="mono small">${escape(call.agent_role)}</td>
      <td class="mono small">${escape(call.tool)}</td>
      <td>${badge(call.status === 'ok' ? 'healthy' : 'failed')}</td>
      <td class="num small">${call.duration_ms ?? 0} ms</td>
      <td class="small">${escape((call.error || call.output || '').slice(0, 200))}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/** The services the fingerprinting adapter identified. */
export function renderServices(data) {
  const urls = data.urls || [];
  const summary = (data.summary && data.summary.services) || [];
  if (!urls.length) {
    return '<div class="empty"><div class="big">No services recorded</div>'
      + 'The fingerprinting adapter identifies what runs on each URL and stores it here.</div>';
  }
  const inventory = summary.length ? `
    <div class="card">
      <div class="card-head"><h2>Inventory</h2><span class="desc">${summary.length} distinct service(s)</span></div>
      <div class="card-body tight"><div class="table-scroll">
        <table><thead><tr><th>Service</th><th>Version</th><th>Category</th><th>Seen on</th></tr></thead>
        <tbody>${summary.map((item) => `<tr>
          <td>${escape(item.name)}</td>
          <td class="mono">${escape(item.version || '-')}</td>
          <td class="small faint">${escape(item.category || '-')}</td>
          <td class="small faint">${item.count} url(s)</td>
        </tr>`).join('')}</tbody></table>
      </div></div>
    </div>` : '';

  const perUrl = urls.map((document) => {
    const services = document.services || [];
    const rows = services.length ? services.map((service) => `<tr>
      <td>${escape(service.name)}</td>
      <td class="mono">${escape(service.version || '-')}</td>
      <td class="small">${escape(service.category || '-')}</td>
      <td class="small faint">${escape(service.source || '-')}</td>
      <td class="num">${Math.round((service.confidence || 0) * 100)}%</td>
    </tr>`).join('') : '<tr><td colspan="5" class="faint">no service identified</td></tr>';
    return `<div class="card">
      <div class="card-head">
        <h2 class="mono" style="font-size:12.5px">${escape(document.url)}</h2>
        <span class="desc">HTTP ${document.status_code || '-'} &middot; ${escape(document.title || 'no title')}</span>
      </div>
      <div class="card-body tight"><div class="table-scroll">
        <table><thead><tr><th>Service</th><th>Version</th><th>Category</th><th>Identified by</th><th>Confidence</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div></div>
    </div>`;
  }).join('');

  return inventory + perUrl;
}

/**
 * Start a follow-up scan on the URLs the crawlers found.
 *
 * The follow-up scan works on the surface the crawler found, not only
 * on the entry point the user typed.
 */
export async function scanTheseUrls(output) {
  const items = (output && output.items) || [];
  const urls = items.filter((item) => item.kind === 'url').map((item) => item.value);
  if (!urls.length) return;
  let host = '';
  try {
    host = new URL(urls[0]).hostname;
  } catch (err) {
    host = '';
  }
  const created = await api('/scans', {
    method: 'POST',
    // The api wrapper serialises the body itself.  Passing a string
    // here would serialise it a second time, and the API would receive
    // a JSON string where it expects the scan itself.
    body: {
      name: `follow-up scan of ${host || 'the crawled URLs'}`,
      targets: { urls, authorized_hosts: host ? [host] : [] },
      test_environment: true,
    },
  });
  location.hash = `#/scans/${created.scan_id}`;
}
