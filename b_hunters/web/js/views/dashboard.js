/* The overview: what the platform is doing right now. */

import { api } from '../api.js';
import { el, renderAgents, renderKeyValues, setTitle } from '../components.js';
import { badge, escape, fmtTime, severityBadge } from '../format.js';

/** The dashboard route. */
export async function dashboardView() {
  setTitle('Overview', 'Live platform metrics');
  const data = await api('/dashboard');
  const scans = data.scans || {};
  const findings = data.findings || {};
  const karton = data.karton || {};
  const tools = data.tools || {};
  const providers = data.providers || [];

  const sev = findings.by_severity || {};
  const byStatus = findings.by_verification || {};

  const html = `
    <div class="grid cols-5">
      <div class="stat accent"><div class="label">Total scans</div><div class="value">${scans.total ?? 0}</div><div class="foot">${scans.running ?? 0} running &middot; ${scans.queued ?? 0} queued</div></div>
      <div class="stat ok"><div class="label">Completed</div><div class="value">${scans.completed ?? 0}</div><div class="foot">${scans.failed ?? 0} failed</div></div>
      <div class="stat"><div class="label">Open findings</div><div class="value">${findings.open ?? 0}</div><div class="foot">${byStatus.unverified ?? 0} unverified &middot; ${byStatus.likely ?? 0} likely</div></div>
      <div class="stat warn"><div class="label">Active agents</div><div class="value">${(data.agents?.active_count ?? 0)}</div><div class="foot">${(data.tool_calls?.total ?? 0)} tool calls</div></div>
      <div class="stat ${karton.available ? 'ok' : 'err'}"><div class="label">Karton queue</div><div class="value">${karton.available ? (karton.pending_tasks ?? 0) : '—'}</div><div class="foot">${karton.available ? `${karton.online_consumers ?? 0} consumers &middot; ${karton.crashed_tasks ?? 0} crashed` : escape(karton.error || 'unavailable')}</div></div>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <div class="card-head"><h2>Findings by severity</h2><span class="desc">${findings.total ?? 0} total</span></div>
        <div class="card-body">
          ${renderSeverityBars(sev, findings.total ?? 0)}
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Verification status</h2><span class="desc">evidence-driven</span></div>
        <div class="card-body">
          ${renderKeyValues(byStatus)}
        </div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <div class="card-head"><h2>Recent scans</h2><span class="desc">latest activity</span></div>
        <div class="card-body tight"><div class="table-scroll">${renderRecentScans(data.recent_scans || [])}</div></div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Active agents</h2><span class="desc">last seen</span></div>
        <div class="card-body tight"><div class="table-scroll">${renderAgents(data.agents?.items || [])}</div></div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <div class="card-head"><h2>Tool health</h2><span class="desc">${tools.total ?? 0} adapters</span></div>
        <div class="card-body tight"><div class="table-scroll">${renderToolHealth(tools.adapters || [])}</div></div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Model providers</h2><span class="desc">connectivity</span></div>
        <div class="card-body tight"><div class="table-scroll">${renderProviders(providers)}</div></div>
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Recent errors</h2><span class="desc">scanner and agent failures</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderErrors(data.recent_errors || [])}</div></div>
    </div>`;
  el('view').innerHTML = html;
}

/** The findings by severity table with a bar per severity. */
export function renderSeverityBars(sev, total) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const rows = order.map((key) => {
    const count = sev[key] ?? 0;
    const pct = total ? Math.round((count / total) * 100) : 0;
    const color = { critical: 'var(--err)', high: 'var(--high)', medium: 'var(--warn)', low: 'var(--low)', info: 'var(--info)' }[key];
    return `<tr>
      <td style="width:110px">${severityBadge(key)}</td>
      <td class="num" style="width:60px">${count}</td>
      <td><div class="bar"><span style="width:${pct}%;background:${color}"></span></div></td>
      <td class="num faint" style="width:52px">${pct}%</td>
    </tr>`;
  }).join('');
  return `<table><tbody>${rows || '<tr><td class="faint">No findings yet</td></tr>'}</tbody></table>`;
}

/** The last scans of the platform. */
export function renderRecentScans(scans) {
  if (!scans.length) return '<div class="empty">No scans have been created yet.</div>';
  return `<table><thead><tr><th>Name</th><th>Status</th><th>Targets</th><th>Created</th></tr></thead><tbody>
    ${scans.map((scan) => `<tr>
      <td><a href="#/scans/${escape(scan.scan_id)}">${escape(scan.name)}</a></td>
      <td>${badge(scan.status)}</td>
      <td class="mono small">${escape((scan.definition?.targets || []).join(', ') || '-')}</td>
      <td class="small faint">${fmtTime(scan.created_at)}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/** The scanner adapters and what the platform knows about them. */
export function renderToolHealth(adapters) {
  if (!adapters.length) return '<div class="empty">No adapters registered.</div>';
  return `<table><thead><tr><th>Adapter</th><th>Version</th><th>Status</th><th>Capabilities</th></tr></thead><tbody>
    ${adapters.map((adapter) => `<tr>
      <td class="mono">${escape(adapter.name)}</td>
      <td class="small faint">${escape(adapter.version)}</td>
      <td>${badge(adapter.status)}</td>
      <td class="small faint">${escape((adapter.capabilities || []).join(', '))}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/** The model providers and whether they answer. */
export function renderProviders(providers) {
  if (!providers.length) return '<div class="empty">No model providers are configured. Agents cannot run until one is added under Administration.</div>';
  return `<table><thead><tr><th>Provider</th><th>Model</th><th>Reachable</th><th>Latency</th></tr></thead><tbody>
    ${providers.map((provider) => `<tr>
      <td class="mono">${escape(provider.name)}</td>
      <td class="small">${escape(provider.model || '-')}</td>
      <td>${provider.reachable ? badge('healthy') : badge('unavailable')}</td>
      <td class="small faint">${provider.latency_ms ?? 0} ms</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/** The scanner and agent failures of the last hours. */
export function renderErrors(errors) {
  if (!errors.length) return '<div class="empty">No recent errors.</div>';
  return `<table><thead><tr><th>When</th><th>Kind</th><th>Scan</th><th>Detail</th></tr></thead><tbody>
    ${errors.map((error) => `<tr>
      <td class="small faint nowrap">${fmtTime(error.at)}</td>
      <td>${badge(error.kind)}</td>
      <td class="mono small">${escape(error.scan_id || '-')}</td>
      <td class="small">${escape(JSON.stringify(error.payload || {}).slice(0, 220))}</td>
    </tr>`).join('')}
  </tbody></table>`;
}
