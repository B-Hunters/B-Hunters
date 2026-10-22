/* B-Hunters platform frontend.
 *
 * A dependency-free ES module SPA.  No build step: the platform is a
 * Python service and shipping a node toolchain for a dashboard would add a
 * second build system for no functional gain.
 *
 * Security notes:
 *  - The session cookie is HttpOnly; the CSRF token is read from a
 *    readable cookie and echoed in the X-CSRF-Token header.
 *  - All rendering goes through escape() so that target-derived content
 *    (host names, page titles, tool output) can never inject markup.
 */

const API = '/api/v1';

const state = {
  user: null,
  csrf: null,
  route: 'dashboard',
  params: {},
  stream: null,
  lastSeq: 0,
  pollTimer: null,
  cache: {},
};

/* ------------------------------------------------------------------ api */
function readCookie(name) {
  const match = document.cookie.match(new RegExp('(^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[2]) : null;
}

async function api(path, { method = 'GET', body = null, raw = false } = {}) {
  const headers = { 'Accept': 'application/json' };
  if (body !== null) headers['Content-Type'] = 'application/json';
  const csrf = readCookie('bh_csrf');
  if (csrf) headers['X-CSRF-Token'] = csrf;

  const response = await fetch(API + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === null ? null : JSON.stringify(body),
  });

  if (response.status === 401) {
    state.user = null;
    showLogin();
    throw new Error('Your session has expired. Please sign in again.');
  }
  if (raw) return response;
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = { detail: text }; }
  }
  if (!response.ok) {
    const detail = payload && payload.detail;
    const message = typeof detail === 'string' ? detail
      : (detail && detail.message) ? detail.message
      : `Request failed with HTTP ${response.status}`;
    const error = new Error(message);
    error.payload = payload;
    error.status = response.status;
    throw error;
  }
  return payload;
}

/* ---------------------------------------------------------------- utils */
function escape(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function el(id) { return document.getElementById(id); }

function fmtTime(value) {
  if (!value) return '-';
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return '-';
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) return `${total}s`;
  if (total < 3600) return `${Math.floor(total / 60)}m ${total % 60}s`;
  return `${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}m`;
}

function toast(message, kind = 'info') {
  const host = el('toasts');
  const node = document.createElement('div');
  node.className = `toast ${kind}`;
  node.textContent = message;
  host.appendChild(node);
  setTimeout(() => node.remove(), 5200);
}

function badge(value) {
  const text = escape(value || 'unknown');
  return `<span class="badge ${escape(String(value || 'unknown').toLowerCase())}">${text}</span>`;
}

function severityBadge(value) {
  return badge(value);
}

/* -------------------------------------------------------------- routing */
const routes = {};
function registerRoute(name, handler) { routes[name] = handler; }

/**
 * Resolve a hash fragment to a route.
 *
 * The hash has the form ``#/<name>`` or ``#/<name>/<id>``.  A route that
 * takes an identifier is registered as ``"<name>/:id"``; this function picks
 * the parameterised route when an identifier is present and falls back to
 * the list route otherwise.
 */
function resolveRoute(raw) {
  const parts = String(raw || '').replace(/^#\/?/, '').split('/').filter(Boolean);
  if (!parts.length) return null;
  const name = parts[0];
  const id = parts.length > 1 ? parts[1] : '';
  if (id && routes[`${name}/:id`]) return { name: `${name}/:id`, params: { id } };
  if (routes[name]) return { name, params: id ? { id } : {} };
  return null;
}

async function navigate(route, params = {}, { updateHash = true } = {}) {
  // A route may be registered as "<name>/:id"; the identifier travels in
  // ``params.id`` and is appended to the hash separately.
  const base = String(route).split('/:')[0];
  const id = params.id || '';
  const target = route;

  state.route = target;
  state.params = { ...params, id };
  closeStream();
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.classList.toggle('active', link.dataset.route === base);
  });

  if (updateHash) {
    const wanted = '#/' + base + (id ? '/' + id : '');
    if (location.hash !== wanted) {
      // Update the hash without re-entering the handler.
      history.pushState(null, '', wanted);
    }
  }

  const view = el('view');
  view.innerHTML = '<div class="row" style="padding:40px"><span class="spinner"></span><span class="muted">Loading…</span></div>';
  try {
    await routes[target]({ ...params, id });
  } catch (error) {
    view.innerHTML = `<div class="alert error">${escape(error.message)}</div>`;
  }
}

window.addEventListener('hashchange', () => {
  const resolved = resolveRoute(location.hash);
  if (resolved) navigate(resolved.name, resolved.params, { updateHash: false });
  else navigate('dashboard', {}, { updateHash: false });
});

/* ---------------------------------------------------------------- login */
function showLogin() {
  el('login-shell').classList.remove('hidden');
  el('app-shell').classList.remove('active');
  el('login-shell').style.display = 'grid';
  closeStream();
}

function showApp() {
  el('login-shell').style.display = 'none';
  el('app-shell').classList.add('active');
}

el('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = el('login-submit');
  const errorBox = el('login-error');
  errorBox.classList.add('hidden');
  button.disabled = true;
  button.textContent = 'Signing in…';
  try {
    const result = await api('/auth/login', {
      method: 'POST',
      body: {
        username: el('login-username').value,
        password: el('login-password').value,
      },
    });
    state.user = result;
    state.csrf = result.csrf_token;
    el('login-password').value = '';
    await enterApp();
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove('hidden');
  } finally {
    button.disabled = false;
    button.textContent = 'Sign in';
  }
});

el('logout-btn').addEventListener('click', async () => {
  try { await api('/auth/logout', { method: 'POST' }); } catch { /* already gone */ }
  state.user = null;
  showLogin();
  toast('Signed out.', 'info');
});

el('refresh-btn').addEventListener('click', () => navigate(state.route, state.params));

document.querySelectorAll('.nav-link').forEach((link) => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    navigate(link.dataset.route);
  });
});

async function enterApp() {
  showApp();
  const me = await api('/auth/me');
  state.user = me;
  el('user-name').textContent = me.username;
  el('user-role').textContent = me.role;
  el('user-avatar').textContent = (me.username || '?').slice(0, 2).toUpperCase();
  el('admin-nav').style.display = me.role === 'admin' ? '' : 'none';
  const resolved = resolveRoute(location.hash);
  if (resolved) navigate(resolved.name, resolved.params, { updateHash: false });
  else navigate('dashboard', {}, { updateHash: false });
}

/* ------------------------------------------------------------ dashboard */
registerRoute('dashboard', async () => {
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
});

function renderSeverityBars(sev, total) {
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

function renderKeyValues(obj) {
  const keys = Object.keys(obj || {});
  if (!keys.length) return '<div class="empty">No verification data yet.</div>';
  return `<dl class="kv">${keys.map((k) => `<dt>${escape(k)}</dt><dd>${escape(obj[k])}</dd>`).join('')}</dl>`;
}

function renderRecentScans(scans) {
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

function renderAgents(agents) {
  if (!agents.length) return '<div class="empty">No agents are active.</div>';
  return `<table><thead><tr><th>Role</th><th>Status</th><th>Conclusion</th><th>Last seen</th></tr></thead><tbody>
    ${agents.map((agent) => `<tr>
      <td class="mono">${escape(agent.role)}</td>
      <td>${badge(agent.status)}</td>
      <td class="small">${escape((agent.conclusion || '').slice(0, 120))}</td>
      <td class="small faint">${fmtTime(agent.last_seen_at)}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

function renderToolHealth(adapters) {
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

function renderProviders(providers) {
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

function renderErrors(errors) {
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

function setTitle(title, crumb) {
  el('page-title').textContent = title;
  el('page-crumb').textContent = crumb || '';
}

/* ---------------------------------------------------------------- scans */
registerRoute('scans', async () => {
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
});

function renderScanTable(items) {
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

/* ------------------------------------------------------------ new scan */
registerRoute('new-scan', async () => {
  setTitle('New scan', 'Scope is validated on the server before anything is queued');
  const [roles, adapters] = await Promise.all([
    api('/admin/agent-roles'),
    api('/scans/scanner-specs').catch(() => ({ roles: [], scanners: [] })),
  ]);
  const roleList = roles.roles || [];
  const scannerList = adapters.scanners || [];

  el('view').innerHTML = `
    <div class="split">
      <div>
        <div class="card">
          <div class="card-head"><h2>Scope</h2><span class="desc">only these hosts may be contacted</span></div>
          <div class="card-body">
            <div class="field">
              <label for="scan-name">Scan name</label>
              <input type="text" id="scan-name" placeholder="Acme staging assessment" required>
            </div>
            <div class="field">
              <label for="scan-targets">Target URLs (one per line)</label>
              <textarea id="scan-targets" placeholder="https://staging.acme.test&#10;https://api.acme.test"></textarea>
              <div class="hint">A target must fall inside the authorised host list below. Hosts discovered while crawling are <em>not</em> automatically authorised.</div>
            </div>
            <div class="field">
              <label for="scan-hosts">Explicitly authorised hosts (one per line)</label>
              <textarea id="scan-hosts" placeholder="acme.test&#10;*.acme.test"></textarea>
              <div class="hint">Wildcards such as <code>*.acme.test</code> are supported. This list is the whole scope.</div>
            </div>
            <div class="grid cols-2">
              <div class="field">
                <label for="scan-excluded">Excluded paths (one per line)</label>
                <textarea id="scan-excluded" placeholder="/admin/delete"></textarea>
              </div>
              <div class="field">
                <label for="scan-artifacts">Source or JavaScript artefacts (one per line)</label>
                <textarea id="scan-artifacts" placeholder="/srv/artifacts/app.js"></textarea>
              </div>
            </div>
            <div class="grid cols-2">
              <div class="field">
                <label for="scan-schemas">OpenAPI / GraphQL schemas (one per line)</label>
                <textarea id="scan-schemas" placeholder="/srv/artifacts/openapi.json"></textarea>
              </div>
              <div class="field">
                <label for="scan-accounts">Approved test accounts (one per line, username only)</label>
                <textarea id="scan-accounts" placeholder="tester_a&#10;tester_b"></textarea>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h2>Execution limits</h2><span class="desc">bounded by design</span></div>
          <div class="card-body">
            <div class="grid cols-2">
              <div class="field"><label for="scan-concurrency">Maximum concurrency</label><input type="number" id="scan-concurrency" value="4" min="1" max="32"></div>
              <div class="field"><label for="scan-rps">Requests per second</label><input type="number" id="scan-rps" value="10" min="0.1" step="0.5"></div>
              <div class="field"><label for="scan-timeout">Request timeout (seconds)</label><input type="number" id="scan-timeout" value="20" min="1" max="300"></div>
              <div class="field"><label for="scan-duration">Maximum duration (seconds)</label><input type="number" id="scan-duration" value="3600" min="30" max="86400"></div>
            </div>
            <div class="field">
              <label>Mode</label>
              <div class="row">
                <label style="display:flex;align-items:center;gap:7px;margin:0"><input type="checkbox" id="scan-safe" checked style="width:auto"> Safe testing mode</label>
                <label style="display:flex;align-items:center;gap:7px;margin:0"><input type="checkbox" id="scan-state" style="width:auto"> Allow state-changing requests</label>
                <label style="display:flex;align-items:center;gap:7px;margin:0"><input type="checkbox" id="scan-lab" style="width:auto"> Isolated test environment</label>
              </div>
              <div class="hint">Isolated test environment permits loopback and private destinations. Never enable it against a production system.</div>
            </div>
          </div>
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-head"><h2>Profile</h2></div>
          <div class="card-body">
            <div class="field">
              <label for="scan-profile">Scan profile</label>
              <select id="scan-profile">
                <option value="standard">standard - discovery, analysis, verification, reporting</option>
                <option value="recon">recon - discovery only</option>
              </select>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h2>Agent roles</h2><span class="desc">${roleList.length} available</span></div>
          <div class="card-body">
            <div class="chips" id="role-chips">
              ${roleList.map((role) => `<span class="chip" data-role="${escape(role.role)}" title="${escape(role.objective)}">${escape(role.title)}</span>`).join('')}
            </div>
            <div class="hint" style="margin-top:10px">Click a role to include it. The orchestrator adds verification and reporting automatically.</div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h2>Scanner tools</h2><span class="desc">${scannerList.length} adapters</span></div>
          <div class="card-body">
            <div class="chips" id="scanner-chips">
              ${scannerList.map((scanner) => `<span class="chip" data-scanner="${escape(scanner.name)}" title="${escape(scanner.description || '')}">${escape(scanner.name)}</span>`).join('')}
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h2>Review</h2></div>
          <div class="card-body">
            <div id="preview-out" class="faint small">Fill in the scope and press <strong>Validate scope</strong>.</div>
            <div class="row" style="margin-top:14px">
              <button class="btn" id="validate-btn">Validate scope</button>
              <button class="btn primary" id="create-btn" disabled>Create scan</button>
            </div>
            <div id="create-out" style="margin-top:12px"></div>
          </div>
        </div>
      </div>
    </div>`;

  el('role-chips').addEventListener('click', (event) => {
    const chip = event.target.closest('.chip');
    if (chip) chip.classList.toggle('on');
  });
  el('scanner-chips').addEventListener('click', (event) => {
    const chip = event.target.closest('.chip');
    if (chip) chip.classList.toggle('on');
  });

  const collect = () => ({
    name: el('scan-name').value.trim(),
    description: '',
    targets: {
      urls: splitLines(el('scan-targets').value),
      authorized_hosts: splitLines(el('scan-hosts').value),
      excluded_paths: splitLines(el('scan-excluded').value),
      start_paths: [],
      url_lists: [],
    },
    profile: el('scan-profile').value,
    scanners: selectedChips('scanner-chips', 'scanner'),
    agent_roles: selectedChips('role-chips', 'role'),
    artifacts: splitLines(el('scan-artifacts').value),
    schema_artifacts: splitLines(el('scan-schemas').value),
    test_accounts: splitLines(el('scan-accounts').value).map((username) => ({ username })),
    max_concurrency: Number(el('scan-concurrency').value),
    max_requests_per_second: Number(el('scan-rps').value),
    request_timeout: Number(el('scan-timeout').value),
    max_duration_seconds: Number(el('scan-duration').value),
    safe_mode: el('scan-safe').checked,
    allow_state_changing: el('scan-state').checked,
    test_environment: el('scan-lab').checked,
    provider: '',
  });

  el('validate-btn').addEventListener('click', async () => {
    const payload = collect();
    const out = el('preview-out');
    out.innerHTML = '<span class="spinner"></span> Validating…';
    try {
      const result = await api('/scans/preview', { method: 'POST', body: payload });
      const warnings = (result.warnings || []).map((w) => `<div class="alert warn">${escape(w)}</div>`).join('');
      const rejected = (result.out_of_scope || []).map((item) =>
        `<div class="alert error">${escape(item.url)} — ${escape(item.reason)}</div>`).join('');
      out.innerHTML = `
        ${warnings}${rejected}
        <div class="alert ok">Scope is valid. ${result.accepted_urls.length} target(s) inside ${result.authorized_hosts.length} authorised host(s).</div>
        <dl class="kv" style="margin-top:10px">
          <dt>Profile</dt><dd>${escape(result.profile)}</dd>
          <dt>Agents</dt><dd>${escape((result.agent_roles || []).join(', ') || 'none')}</dd>
          <dt>Scanners</dt><dd>${escape((result.scanners || []).join(', ') || 'none')}</dd>
          <dt>Duration limit</dt><dd>${fmtDuration(result.max_duration_seconds)}</dd>
        </dl>`;
      el('create-btn').disabled = !(result.accepted_urls || []).length;
    } catch (error) {
      out.innerHTML = `<div class="alert error">${escape(error.message)}</div>`;
      el('create-btn').disabled = true;
    }
  });

  el('create-btn').addEventListener('click', async () => {
    const button = el('create-btn');
    button.disabled = true;
    const out = el('create-out');
    out.innerHTML = '<span class="spinner"></span> Creating…';
    try {
      const scan = await api('/scans', { method: 'POST', body: collect() });
      out.innerHTML = `<div class="alert ok">Scan <strong>${escape(scan.name)}</strong> created.</div>`;
      toast('Scan created.', 'ok');
      navigate('scans');
    } catch (error) {
      out.innerHTML = `<div class="alert error">${escape(error.message)}</div>`;
      button.disabled = false;
    }
  });
});

function splitLines(text) {
  return String(text || '').split('\n').map((line) => line.trim()).filter(Boolean);
}

function selectedChips(containerId, attribute) {
  return Array.from(el(containerId).querySelectorAll(`.chip.on[data-${attribute}]`))
    .map((chip) => chip.dataset[attribute]);
}

/* ----------------------------------------------------------- live scan */
registerRoute('scans/:id', async (params) => {
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
      <div class="tab" data-tab="services">Services</div>
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
});

async function renderScanTab(tab, scanId) {
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
    body.innerHTML = `<div class="card"><div class="card-body tight"><div class="table-scroll">${renderAgents(data.agents || [])}</div></div></div>`;
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

function renderTasks(tasks) {
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

function renderMessages(messages) {
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

function renderToolCalls(calls) {
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

/* ----------------------------------------------------------------- SSE */
function closeStream() {
  if (state.stream) {
    state.stream.close();
    state.stream = null;
  }
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  const indicator = el('live-indicator');
  if (indicator) indicator.style.display = 'none';
}

function startStream(scanId) {
  closeStream();
  const indicator = el('live-indicator');
  indicator.style.display = '';
  el('live-dot').className = 'conn-dot';

  const source = new EventSource(`${API}/scans/${scanId}/stream?last_event_id=${state.lastSeq}`);
  state.stream = source;

  const setStreamState = (text, kind) => {
    el('live-dot').className = 'conn-dot' + (kind ? ' ' + kind : '');
    el('live-text').textContent = text;
    const state = el('stream-state');
    if (state) state.textContent = text;
  };

  source.onopen = () => {
    setStreamState('live', 'live');
  };
  source.onerror = () => {
    // EventSource reconnects on its own; the server replays from
    // Last-Event-ID so no events are lost.
    setStreamState('reconnecting…', 'down');
  };
  source.onmessage = (event) => handleEvent(event);
  ['scan.started', 'scan.completed', 'scan.failed', 'scan.cancelled', 'agent.completed',
    'agent.message', 'scanner.completed', 'scanner.error', 'task.blocked', 'collaboration.summary',
    'scan.paused', 'scan.resumed', 'scan.stop_requested'].forEach((kind) => {
    source.addEventListener(kind, handleEvent);
  });
}

function handleEvent(event) {
  let payload = {};
  try { payload = JSON.parse(event.data); } catch { return; }
  state.lastSeq = Math.max(state.lastSeq, Number(payload.seq || 0));

  const log = el('event-log');
  if (!log) return;
  const line = document.createElement('div');
  const kind = String(payload.kind || 'message');
  line.className = 'log-line' + (kind.includes('error') || kind.includes('failed') ? ' error' : '');
  line.innerHTML = `<span class="ts">${escape(fmtTime(payload.at))}</span>` +
    `<span class="kind">${escape(kind)}</span>` +
    `<span>${escape(JSON.stringify(payload.payload || {}).slice(0, 600))}</span>`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

/* ------------------------------------------------------------ findings */
registerRoute('findings', async () => {
  setTitle('Findings', 'Filterable across every scan');
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  const data = await api('/findings?limit=500');
  const items = data.items || [];

  el('view').innerHTML = `
    <div class="toolbar">
      <input class="filter-input" id="f-text" type="text" placeholder="Filter by title, host or class…">
      <select id="f-sev" style="max-width:150px"><option value="">All severities</option>
        ${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<option value="${s}">${s}</option>`).join('')}</select>
      <select id="f-ver" style="max-width:170px"><option value="">All verification states</option>
        ${['confirmed', 'likely', 'unverified', 'inconclusive', 'rejected'].map((s) => `<option value="${s}">${s}</option>`).join('')}</select>
      <input class="filter-input" id="f-host" type="text" placeholder="Host…">
      <div class="spacer"></div>
      <span class="badge info">${data.total} total</span>
    </div>
    <div class="grid cols-5" style="margin-bottom:16px">
      ${['critical', 'high', 'medium', 'low', 'info'].map((s) => `
        <div class="stat"><div class="label">${s}</div><div class="value">${(data.severity_counts || {})[s] ?? 0}</div></div>`).join('')}
    </div>
    <div class="card"><div class="card-body tight"><div class="table-scroll" id="f-table">${renderFindings(items)}</div></div></div>`;

  const apply = () => {
    const text = el('f-text').value.toLowerCase();
    const sev = el('f-sev').value;
    const ver = el('f-ver').value;
    const host = el('f-host').value.toLowerCase();
    const filtered = items.filter((finding) => {
      if (sev && finding.severity !== sev) return false;
      if (ver && finding.verification_status !== ver) return false;
      if (host && !(finding.host || '').toLowerCase().includes(host)) return false;
      if (!text) return true;
      return `${finding.title} ${finding.summary} ${finding.host} ${finding.vuln_class}`.toLowerCase().includes(text);
    });
    el('f-table').innerHTML = renderFindings(filtered);
  };
  ['f-text', 'f-host'].forEach((id) => el(id).addEventListener('input', apply));
  ['f-sev', 'f-ver'].forEach((id) => el(id).addEventListener('change', apply));
});

function renderServices(data) {
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

function renderFindings(items) {
  if (!items.length) return '<div class="empty"><div class="big">No findings</div>Findings appear here once a scanner or agent reports one.</div>';
  return `<table><thead><tr>
    <th>Severity</th><th>Title</th><th>Class</th><th>Location</th><th>Confidence</th><th>Verification</th><th>Detected by</th><th>Last seen</th>
  </tr></thead><tbody>
  ${items.map((finding) => `<tr>
    <td>${severityBadge(finding.severity)}</td>
    <td>${escape(finding.title)}
      <div class="small faint">${escape((finding.summary || '').slice(0, 150))}</div></td>
    <td class="small">${escape(finding.vuln_class)}${finding.cwe ? `<div class="faint">${escape(finding.cwe)}</div>` : ''}</td>
    <td class="mono small">${escape(finding.host || '-')}${escape(finding.path || '')}</td>
    <td class="num">${Math.round((finding.confidence ?? 0) * 100)}%</td>
    <td>${badge(finding.verification_status)}</td>
    <td class="small faint">${escape((finding.detected_by || []).join(', '))}</td>
    <td class="small faint nowrap">${fmtTime(finding.last_seen_at)}</td>
  </tr>`).join('')}
  </tbody></table>`;
}

/* ------------------------------------------------------- agent workspace */
registerRoute('agents', async () => {
  setTitle('Agent workspace', 'Roles, configuration and live activity');
  const [roles, defs] = await Promise.all([
    api('/admin/agent-roles'),
    api('/admin/agent-definitions').catch(() => ({ items: [] })),
  ]);
  const roleList = roles.roles || [];

  el('view').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>Agent roles</h2><span class="desc">${roleList.length} roles</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderRoleTable(roleList)}</div></div>
    </div>
    <div class="card">
      <div class="card-head"><h2>Versioned definitions</h2><span class="desc">a scan replays with the version it used</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderDefinitionTable(defs.items || [])}</div></div>
    </div>`;

  document.querySelectorAll('[data-role-detail]').forEach((node) => {
    node.addEventListener('click', () => {
      const role = roleList.find((item) => item.role === node.dataset.roleDetail);
      if (!role) return;
      el('view').innerHTML = `
        <div class="toolbar"><button class="btn small" id="back-roles">← Back</button></div>
        <div class="card">
          <div class="card-head"><h2>${escape(role.title)}</h2><span class="desc">${escape(role.role)}</span></div>
          <div class="card-body">
            <p class="muted">${escape(role.objective)}</p>
            <h3 style="font-size:13px;margin-top:18px">System prompt</h3>
            <pre class="json">${escape(role.system_prompt)}</pre>
            <h3 style="font-size:13px;margin-top:18px">Tools</h3>
            <div class="chips">${(role.tools || []).map((tool) => `<span class="chip">${escape(tool)}</span>`).join('') || '<span class="faint">none</span>'}</div>
            <h3 style="font-size:13px;margin-top:18px">Capabilities</h3>
            <div class="chips">${((role.permissions || {}).capabilities || []).map((capability) => `<span class="chip">${escape(capability)}</span>`).join('') || '<span class="faint">none</span>'}</div>
            <h3 style="font-size:13px;margin-top:18px">Budget</h3>
            <pre class="json">${escape(JSON.stringify(role.budget || {}, null, 2))}</pre>
          </div>
        </div>`;
      el('back-roles').addEventListener('click', () => navigate('agents'));
    });
  });
});

function renderRoleTable(roles) {
  return `<table><thead><tr><th>Role</th><th>Title</th><th>Stage</th><th>Tools</th><th>Capabilities</th><th>Max rounds</th></tr></thead><tbody>
    ${roles.map((role) => `<tr>
      <td><a href="#" data-role-detail="${escape(role.role)}" class="mono">${escape(role.role)}</a></td>
      <td>${escape(role.title)}</td>
      <td>${badge(role.stage)}</td>
      <td class="small faint">${escape((role.tools || []).join(', ') || 'none')}</td>
      <td class="small faint">${escape(((role.permissions || {}).capabilities || []).join(', ') || 'none')}</td>
      <td class="num">${(role.budget || {}).max_rounds ?? '-'}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

function renderDefinitionTable(defs) {
  if (!defs.length) return '<div class="empty">No custom agent definitions yet. The built-in roles are used by default.</div>';
  return `<table><thead><tr><th>Name</th><th>Role</th><th>Version</th><th>Enabled</th><th>Created by</th><th>Created</th></tr></thead><tbody>
    ${defs.map((def) => `<tr>
      <td>${escape(def.name)}</td>
      <td class="mono small">${escape(def.role)}</td>
      <td class="num">${def.version}</td>
      <td>${def.enabled ? badge('healthy') : badge('draft')}</td>
      <td class="small faint">${escape(def.created_by || '-')}</td>
      <td class="small faint">${fmtTime(def.created_at)}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/* -------------------------------------------------------------- karton */
registerRoute('karton', async () => {
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
});

function renderQueues(queues) {
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

/* ---------------------------------------------------------- benchmarks */
registerRoute('benchmarks', async () => {
  setTitle('Benchmarks', 'Vulnerable application laboratory');
  const data = await api('/benchmarks').catch(() => ({ items: [] }));
  el('view').innerHTML = `
    <div class="alert info">The benchmark laboratory runs deliberately vulnerable applications on an isolated Docker network. See <code>docs/benchmark.md</code> for the setup and teardown procedure.</div>
    <div class="card"><div class="card-body tight"><div class="table-scroll">${renderBenchmarks(data.items || [])}</div></div></div>`;
});

function renderBenchmarks(items) {
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

/* ------------------------------------------------------------- admin */
registerRoute('users', async () => {
  setTitle('Users', 'Account administration');
  const data = await api('/admin/users');
  el('view').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>Users</h2><span class="desc">${data.count} accounts</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderUsers(data.items || [])}</div></div>
    </div>`;
});

function renderUsers(users) {
  return `<table><thead><tr><th>Username</th><th>Role</th><th>Email</th><th>Active</th><th>Last login</th></tr></thead><tbody>
    ${users.map((user) => `<tr>
      <td class="mono">${escape(user.username)}</td>
      <td>${badge(user.role)}</td>
      <td class="small">${escape(user.email || '-')}</td>
      <td>${user.active ? badge('healthy') : badge('draft')}</td>
      <td class="small faint">${fmtTime(user.last_login_at)}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

registerRoute('providers', async () => {
  setTitle('Model providers', 'OpenAI-compatible endpoints');
  const data = await api('/admin/providers');
  el('view').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>Providers</h2><span class="desc">${data.count} configured</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderProviderTable(data.items || [])}</div></div>
    </div>
    <div class="card">
      <div class="card-head"><h2>Add a provider</h2><span class="desc">the secret is stored server-side only</span></div>
      <div class="card-body">
        <div class="grid cols-2">
          <div class="field"><label for="p-name">Name</label><input type="text" id="p-name" placeholder="local-llm"></div>
          <div class="field"><label for="p-model">Model</label><input type="text" id="p-model" placeholder="my-model"></div>
        </div>
        <div class="field"><label for="p-url">Base URL</label><input type="text" id="p-url" placeholder="https://api.example.com/v1"></div>
        <div class="field"><label for="p-key">API key</label><input type="password" id="p-key" placeholder="sk-…"></div>
        <button class="btn primary" id="p-save">Save provider</button>
      </div>
    </div>`;

  el('p-save').addEventListener('click', async () => {
    try {
      await api('/admin/providers', {
        method: 'POST',
        body: {
          name: el('p-name').value.trim(),
          base_url: el('p-url').value.trim(),
          model: el('p-model').value.trim(),
          api_key: el('p-key').value,
        },
      });
      toast('Provider saved.', 'ok');
      navigate('providers');
    } catch (error) {
      toast(error.message, 'error');
    }
  });
});

function renderProviderTable(providers) {
  if (!providers.length) return '<div class="empty">No providers configured. Agents cannot run until one is added.</div>';
  return `<table><thead><tr><th>Name</th><th>Base URL</th><th>Model</th><th>Enabled</th><th></th></tr></thead><tbody>
    ${providers.map((provider) => `<tr>
      <td class="mono">${escape(provider.name)}</td>
      <td class="mono small">${escape(provider.base_url)}</td>
      <td class="small">${escape(provider.model || '-')}</td>
      <td>${provider.enabled ? badge('healthy') : badge('draft')}</td>
      <td class="right"><button class="btn small" data-health="${escape(provider.name)}">Check health</button></td>
    </tr>`).join('')}
  </tbody></table>`;
}

registerRoute('agent-defs', async () => {
  setTitle('Agent definitions', 'Versioned role configuration');
  const [defs, roles] = await Promise.all([
    api('/admin/agent-definitions'),
    api('/admin/agent-roles'),
  ]);
  el('view').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>Definitions</h2><span class="desc">editing creates a new version</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderDefinitionTable(defs.items || [])}</div></div>
    </div>`;
});

registerRoute('audit', async () => {
  setTitle('Audit log', 'Authentication and administrative actions');
  const data = await api('/admin/audit?limit=300');
  el('view').innerHTML = `
    <div class="card"><div class="card-body tight"><div class="table-scroll">${renderAudit(data.items || [])}</div></div></div>`;
});

function renderAudit(entries) {
  if (!entries.length) return '<div class="empty">No audit entries yet.</div>';
  return `<table><thead><tr><th>When</th><th>Action</th><th>Actor</th><th>Target</th><th>Outcome</th><th>IP</th></tr></thead><tbody>
    ${entries.map((entry) => `<tr>
      <td class="small faint nowrap">${fmtTime(entry.at)}</td>
      <td class="mono small">${escape(entry.action)}</td>
      <td class="small">${escape(entry.actor)}</td>
      <td class="small faint">${escape(entry.target_type || '-')}${entry.target_id ? ' ' + escape(entry.target_id) : ''}</td>
      <td>${badge(entry.outcome === 'success' ? 'healthy' : 'failed')}</td>
      <td class="small faint mono">${escape(entry.ip_address || '-')}</td>
    </tr>`).join('')}
  </tbody></table>`;
}

/* ------------------------------------------------------------- startup */
(async function start() {
  try {
    await api('/auth/me');
    await enterApp();
  } catch {
    showLogin();
  }
})();
