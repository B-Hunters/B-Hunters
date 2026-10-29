/* The new scan form: the scope, the limits and the profile. */

import { api } from '../api.js';
import { el, setTitle, toast } from '../components.js';
import { escape, fmtDuration, splitLines } from '../format.js';
import { navigate } from '../router.js';

/** The new scan route. */
export async function newScanView() {
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
                <option value="standard">standard - discovery, analysis, reporting</option>
                <option value="recon">recon - discovery only</option>
              </select>
            </div>
            <div class="field">
              <label style="display:flex;align-items:center;gap:7px;margin:0"><input type="checkbox" id="scan-verifier" style="width:auto"> Independent verifier</label>
              <div class="hint">The verifier re-checks every candidate finding, which costs one request each. The reporting role reconciles the findings either way. Leave it off unless you want the second opinion.</div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h2>Agent roles</h2><span class="desc">${roleList.length} available</span></div>
          <div class="card-body">
            <div class="chips" id="role-chips">
              ${roleList.map((role) => `<span class="chip" data-role="${escape(role.role)}" title="${escape(role.objective)}">${escape(role.title)}</span>`).join('')}
            </div>
            <div class="hint" style="margin-top:10px">Click the roles this scan should run. The reporting role is always added. Leave every chip off to run the whole set.</div>
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
    independent_verifier: el('scan-verifier').checked,
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
}

/** The roles or the scanners the user ticked. */
export function selectedChips(containerId, attribute) {
  return Array.from(el(containerId).querySelectorAll(`.chip.on[data-${attribute}]`))
    .map((chip) => chip.dataset[attribute]);
}
