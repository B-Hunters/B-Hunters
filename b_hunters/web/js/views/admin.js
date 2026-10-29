/* The administration views: the accounts, the providers and the audit log. */

import { api } from '../api.js';
import { el, renderDefinitionTable, setTitle, toast } from '../components.js';
import { badge, escape, fmtTime } from '../format.js';
import { navigate } from '../router.js';

/** The users route. */
export async function usersView() {
  setTitle('Users', 'Account administration');
  const data = await api('/admin/users');
  el('view').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>Users</h2><span class="desc">${data.count} accounts</span></div>
      <div class="card-body tight"><div class="table-scroll">${renderUsers(data.items || [])}</div></div>
    </div>`;
}

/** The table of the accounts. */
export function renderUsers(users) {
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

/** The model providers route. */
export async function providersView() {
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
}

/** The table of the configured providers. */
export function renderProviderTable(providers) {
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

/** The agent definitions route. */
export async function agentDefinitionsView() {
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
}

/** The audit log route. */
export async function auditView() {
  setTitle('Audit log', 'Authentication and administrative actions');
  const data = await api('/admin/audit?limit=300');
  el('view').innerHTML = `
    <div class="card"><div class="card-body tight"><div class="table-scroll">${renderAudit(data.items || [])}</div></div></div>`;
}

/** The table of the audit entries. */
export function renderAudit(entries) {
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
