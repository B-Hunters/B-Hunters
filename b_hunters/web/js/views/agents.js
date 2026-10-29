/* The agent workspace: the roles, their prompts and their versions. */

import { api } from '../api.js';
import { el, renderDefinitionTable, setTitle } from '../components.js';
import { badge, escape } from '../format.js';
import { navigate } from '../router.js';

/** The agent workspace route. */
export async function agentsView() {
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
}

/** The table of the roles the platform knows. */
export function renderRoleTable(roles) {
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
