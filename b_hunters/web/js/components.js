/* The render helpers that more than one view uses.
 *
 * The DOM helpers (el, setTitle, toast) live here too: they are the
 * console's way of touching the page and every view needs them.  The
 * renderers here are pure — they take data and return markup — so they
 * can be checked without a browser.
 */

import { badge, escape, fmtTime, severityBadge } from './format.js';

/** The element with this id. */
export function el(id) {
  return document.getElementById(id);
}

/** Set the page title and the crumb under it. */
export function setTitle(title, crumb) {
  el('page-title').textContent = title;
  el('page-crumb').textContent = crumb || '';
}

/** Show a message in the corner of the page. */
export function toast(message, kind = 'info') {
  const host = el('toasts');
  const node = document.createElement('div');
  node.className = `toast ${kind}`;
  node.textContent = message;
  host.appendChild(node);
  setTimeout(() => node.remove(), 5200);
}

/** A key and value list; used for the counters the API returns. */
export function renderKeyValues(obj) {
  const keys = Object.keys(obj || {});
  if (!keys.length) return '<div class="empty">No verification data yet.</div>';
  return `<dl class="kv">${keys.map((k) => `<dt>${escape(k)}</dt><dd>${escape(obj[k])}</dd>`).join('')}</dl>`;
}

/**
 * Render a long tool output.
 *
 * A long output is collapsed, not cut: the whole of it is in the page
 * and the reader opens it when they want it.
 */
export function renderOutput(text) {
  const body = escape(text || '');
  if (body.length <= 900) {
    return `<pre style="white-space: pre-wrap; font-size: 0.78rem; margin: 0.2rem 0 0.6rem 0;">${body}</pre>`;
  }
  return `<details><summary style="cursor: pointer; font-size: 0.78rem;">${body.slice(0, 900)} … (${body.length} characters, open for the rest)</summary><pre style="white-space: pre-wrap; font-size: 0.78rem; margin: 0.2rem 0 0.6rem 0;">${body}</pre></details>`;
}

/**
 * Group the recorded tool calls by the role that made them.
 *
 * The counts are what each role actually did, so the table can say
 * "nuclei ×3" instead of repeating the transcript.
 */
export function groupToolCallsByRole(toolCalls) {
  const byRole = {};
  (toolCalls || []).forEach((call) => {
    const role = call.agent_role || call.role || 'unknown';
    byRole[role] = byRole[role] || {};
    const tool = call.tool || call.name || 'tool';
    byRole[role][tool] = (byRole[role][tool] || 0) + 1;
  });
  return byRole;
}

/** The agents table; the dashboard and the scan's agent tab share it. */
export function renderAgents(agents, toolCalls) {
  if (!agents.length) return '<div class="empty">No agents are active.</div>';
  // What each role actually did, from the tool calls it recorded.
  const byRole = groupToolCallsByRole(toolCalls);
  return `<table><thead><tr><th>Role</th><th>Status</th><th>What it did</th><th>Conclusion</th><th>Last seen</th></tr></thead><tbody>
    ${agents.map((agent) => {
      const tools = byRole[agent.role] || {};
      const used = Object.keys(tools).sort().map((tool) => `${tool} ×${tools[tool]}`).join(', ');
      const detail = agent.detail || {};
      const counts = [
        detail.rounds ? `${detail.rounds} rounds` : '',
        detail.tool_calls_used ? `${detail.tool_calls_used} tool calls` : '',
        detail.tokens_used ? `${detail.tokens_used} tokens` : '',
        detail.duration_seconds ? `${detail.duration_seconds}s` : '',
      ].filter(Boolean).join(' · ');
      return `<tr>
      <td class="mono">${escape(agent.role)}</td>
      <td>${badge(agent.status)}</td>
      <td class="small">${escape(used || '-')}${counts ? `<div class="faint">${escape(counts)}</div>` : ''}</td>
      <td class="small">${escape(agent.conclusion || (agent.error ? agent.error : '-'))}</td>
      <td class="small faint">${fmtTime(agent.last_seen_at)}</td>
    </tr>`;
    }).join('')}
  </tbody></table>`;
}

/** The findings table; the findings view and the scan's tab share it. */
export function renderFindings(items) {
  if (!items.length) return '<div class="empty"><div class="big">No findings</div>Findings appear here once a scanner or agent reports one.</div>';
  return `<table><thead><tr>
    <th>Severity</th><th>Tool</th><th>Title</th><th>Class</th><th>Location</th><th>Confidence</th><th>Verification</th><th>Last seen</th>
  </tr></thead><tbody>
  ${items.map((finding) => `<tr>
    <td>${severityBadge(finding.severity)}</td>
    <td class="small"><span class="badge bg-secondary">${escape((finding.detected_by || []).join(', ') || finding.detection_source || '-')}</span></td>
    <td>${escape(finding.title)}
      <div class="small faint">${escape((finding.summary || '').slice(0, 150))}</div></td>
    <td class="small">${escape(finding.vuln_class)}${finding.cwe ? `<div class="faint">${escape(finding.cwe)}</div>` : ''}</td>
    <td class="mono small">${escape(finding.host || '-')}${escape(finding.path || '')}</td>
    <td class="num">${Math.round((finding.confidence ?? 0) * 100)}%</td>
    <td>${badge(finding.verification_status)}</td>
    <td class="small faint nowrap">${fmtTime(finding.last_seen_at)}</td>
  </tr>`).join('')}
  </tbody></table>`;
}

/** The versioned agent definitions; the agent views share it. */
export function renderDefinitionTable(defs) {
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
