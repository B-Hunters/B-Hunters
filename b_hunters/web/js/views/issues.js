/* The issues: the durable findings, with their triage state and their
 * comments.
 *
 * A finding belongs to the scan that found it.  An issue is the thing
 * behind it: it carries the state (is it open, in progress, fixed?) and
 * it is what the operator works on.  The same problem found by a later
 * scan of the same target is the same issue, so marking it fixed in
 * one scan marks it fixed in every scan after that.
 */

import { api } from '../api.js';
import { el, setTitle } from '../components.js';
import { escape } from '../format.js';

/** The states a triage can be in. */
export const TRIAGE_STATES = [
  'open',
  'in_progress',
  'fixed',
  'risk_accepted',
  'false_positive',
  'duplicate',
  'auto_closed',
];

/** The severity of an issue, worst first. */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * The triage states of an issue, as a badge.
 *
 * The colour says where the issue stands, not how bad it is: an open
 * critical issue and a fixed critical issue are the same severity and
 * a different state.
 */
export function triageBadge(status) {
  const tone = {
    open: 'danger',
    in_progress: 'warn',
    fixed: 'ok',
    risk_accepted: 'info',
    false_positive: 'muted',
    duplicate: 'muted',
    auto_closed: 'muted',
  }[status] || 'muted';
  return `<span class="badge ${tone}">${escape(status || 'open')}</span>`;
}

/** The rows of the issue table. */
export function renderIssues(issues) {
  if (!issues || !issues.length) {
    return '<p class="muted">No issue has been recorded yet.</p>';
  }
  const rows = issues.map((issue) => `
    <tr data-issue="${escape(issue.issue_id)}">
      <td>${escape(issue.severity || 'info')}</td>
      <td>${escape(issue.title || '')}</td>
      <td>${escape(issue.vuln_class || '')}</td>
      <td>${triageBadge(issue.triage_status)}</td>
      <td>${escape(issue.assignee || '')}</td>
      <td>${(issue.tags || []).map((t) => `<span class="badge info">${escape(t)}</span>`).join(' ')}</td>
      <td><button class="btn small" data-open="${escape(issue.issue_id)}">Open</button></td>
    </tr>`).join('');
  return `
    <table class="table">
      <thead><tr>
        <th>Severity</th><th>Title</th><th>Class</th><th>State</th>
        <th>Owner</th><th>Tags</th><th></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

/** The issue route. */
export async function issuesView() {
  setTitle('Issues', 'The durable findings, and what was decided about them');
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  const state = params.get('triage_status') || '';
  const data = await api(`/issues?limit=500${state ? `&triage_status=${encodeURIComponent(state)}` : ''}`);
  const items = data.issues || [];

  el('view').innerHTML = `
    <div class="toolbar">
      <select id="i-state" style="max-width:180px"><option value="">All states</option>
        ${TRIAGE_STATES.map((s) => `<option value="${s}"${s === state ? ' selected' : ''}>${s}</option>`).join('')}</select>
      <input class="filter-input" id="i-text" type="text" placeholder="Filter by title or class…">
      <div class="spacer"></div>
      <span class="badge info">${data.count} issue(s)</span>
    </div>
    <div class="grid cols-5" style="margin-bottom:16px">
      ${SEVERITIES.map((s) => `
        <div class="stat"><div class="label">${s}</div>
          <div class="value">${items.filter((i) => i.severity === s).length}</div></div>`).join('')}
    </div>
    <div class="card"><div class="card-body tight">
      <div class="table-scroll" id="i-table">${renderIssues(items)}</div>
    </div></div>
    <div id="i-detail"></div>`;

  const apply = () => {
    const text = el('i-text').value.toLowerCase();
    const filtered = items.filter((issue) =>
      !text || `${issue.title} ${issue.vuln_class} ${issue.host || ''}`.toLowerCase().includes(text));
    el('i-table').innerHTML = renderIssues(filtered);
    el('i-table').querySelectorAll('[data-open]').forEach((button) =>
      button.addEventListener('click', () => openIssue(button.dataset.open)));
  };

  el('i-state').addEventListener('change', (event) => {
    location.hash = `#/issues?triage_status=${encodeURIComponent(event.target.value)}`;
  });
  el('i-text').addEventListener('input', apply);
  apply();
}

/** The panel of one issue: its state, its history and its comments. */
export async function openIssue(issueId) {
  const detail = el('i-detail');
  if (!detail) return;
  detail.innerHTML = '<div class="card"><div class="card-body">Loading…</div></div>';
  const [issue, history] = await Promise.all([
    api(`/issues/${issueId}`),
    api(`/issues/${issueId}/history`),
  ]);
  const comments = await api(`/issues/${issueId}/comments`);

  detail.innerHTML = `
    <div class="card" style="margin-top:16px">
      <div class="card-body">
        <h3>${escape(issue.title || '')}</h3>
        <p class="muted">${escape(issue.vuln_class || '')} · ${escape(issue.severity || '')} ·
          ${escape(issue.host || '')}${escape(issue.path || '')}</p>
        <div class="toolbar">
          <select id="d-state" style="max-width:180px">
            ${TRIAGE_STATES.map((s) => `<option value="${s}"${s === issue.triage_status ? ' selected' : ''}>${s}</option>`).join('')}
          </select>
          <input class="filter-input" id="d-owner" type="text" placeholder="Owner…"
            value="${escape(issue.assignee || '')}">
          <button class="btn" id="d-save">Save</button>
          <div class="spacer"></div>
          <span class="badge info">${history.events.length} change(s)</span>
        </div>
        <h4>Comments</h4>
        <div id="d-comments">
          ${(comments.comments || []).map((c) => `
            <div class="comment">
              <div class="muted small">${escape(c.author || '')} · ${escape(String(c.created_at || ''))}</div>
              <div>${escape(c.body || '')}</div>
            </div>`).join('') || '<p class="muted">No comment yet.</p>'}
        </div>
        <div class="toolbar">
          <input class="filter-input" id="d-comment" type="text" placeholder="Write a comment…">
          <button class="btn" id="d-comment-send">Comment</button>
        </div>
        <h4>History</h4>
        <div class="table-scroll">
          <table class="table"><thead><tr><th>When</th><th>Event</th><th>From</th><th>To</th></tr></thead>
          <tbody>
            ${(history.events || []).map((e) => `
              <tr><td>${escape(String(e.at || ''))}</td><td>${escape(e.event || '')}</td>
              <td>${escape(e.from || '')}</td><td>${escape(e.to || '')}</td></tr>`).join('')
              || '<tr><td colspan="4" class="muted">Nothing yet.</td></tr>'}
          </tbody></table>
        </div>
      </div>
    </div>`;

  el('d-save').addEventListener('click', async () => {
    await api(`/issues/${issueId}/triage`, {
      method: 'POST',
      body: { status: el('d-state').value, assignee: el('d-owner').value },
    });
    issuesView();
  });

  el('d-comment-send').addEventListener('click', async () => {
    const body = el('d-comment').value.trim();
    if (!body) return;
    await api(`/issues/${issueId}/comments`, { method: 'POST', body: { body } });
    openIssue(issueId);
  });
}
