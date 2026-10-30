/* The findings of every scan, with the filters the platform offers. */

import { api } from '../api.js';
import { el, renderFindings, setTitle } from '../components.js';

/** The tools that can raise a finding: the workers and the agent roles. */
export function detectorOptions(items) {
  const names = new Set();
  for (const finding of items || []) {
    for (const name of finding.detected_by || []) names.add(name);
    if (finding.detection_source) names.add(finding.detection_source);
  }
  return [...names].sort();
}

/** The findings route. */
export async function findingsView() {
  setTitle('Findings', 'Filterable across every scan');
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  const data = await api('/findings?limit=500');
  const items = data.items || [];
  const detectors = detectorOptions(items);

  el('view').innerHTML = `
    <div class="toolbar">
      <input class="filter-input" id="f-text" type="text" placeholder="Filter by title, host or class…">
      <select id="f-sev" style="max-width:150px"><option value="">All severities</option>
        ${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<option value="${s}">${s}</option>`).join('')}</select>
      <select id="f-ver" style="max-width:170px"><option value="">All verification states</option>
        ${['confirmed', 'likely', 'unverified', 'inconclusive', 'rejected'].map((s) => `<option value="${s}">${s}</option>`).join('')}</select>
      <select id="f-det" style="max-width:190px"><option value="">All detectors</option>
        ${detectors.map((d) => `<option value="${d}">${d}</option>`).join('')}</select>
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
    const det = el('f-det').value;
    const host = el('f-host').value.toLowerCase();
    const filtered = items.filter((finding) => {
      if (sev && finding.severity !== sev) return false;
      if (ver && finding.verification_status !== ver) return false;
      if (det) {
        // A finding is the work of the tool that raised it: the
        // detector is one of the tools that found it.
        const found = finding.detected_by || [];
        const source = finding.detection_source || '';
        if (!found.includes(det) && source !== det) return false;
      }
      if (host && !(finding.host || '').toLowerCase().includes(host)) return false;
      if (!text) return true;
      return `${finding.title} ${finding.summary} ${finding.host} ${finding.vuln_class}`.toLowerCase().includes(text);
    });
    el('f-table').innerHTML = renderFindings(filtered);
  };
  ['f-text', 'f-host'].forEach((id) => el(id).addEventListener('input', apply));
  ['f-sev', 'f-ver', 'f-det'].forEach((id) => el(id).addEventListener('change', apply));
}
