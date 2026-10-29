/* The render helpers the views share. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  groupToolCallsByRole,
  renderAgents,
  renderDefinitionTable,
  renderFindings,
  renderKeyValues,
  renderOutput,
} from '../../b_hunters/web/js/components.js';

test('a key and value list shows every pair', () => {
  const html = renderKeyValues({ confirmed: 3, unverified: 1 });
  assert.match(html, /<dt>confirmed<\/dt><dd>3<\/dd>/);
  assert.match(html, /<dt>unverified<\/dt><dd>1<\/dd>/);
});

test('an empty key and value list says so', () => {
  assert.match(renderKeyValues({}), /No verification data yet/);
  assert.match(renderKeyValues(null), /No verification data yet/);
});

test('a key and value list escapes its keys and values', () => {
  const html = renderKeyValues({ '<b>': '<i>' });
  assert.match(html, /&lt;b&gt;/);
  assert.match(html, /&lt;i&gt;/);
  assert.doesNotMatch(html, /<b>/);
});

test('a short output is shown in full', () => {
  const html = renderOutput('nuclei found nothing');
  assert.match(html, /<pre/);
  assert.doesNotMatch(html, /<details/);
  assert.match(html, /nuclei found nothing/);
});

test('a long output is collapsed but kept whole', () => {
  const html = renderOutput('x'.repeat(1200));
  assert.match(html, /<details/);
  assert.match(html, /1200 characters/);
  assert.match(html, /x{900}/);
});

test('an output is escaped', () => {
  assert.match(renderOutput('<script>'), /&lt;script&gt;/);
});

test('the tool calls are grouped by the role that made them', () => {
  const grouped = groupToolCallsByRole([
    { agent_role: 'recon', tool: 'nuclei' },
    { agent_role: 'recon', tool: 'nuclei' },
    { agent_role: 'recon', tool: 'katana' },
    { role: 'analyst', name: 'dalfox' },
    { tool: 'curl' },
  ]);
  assert.deepEqual(grouped, {
    recon: { nuclei: 2, katana: 1 },
    analyst: { dalfox: 1 },
    unknown: { curl: 1 },
  });
});

test('no tool calls group into nothing', () => {
  assert.deepEqual(groupToolCallsByRole([]), {});
  assert.deepEqual(groupToolCallsByRole(null), {});
});

test('the agents table says what each role did', () => {
  const html = renderAgents(
    [{ role: 'recon', status: 'idle', last_seen_at: 1, conclusion: 'nothing found' }],
    [{ agent_role: 'recon', tool: 'nuclei' }, { agent_role: 'recon', tool: 'katana' }],
  );
  assert.match(html, /katana ×1, nuclei ×1/);
  assert.match(html, /nothing found/);
  assert.match(html, /<span class="badge idle">idle<\/span>/);
});

test('the agents table shows the counters of a run', () => {
  const html = renderAgents(
    [{ role: 'recon', status: 'idle', detail: { rounds: 3, tool_calls_used: 12, tokens_used: 900 } }],
    [],
  );
  assert.match(html, /3 rounds · 12 tool calls · 900 tokens/);
});

test('no agents say so', () => {
  assert.match(renderAgents([], []), /No agents are active/);
});

test('the findings table shows the finding and its verification', () => {
  const html = renderFindings([
    {
      severity: 'high',
      title: 'Reflected XSS',
      summary: 'The parameter is echoed',
      vuln_class: 'xss',
      cwe: 'CWE-79',
      host: 'demo.test',
      path: '/search',
      confidence: 0.9,
      verification_status: 'confirmed',
      detected_by: ['nuclei'],
      last_seen_at: 1,
    },
  ]);
  assert.match(html, /Reflected XSS/);
  assert.match(html, /<span class="badge high">high<\/span>/);
  assert.match(html, /confirmed/);
  assert.match(html, /90%/);
  assert.match(html, /CWE-79/);
  assert.match(html, /demo\.test/);
});

test('no findings say so', () => {
  assert.match(renderFindings([]), /No findings/);
});

test('the definitions table shows the version and the state', () => {
  const html = renderDefinitionTable([
    { name: 'recon-v2', role: 'recon', version: 2, enabled: true, created_by: 'admin', created_at: 1 },
  ]);
  assert.match(html, /recon-v2/);
  assert.match(html, /<td class="num">2<\/td>/);
  assert.match(html, /healthy/);
});

test('no definitions say so', () => {
  assert.match(renderDefinitionTable([]), /No custom agent definitions yet/);
});
