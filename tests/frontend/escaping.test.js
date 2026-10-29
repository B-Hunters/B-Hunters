/* The escaping is a security property, not a style choice.
 *
 * The console renders target-derived content: host names, page titles,
 * tool output, scanner findings.  Every one of those values has to
 * reach the page as text and never as markup.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { badge, escape } from '../../b_hunters/web/js/format.js';
import {
  renderAgents,
  renderDefinitionTable,
  renderFindings,
  renderKeyValues,
  renderOutput,
} from '../../b_hunters/web/js/components.js';
import {
  renderErrors,
  renderProviders,
  renderRecentScans,
  renderSeverityBars,
  renderToolHealth,
} from '../../b_hunters/web/js/views/dashboard.js';
import { renderScanTable } from '../../b_hunters/web/js/views/scans.js';
import {
  renderMessages,
  renderScanners,
  renderServices,
  renderTasks,
  renderToolCalls,
} from '../../b_hunters/web/js/views/scan-detail.js';
import { renderRoleTable } from '../../b_hunters/web/js/views/agents.js';
import { renderQueues } from '../../b_hunters/web/js/views/karton.js';
import { renderBenchmarks } from '../../b_hunters/web/js/views/benchmarks.js';
import { renderAudit, renderProviderTable, renderUsers } from '../../b_hunters/web/js/views/admin.js';

const HOSTILE = '<img src=x onerror="alert(1)">';
const SCRIPT = '</script><script>alert(1)</script>';

function assertEscaped(html, label) {
  // The value may still read as text on the page; what must not happen
  // is that it becomes a tag.
  assert.doesNotMatch(html, /<img/, `${label} lets an image tag through`);
  assert.doesNotMatch(html, /<script/i, `${label} lets a script tag through`);
  assert.doesNotMatch(html, /<\/script/i, `${label} lets a closing script tag through`);
}

test('the scanners table escapes the values of a target', () => {
  const html = renderScanners(
    {
      workers: [{
        worker: HOSTILE,
        status: SCRIPT,
        tasks: 1,
        items: 1,
        candidates: 0,
        output: [{ field: HOSTILE, count: 1, preview: SCRIPT, truncated: false }],
      }],
      summary: { crawled_urls: 0, urls_with_parameters: 0 },
    },
    { items: [{ worker: HOSTILE, kind: 'url', value: SCRIPT }] },
  );
  assertEscaped(html, 'the scanners table');
  assert.match(html, /&lt;img/);
});

test('the services table escapes the values of a target', () => {
  const html = renderServices({
    urls: [{
      url: HOSTILE,
      status_code: 200,
      title: SCRIPT,
      services: [{ name: HOSTILE, version: SCRIPT, category: HOSTILE, source: HOSTILE, confidence: 0.5 }],
    }],
    summary: { services: [{ name: HOSTILE, version: SCRIPT, category: HOSTILE, count: 1 }] },
  });
  assertEscaped(html, 'the services table');
});

test('the findings table escapes the values of a target', () => {
  const html = renderFindings([
    {
      severity: HOSTILE,
      title: SCRIPT,
      summary: HOSTILE,
      vuln_class: HOSTILE,
      cwe: HOSTILE,
      host: HOSTILE,
      path: SCRIPT,
      confidence: 0.5,
      verification_status: HOSTILE,
      detected_by: [HOSTILE],
      detection_source: HOSTILE,
      last_seen_at: 1,
    },
  ]);
  assertEscaped(html, 'the findings table');
});

test('the scan tables escape the values of a target', () => {
  assertEscaped(
    renderScanTable([{
      scan_id: HOSTILE,
      name: SCRIPT,
      status: HOSTILE,
      definition: { targets: [HOSTILE] },
      finding_counts: {},
      created_by: SCRIPT,
      created_at: 1,
    }]),
    'the scans table',
  );
  assertEscaped(
    renderRecentScans([{
      scan_id: HOSTILE,
      name: SCRIPT,
      status: HOSTILE,
      definition: { targets: [HOSTILE] },
      created_at: 1,
    }]),
    'the recent scans table',
  );
  assertEscaped(
    renderTasks([{ title: SCRIPT, task_id: HOSTILE, agent_role: HOSTILE, status: HOSTILE, depends_on: [SCRIPT], attempts: 0, error: SCRIPT }]),
    'the tasks table',
  );
  assertEscaped(
    renderMessages([{ seq: 1, kind: HOSTILE, sender_role: SCRIPT, target: HOSTILE, hypothesis: SCRIPT, confidence: HOSTILE, disposition: SCRIPT }]),
    'the messages table',
  );
  assertEscaped(
    renderToolCalls([{ at: 1, agent_role: SCRIPT, tool: HOSTILE, status: 'ok', duration_ms: 1, output: SCRIPT }]),
    'the tool calls table',
  );
  assertEscaped(
    renderAgents([{ role: SCRIPT, status: HOSTILE, last_seen_at: 1, conclusion: SCRIPT }], [{ agent_role: SCRIPT, tool: HOSTILE }]),
    'the agents table',
  );
});

test('the admin tables escape the values of a target', () => {
  assertEscaped(
    renderUsers([{ username: SCRIPT, role: HOSTILE, email: SCRIPT, active: true, last_login_at: 1 }]),
    'the users table',
  );
  assertEscaped(
    renderProviderTable([{ name: SCRIPT, base_url: HOSTILE, model: SCRIPT, enabled: true }]),
    'the providers table',
  );
  assertEscaped(
    renderAudit([{ at: 1, action: SCRIPT, actor: HOSTILE, target_type: SCRIPT, target_id: SCRIPT, outcome: HOSTILE, ip_address: SCRIPT }]),
    'the audit table',
  );
  assertEscaped(
    renderDefinitionTable([{ name: SCRIPT, role: HOSTILE, version: 1, enabled: true, created_by: SCRIPT, created_at: 1 }]),
    'the definitions table',
  );
  assertEscaped(
    renderRoleTable([{ role: SCRIPT, title: HOSTILE, stage: SCRIPT, tools: [HOSTILE], permissions: { capabilities: [SCRIPT] }, budget: {} }]),
    'the roles table',
  );
});

test('the dashboard tables escape the values of a target', () => {
  assertEscaped(
    renderToolHealth([{ name: SCRIPT, version: HOSTILE, status: SCRIPT, capabilities: [HOSTILE] }]),
    'the tool health table',
  );
  assertEscaped(
    renderProviders([{ name: SCRIPT, model: HOSTILE, reachable: true, latency_ms: 1 }]),
    'the providers table',
  );
  assertEscaped(
    renderErrors([{ at: 1, kind: SCRIPT, scan_id: HOSTILE, payload: { message: SCRIPT } }]),
    'the errors table',
  );
  assertEscaped(renderKeyValues({ [SCRIPT]: HOSTILE }), 'the key and value list');
  assertEscaped(renderOutput(SCRIPT), 'the output');
  assertEscaped(renderBenchmarks([{ name: SCRIPT, slug: HOSTILE, version: SCRIPT, image: SCRIPT, port: HOSTILE, test_cases: [], license: SCRIPT, available: true }]), 'the benchmarks table');
  assertEscaped(renderQueues([{ queue: SCRIPT, online_consumers: 1, pending_tasks: 0, started_tasks: 0, crashed_tasks: 0, oldest_task_age_seconds: 0 }]), 'the queues table');
});

test('the severity bars show only the five known severities', () => {
  const html = renderSeverityBars({ [HOSTILE]: 1 }, 1);
  assertEscaped(html, 'the severity bars');
  assert.match(html, /critical/);
  assert.doesNotMatch(html, /&lt;img/);
});

test('a badge escapes the value it shows', () => {
  assertEscaped(badge(HOSTILE), 'the badge');
});

test('escape leaves no angle bracket of a hostile value', () => {
  const escaped = escape(SCRIPT);
  assert.equal(escaped, '&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.doesNotMatch(escaped, /</);
});
