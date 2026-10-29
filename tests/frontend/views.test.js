/* The tables the views render. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

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

test('the severity bars show a bar and a share per severity', () => {
  const html = renderSeverityBars({ critical: 2, high: 1 }, 3);
  assert.match(html, /<span class="badge critical">critical<\/span>/);
  assert.match(html, /width:67%/);
  assert.match(html, /width:33%/);
});

test('the severity bars show nothing without findings', () => {
  const html = renderSeverityBars({}, 0);
  assert.match(html, /width:0%/);
  assert.doesNotMatch(html, /undefined/);
});

test('the recent scans link to the scan', () => {
  const html = renderRecentScans([
    { scan_id: 's1', name: 'webgoat', status: 'completed', definition: { targets: ['http://a'] }, created_at: 1 },
  ]);
  assert.match(html, /href="#\/scans\/s1"/);
  assert.match(html, /webgoat/);
  assert.match(html, /<span class="badge completed">completed<\/span>/);
});

test('no recent scans say so', () => {
  assert.match(renderRecentScans([]), /No scans have been created yet/);
});

test('the tool health table names the adapter and its capabilities', () => {
  const html = renderToolHealth([
    { name: 'dalfox', version: '1.1.16', status: 'healthy', capabilities: ['xss'] },
  ]);
  assert.match(html, /dalfox/);
  assert.match(html, /1\.1\.16/);
  assert.match(html, /xss/);
});

test('no adapters say so', () => {
  assert.match(renderToolHealth([]), /No adapters registered/);
});

test('the providers table shows whether a provider answers', () => {
  const html = renderProviders([
    { name: 'local', model: 'm', reachable: true, latency_ms: 12 },
    { name: 'far', model: '', reachable: false, latency_ms: 0 },
  ]);
  assert.match(html, /healthy/);
  assert.match(html, /unavailable/);
  assert.match(html, /12 ms/);
});

test('no providers say so', () => {
  assert.match(renderProviders([]), /No model providers are configured/);
});

test('the errors table shows the kind and the scan', () => {
  const html = renderErrors([
    { at: 1, kind: 'scanner', scan_id: 's1', payload: { message: 'boom' } },
  ]);
  assert.match(html, /<span class="badge scanner">scanner<\/span>/);
  assert.match(html, /s1/);
  assert.match(html, /boom/);
});

test('no errors say so', () => {
  assert.match(renderErrors([]), /No recent errors/);
});

test('the scans table shows the counts and who started the scan', () => {
  const html = renderScanTable([
    {
      scan_id: 's1',
      name: 'webgoat',
      status: 'running',
      definition: { targets: ['http://a', 'http://b'] },
      finding_counts: { critical: 1, high: 2 },
      created_by: 'admin',
      created_at: 1,
    },
  ]);
  assert.match(html, /href="#\/scans\/s1"/);
  assert.match(html, /http:\/\/a, http:\/\/b/);
  assert.match(html, /<td class="num">1<\/td>/);
  assert.match(html, /<td class="num">2<\/td>/);
  assert.match(html, /admin/);
});

test('no scans say so', () => {
  assert.match(renderScanTable([]), /No scans yet/);
});

test('the scanners table keeps what the workers found', () => {
  const html = renderScanners(
    {
      workers: [{
        worker: 'B-Hunters-Nuclei',
        status: 'found',
        tasks: 3,
        items: 3,
        candidates: 0,
        output: [{ field: 'Vulns.Nuclei', count: 3, preview: 'x', truncated: false }],
      }],
      summary: { crawled_urls: 1, urls_with_parameters: 0 },
    },
    { items: [{ worker: 'B-Hunters-Katana', kind: 'url', value: 'http://a/x' }] },
  );
  assert.match(html, /What the scanners found/);
  assert.match(html, /1 item\(s\) saved/);
  assert.match(html, /B-Hunters-Nuclei/);
  assert.match(html, /Scan these 1 URL\(s\)/);
});

test('no scanner workers say so', () => {
  assert.match(renderScanners({ workers: [] }, {}), /No scanner workers are connected/);
});

test('the tasks table shows the dependencies', () => {
  const html = renderTasks([
    { title: 'crawl', task_id: 't1', agent_role: 'recon', status: 'done', depends_on: ['x:1'], attempts: 1, error: '' },
  ]);
  assert.match(html, /crawl/);
  assert.match(html, /t1/);
  assert.match(html, /1<\/td>/);
  assert.match(html, /done/);
});

test('no tasks say so', () => {
  assert.match(renderTasks([]), /No tasks have been created yet/);
});

test('the messages table shows the hypothesis and the disposition', () => {
  const html = renderMessages([
    {
      seq: 3,
      kind: 'handoff',
      sender_role: 'recon',
      target: 'analyst',
      hypothesis: 'the parameter is echoed',
      confidence: 'likely',
      disposition: 'accepted',
    },
  ]);
  assert.match(html, /handoff/);
  assert.match(html, /the parameter is echoed/);
  assert.match(html, /accepted/);
});

test('no messages say so', () => {
  assert.match(renderMessages([]), /No agent messages yet/);
});

test('the tool calls table shows the duration and the outcome', () => {
  const html = renderToolCalls([
    { at: 1, agent_role: 'recon', tool: 'nuclei', status: 'ok', duration_ms: 12, output: 'found' },
  ]);
  assert.match(html, /nuclei/);
  assert.match(html, /12 ms/);
  assert.match(html, /healthy/);
});

test('no tool calls say so', () => {
  assert.match(renderToolCalls([]), /No tool calls have been recorded yet/);
});

test('the services table shows the inventory and the services per url', () => {
  const html = renderServices({
    urls: [{
      url: 'https://demo.test',
      status_code: 200,
      title: 'Demo',
      services: [{ name: 'nginx', version: '1.24', category: 'web', source: 'header', confidence: 0.8 }],
    }],
    summary: { services: [{ name: 'nginx', version: '1.24', category: 'web', count: 1 }] },
  });
  assert.match(html, /Inventory/);
  assert.match(html, /nginx/);
  assert.match(html, /https:\/\/demo\.test/);
  assert.match(html, /80%/);
});

test('no services say so', () => {
  assert.match(renderServices({ urls: [] }), /No services recorded/);
});

test('the roles table shows the budget and the capabilities', () => {
  const html = renderRoleTable([
    {
      role: 'recon',
      title: 'Reconnaissance',
      stage: 'recon',
      tools: ['katana'],
      permissions: { capabilities: ['crawl'] },
      budget: { max_rounds: 4 },
    },
  ]);
  assert.match(html, /data-role-detail="recon"/);
  assert.match(html, /Reconnaissance/);
  assert.match(html, /katana/);
  assert.match(html, /crawl/);
  assert.match(html, /<td class="num">4<\/td>/);
});

test('the queues table shows the pending and the crashed tasks', () => {
  const html = renderQueues([
    { queue: 'default', online_consumers: 1, pending_tasks: 2, started_tasks: 3, crashed_tasks: 0, oldest_task_age_seconds: 90 },
  ]);
  assert.match(html, /default/);
  assert.match(html, /1m 30s/);
  assert.match(html, /healthy/);
});

test('no queues say so', () => {
  assert.match(renderQueues([]), /No Karton queues are registered/);
});

test('the benchmarks table shows the image and the port', () => {
  const html = renderBenchmarks([
    { name: 'WebGoat', slug: 'webgoat', version: '2023.4', image: 'b-hunters/webgoat', port: '8080', test_cases: [{}, {}], license: 'MIT', available: true },
  ]);
  assert.match(html, /WebGoat/);
  assert.match(html, /b-hunters\/webgoat/);
  assert.match(html, /8080/);
  assert.match(html, /<td class="num">2<\/td>/);
});

test('no benchmarks say so', () => {
  assert.match(renderBenchmarks([]), /No benchmark manifests are loaded/);
});

test('the users table shows the role and the last login', () => {
  const html = renderUsers([
    { username: 'admin', role: 'admin', email: 'admin@demo.test', active: true, last_login_at: 1 },
  ]);
  assert.match(html, /admin/);
  assert.match(html, /admin@demo\.test/);
  assert.match(html, /healthy/);
});

test('the providers table shows the base url and the enabled state', () => {
  const html = renderProviderTable([
    { name: 'local', base_url: 'http://127.0.0.1:8080/v1', model: 'my-model', enabled: true },
  ]);
  assert.match(html, /local/);
  assert.match(html, /http:\/\/127\.0\.0\.1:8080\/v1/);
  assert.match(html, /my-model/);
  assert.match(html, /Check health/);
});

test('no providers say so', () => {
  assert.match(renderProviderTable([]), /No providers configured/);
});

test('the audit table shows the action and the outcome', () => {
  const html = renderAudit([
    { at: 1, action: 'auth.login', actor: 'admin', target_type: 'session', target_id: 's1', outcome: 'success', ip_address: '10.0.0.1' },
  ]);
  assert.match(html, /auth\.login/);
  assert.match(html, /admin/);
  assert.match(html, /session s1/);
  assert.match(html, /healthy/);
  assert.match(html, /10\.0\.0\.1/);
});

test('no audit entries say so', () => {
  assert.match(renderAudit([]), /No audit entries yet/);
});
