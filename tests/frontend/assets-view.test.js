/* The asset inventory view and the participation table. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { countByKind, filterAssets, renderAssetTable, renderAssetFilters } from '../../b_hunters/web/js/views/assets.js';
import { renderParticipation, renderRoleTable, renderTranscript } from '../../b_hunters/web/js/views/participation.js';

const ASSETS = [
  { kind: 'page', scope: 'first_party', url: 'https://demo.test/', status_code: 200, content_type: 'text/html', size_bytes: 1200, sources: ['asset_crawl'], depth: 0, discovered_from: '' },
  { kind: 'js', scope: 'first_party', url: 'https://demo.test/app.js', status_code: 200, content_type: 'application/javascript', size_bytes: 900, sources: ['asset_crawl', 'B-Hunters-Katana'], depth: 1, discovered_from: 'https://demo.test/' },
  { kind: 'js', scope: 'external', url: 'https://cdn.example.com/jquery.js', status_code: 0, content_type: '', size_bytes: 0, sources: ['asset_crawl'], depth: 1, discovered_from: 'https://demo.test/' },
  { kind: 'image', scope: 'first_party', url: 'https://demo.test/logo.png', status_code: 200, content_type: 'image/png', size_bytes: 4096, sources: ['asset_crawl'], depth: 1, discovered_from: 'https://demo.test/' },
];

test('the javascript view keeps only the javascript assets', () => {
  assert.equal(filterAssets(ASSETS, { kind: 'js' }).length, 2);
  assert.equal(filterAssets(ASSETS, { kind: 'image' }).length, 1);
  assert.equal(filterAssets(ASSETS, {}).length, 4);
});

test('the first-party filter drops the third-party references', () => {
  const firstParty = filterAssets(ASSETS, { scope: 'first_party' });
  assert.equal(firstParty.length, 3);
  assert.ok(!firstParty.some((asset) => asset.url.includes('cdn.example.com')));
});

test('the assets are counted by kind', () => {
  const counts = countByKind(ASSETS);
  assert.equal(counts.js, 2);
  assert.equal(counts.page, 1);
  assert.equal(counts.image, 1);
});

test('the table shows every column', () => {
  const html = renderAssetTable(ASSETS);
  assert.match(html, /app\.js/);
  assert.match(html, /application\/javascript/);
  assert.match(html, /B-Hunters-Katana/);
  assert.match(html, /external/);
});

test('an empty inventory says so', () => {
  assert.match(renderAssetTable([]), /No assets/);
});

test('a hostile url cannot inject markup', () => {
  const html = renderAssetTable([{ kind: 'page', url: '<img src=x onerror=alert(1)>', status_code: 200 }]);
  assert.ok(!html.includes('<img src=x'));
  assert.match(html, /&lt;img/);
});

test('the filters list the kinds that are present', () => {
  const html = renderAssetFilters(countByKind(ASSETS), { kind: 'js' });
  assert.match(html, /JS \(2\)/);
  assert.match(html, /Images \(1\)/);
  assert.match(html, /value="js" selected/);
});

test('the participation table names the reason a tool did not report', () => {
  const html = renderParticipation({
    workers: [{ worker: 'B-Hunters-Nuclei', reason: 'never dispatched', tasks: 0, findings: 0 }],
    native_adapters: [{ name: 'asset_crawl', status: 'succeeded', items: 12 }],
    coverage: { workers: { total: 17, participated: 14 }, native_adapters: { total: 7, participated: 7 } },
  });
  assert.match(html, /never dispatched/);
  assert.match(html, /B-Hunters-Nuclei/);
  assert.match(html, /asset_crawl/);
  assert.match(html, /14 of 17 workers took part/);
});

test('the role table shows the stop reason', () => {
  const html = renderRoleTable([
    { role: 'recon', status: 'wall_clock', stop_reason: 'wall_clock', rounds: 12, tool_calls: 30, tokens: 90000, findings_raised: 2, findings_confirmed: 1, conclusion: 'looked around' },
  ]);
  assert.match(html, /wall_clock/);
  assert.match(html, /looked around/);
  assert.match(html, /data-transcript="recon"/);
});

test('the transcript shows the messages and the tool calls', () => {
  const html = renderTranscript(
    [{ kind: 'observation', target: 'list_assets', hypothesis: 'looked at the assets', observations: ['list_assets -> ok'] }],
    [{ tool: 'http_request', status: 'ok', duration_ms: 12, output_summary: 'HTTP 200' }],
  );
  assert.match(html, /looked at the assets/);
  assert.match(html, /http_request/);
  assert.match(html, /HTTP 200/);
});
