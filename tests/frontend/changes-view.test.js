/* The changes tab: what a diff shows and what it refuses to show. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { renderDiff, renderDiffGroup } from '../../b_hunters/web/js/views/changes.js';

test('the diff shows the four groups', () => {
  const html = renderDiff({
    comparable: true,
    counts: { new: 1, not_observed: 2, reopened: 0, persistent: 3 },
    new: [{ severity: 'high', vuln_class: 'xss', title: 'Reflected XSS', first_seen_at: 'now' }],
    not_observed: [{ severity: 'low', vuln_class: 'open_redirect', title: 'Old redirect' }],
    reopened: [],
    persistent: [{ severity: 'medium', vuln_class: 'ssrf', title: 'Still there', triage_status: 'open' }],
  });
  assert.match(html, /Reflected XSS/);
  assert.match(html, /Old redirect/);
  assert.match(html, /Still there/);
  assert.match(html, /1 new/);
});

test('scans that are not comparable say why', () => {
  const html = renderDiff({ comparable: false, reason: 'the two scans did not ask the same question' });
  assert.match(html, /not comparable/);
  assert.match(html, /did not ask the same question/);
});

test('a group with nothing in it says none', () => {
  const html = renderDiffGroup('Reopened', [], () => '');
  assert.match(html, /none/);
});
