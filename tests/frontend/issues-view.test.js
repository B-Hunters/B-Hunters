/* The issues view: the durable findings, their triage state and their
 * comments.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { renderIssues, triageBadge } from '../../b_hunters/web/js/views/issues.js';

test('the issue table names the issue', () => {
  const html = renderIssues([
    {
      issue_id: 'i1',
      severity: 'high',
      title: 'Reflected XSS in the search',
      vuln_class: 'xss',
      triage_status: 'open',
      assignee: 'me',
      tags: ['web'],
    },
  ]);
  assert.match(html, /Reflected XSS in the search/);
  assert.match(html, /xss/);
  assert.match(html, /open/);
  assert.match(html, /me/);
  assert.match(html, /web/);
});

test('no issue says so', () => {
  const html = renderIssues([]);
  assert.match(html, /No issue/);
});

test('the state of an issue is shown as a badge', () => {
  assert.match(triageBadge('open'), /open/);
  assert.match(triageBadge('fixed'), /fixed/);
});

test('a title that carries markup is escaped', () => {
  const html = renderIssues([
    { issue_id: 'i1', severity: 'high', title: '<script>alert(1)</script>', vuln_class: 'xss' },
  ]);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.match(html, /&lt;script&gt;/);
});
