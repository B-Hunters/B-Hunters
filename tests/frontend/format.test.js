/* The pure helpers of the console: escaping, formatting and splitting. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  badge,
  escape,
  fmtDuration,
  fmtTime,
  severityBadge,
  splitLines,
} from '../../b_hunters/web/js/format.js';

test('escape turns the markup characters into entities', () => {
  assert.equal(escape('<script>alert("x")</script>'), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
  assert.equal(escape("it's"), 'it&#39;s');
  assert.equal(escape('a & b'), 'a &amp; b');
});

test('escape renders nothing for an absent value', () => {
  assert.equal(escape(null), '');
  assert.equal(escape(undefined), '');
});

test('escape keeps a zero and a false', () => {
  assert.equal(escape(0), '0');
  assert.equal(escape(false), 'false');
});

test('fmtTime shows a dash for a missing or unusable value', () => {
  assert.equal(fmtTime(null), '-');
  assert.equal(fmtTime(undefined), '-');
  assert.equal(fmtTime(''), '-');
  assert.equal(fmtTime(0), '-');
  assert.equal(fmtTime('not a date'), '-');
});

test('fmtTime formats a unix time and an iso date', () => {
  assert.notEqual(fmtTime(1700000000), '-');
  assert.notEqual(fmtTime('2026-10-29T10:11:12Z'), '-');
});

test('fmtDuration counts seconds, minutes and hours', () => {
  assert.equal(fmtDuration(0), '0s');
  assert.equal(fmtDuration(45), '45s');
  assert.equal(fmtDuration(60), '1m 0s');
  assert.equal(fmtDuration(90), '1m 30s');
  assert.equal(fmtDuration(3600), '1h 0m');
  assert.equal(fmtDuration(3700), '1h 1m');
});

test('fmtDuration shows a dash for an absent value', () => {
  assert.equal(fmtDuration(null), '-');
  assert.equal(fmtDuration(undefined), '-');
});

test('a negative duration counts as zero', () => {
  assert.equal(fmtDuration(-5), '0s');
});

test('a badge shows the value and names its class after it', () => {
  assert.equal(badge('critical'), '<span class="badge critical">critical</span>');
  assert.equal(badge('Healthy'), '<span class="badge healthy">Healthy</span>');
});

test('a badge without a value says unknown', () => {
  assert.equal(badge(''), '<span class="badge unknown">unknown</span>');
  assert.equal(badge(null), '<span class="badge unknown">unknown</span>');
});

test('a badge escapes the value it shows', () => {
  assert.equal(badge('<img>'), '<span class="badge &lt;img&gt;">&lt;img&gt;</span>');
});

test('severityBadge is the badge of a severity', () => {
  assert.equal(severityBadge('high'), badge('high'));
});

test('splitLines keeps the non-empty trimmed lines', () => {
  assert.deepEqual(splitLines(' a \n\n b\n'), ['a', 'b']);
  assert.deepEqual(splitLines(''), []);
  assert.deepEqual(splitLines(null), []);
});
