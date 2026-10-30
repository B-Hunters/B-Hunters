/* The findings view and its detector filter. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { detectorOptions } from '../../b_hunters/web/js/views/findings.js';

const FINDINGS = [
  { detected_by: ['Nuclei'], detection_source: 'Nuclei', severity: 'high' },
  { detected_by: ['access_control'], detection_source: 'access_control', severity: 'medium' },
  { detected_by: ['Nuclei', 'Wapiti'], detection_source: 'Wapiti', severity: 'low' },
  { detected_by: [], detection_source: '', severity: 'info' },
];

test('every detector that raised a finding is offered', () => {
  const options = detectorOptions(FINDINGS);
  assert.ok(options.includes('Nuclei'));
  assert.ok(options.includes('access_control'));
  assert.ok(options.includes('Wapiti'));
});

test('the detectors are offered once each, in order', () => {
  const options = detectorOptions(FINDINGS);
  assert.equal(new Set(options).size, options.length);
  assert.deepEqual(options, [...options].sort());
});

test('a finding with no detector adds nothing', () => {
  assert.deepEqual(detectorOptions([{ detected_by: [], detection_source: '' }]), []);
});
