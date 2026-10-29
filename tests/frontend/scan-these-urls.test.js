/* The "scan these URLs" action.
 *
 * It creates a follow-up scan from the URLs the crawlers found.  The
 * body it sends must be the scan itself, not a string of the scan: the
 * api wrapper serialises the body itself, and a body that was
 * serialised twice reaches the API as a JSON string where it expects an
 * object.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scanTheseUrls } from '../../b_hunters/web/js/views/scan-detail.js';

function stubFetch(response) {
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return response;
  };
  return calls;
}

test('the follow-up scan is sent as an object, not as a string of one', async () => {
  const calls = stubFetch({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ scan_id: 'scan-1' }),
  });
  globalThis.location = { hash: '' };

  await scanTheseUrls({ items: [{ kind: 'url', value: 'https://demo.test/app.js' }] });

  assert.equal(calls.length, 1);
  const sent = JSON.parse(calls[0].options.body);
  assert.equal(typeof sent, 'object');
  assert.equal(sent.targets.authorized_hosts[0], 'demo.test');
  assert.deepEqual(sent.targets.urls, ['https://demo.test/app.js']);
});

test('nothing is sent when the crawlers found no URL', async () => {
  const calls = stubFetch({ ok: true, status: 200, text: async () => '{}' });
  globalThis.location = { hash: '' };

  await scanTheseUrls({ items: [{ kind: 'path', value: '/admin' }] });

  assert.equal(calls.length, 0);
});
