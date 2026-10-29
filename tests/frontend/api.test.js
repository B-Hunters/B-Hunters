/* The api wrapper: the CSRF header, the errors and the expired session. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { api, readCookie, setUnauthorizedHandler } from '../../b_hunters/web/js/api.js';
import { state } from '../../b_hunters/web/js/state.js';

function stubFetch(response) {
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return response;
  };
  return calls;
}

test('readCookie finds a cookie and decodes it', () => {
  globalThis.document = { cookie: 'bh_csrf=abc%20def; other=1' };
  assert.equal(readCookie('bh_csrf'), 'abc def');
  assert.equal(readCookie('other'), '1');
});

test('readCookie returns null for a cookie that is not set', () => {
  globalThis.document = { cookie: 'other=1' };
  assert.equal(readCookie('bh_csrf'), null);
});

test('readCookie does not match a cookie whose name ends with the one asked for', () => {
  globalThis.document = { cookie: 'x_bh_csrf=abc' };
  assert.equal(readCookie('bh_csrf'), null);
});

test('readCookie survives a page without a cookie jar', () => {
  delete globalThis.document;
  assert.equal(readCookie('bh_csrf'), null);
});

test('a call sends the csrf token of the cookie', async () => {
  globalThis.document = { cookie: 'bh_csrf=tok' };
  const calls = stubFetch({ ok: true, status: 200, text: async () => '{"ok":true}' });
  const payload = await api('/dashboard');
  assert.deepEqual(payload, { ok: true });
  assert.equal(calls[0].url, '/api/v1/dashboard');
  assert.equal(calls[0].options.headers['X-CSRF-Token'], 'tok');
  assert.equal(calls[0].options.credentials, 'same-origin');
});

test('without a cookie jar no csrf token is sent', async () => {
  delete globalThis.document;
  const calls = stubFetch({ ok: true, status: 200, text: async () => '' });
  await api('/scans');
  assert.equal(calls[0].options.headers['X-CSRF-Token'], undefined);
});

test('a call without a body sends no content type', async () => {
  const calls = stubFetch({ ok: true, status: 200, text: async () => '' });
  await api('/scans');
  assert.equal(calls[0].options.headers['Content-Type'], undefined);
  assert.equal(calls[0].options.body, null);
  assert.equal(calls[0].options.method, 'GET');
});

test('a call with a body sends json', async () => {
  const calls = stubFetch({ ok: true, status: 200, text: async () => '' });
  await api('/scans', { method: 'POST', body: { name: 'x' } });
  assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
  assert.equal(calls[0].options.body, '{"name":"x"}');
  assert.equal(calls[0].options.method, 'POST');
});

test('a raw call returns the response itself', async () => {
  const response = { ok: true, status: 200, text: async () => 'x' };
  stubFetch(response);
  assert.equal(await api('/scans/s1/report', { raw: true }), response);
});

test('a failed call throws the message of the server', async () => {
  stubFetch({ ok: false, status: 422, text: async () => '{"detail":"the scope is empty"}' });
  await assert.rejects(api('/scans'), (error) => {
    assert.equal(error.message, 'the scope is empty');
    assert.equal(error.status, 422);
    assert.deepEqual(error.payload, { detail: 'the scope is empty' });
    return true;
  });
});

test('a failed call without a detail names the status', async () => {
  stubFetch({ ok: false, status: 500, text: async () => '' });
  await assert.rejects(api('/scans'), (error) => {
    assert.equal(error.message, 'Request failed with HTTP 500');
    return true;
  });
});

test('a body that is not json becomes the detail of the error', async () => {
  stubFetch({ ok: false, status: 502, text: async () => 'bad gateway' });
  await assert.rejects(api('/scans'), (error) => {
    assert.equal(error.message, 'bad gateway');
    return true;
  });
});

test('an expired session clears the user and hands back the login card', async () => {
  stubFetch({ ok: false, status: 401, text: async () => '' });
  let called = 0;
  setUnauthorizedHandler(() => { called += 1; });
  state.user = { username: 'a' };
  await assert.rejects(api('/auth/me'), (error) => {
    assert.equal(error.message, 'Your session has expired. Please sign in again.');
    return true;
  });
  assert.equal(called, 1);
  assert.equal(state.user, null);
});
