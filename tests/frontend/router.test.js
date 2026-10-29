/* The hash router: how a fragment becomes a route. */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  navigate,
  registerRoute,
  resolveRoute,
  routeHash,
  routes,
} from '../../b_hunters/web/js/router.js';
import { state } from '../../b_hunters/web/js/state.js';

const table = {
  dashboard: () => {},
  scans: () => {},
  'scans/:id': () => {},
};

test('a hash without an identifier resolves to the list route', () => {
  assert.deepEqual(resolveRoute('#/scans', table), { name: 'scans', params: {} });
});

test('a hash with an identifier resolves to the parameterised route', () => {
  assert.deepEqual(resolveRoute('#/scans/s1', table), { name: 'scans/:id', params: { id: 's1' } });
});

test('an unknown route resolves to nothing', () => {
  assert.equal(resolveRoute('#/nope', table), null);
  assert.equal(resolveRoute('', table), null);
  assert.equal(resolveRoute('#/', table), null);
});

test('an identifier without a parameterised route falls back to the list route', () => {
  assert.deepEqual(resolveRoute('#/scans/s1', { scans: () => {} }), { name: 'scans', params: { id: 's1' } });
});

test('the fragment may be written with or without the leading slash', () => {
  assert.deepEqual(resolveRoute('#scans/s1', table), { name: 'scans/:id', params: { id: 's1' } });
  assert.deepEqual(resolveRoute('scans/s1', table), { name: 'scans/:id', params: { id: 's1' } });
});

test('a registered route is found by its name', () => {
  registerRoute('test-route', () => {});
  assert.equal(typeof routes['test-route'], 'function');
  assert.deepEqual(resolveRoute('#/test-route'), { name: 'test-route', params: {} });
});

test('the hash of a route carries the identifier', () => {
  assert.equal(routeHash('scans'), '#/scans');
  assert.equal(routeHash('scans', 's1'), '#/scans/s1');
});

/* The few pieces of the page the router touches. */
function stubPage() {
  const view = { innerHTML: '' };
  const links = [];
  globalThis.document = {
    cookie: '',
    getElementById: (id) => (id === 'view' ? view : null),
    querySelectorAll: () => links,
    createElement: () => ({ className: '', textContent: '', remove() {} }),
  };
  globalThis.location = { hash: '' };
  globalThis.history = {
    pushState: (_state, _title, url) => { globalThis.location.hash = url; },
  };
  return { view, links };
}

test('navigate runs the handler of the route with the identifier', async () => {
  const { view } = stubPage();
  let called = null;
  registerRoute('test-navigate', (params) => { called = params; });
  await navigate('test-navigate', { id: 's1' });
  assert.deepEqual(called, { id: 's1' });
  assert.match(view.innerHTML, /Loading/);
  assert.equal(state.route, 'test-navigate');
  assert.deepEqual(state.params, { id: 's1' });
});

test('navigate writes the route into the hash', async () => {
  stubPage();
  registerRoute('test-hash', () => {});
  await navigate('test-hash');
  assert.equal(globalThis.location.hash, '#/test-hash');
});

test('navigate marks the link of the route as active', async () => {
  const { links } = stubPage();
  const link = { dataset: { route: 'test-active' }, classList: { toggle: (_name, on) => { link.active = on; } } };
  links.push(link);
  registerRoute('test-active', () => {});
  await navigate('test-active');
  assert.equal(link.active, true);
});

test('a route that fails shows its message in the page', async () => {
  const { view } = stubPage();
  registerRoute('test-fails', () => { throw new Error('the scan is gone'); });
  await navigate('test-fails');
  assert.match(view.innerHTML, /the scan is gone/);
});
