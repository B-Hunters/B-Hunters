/* The console's entry point: the shell and the routes.
 *
 * The shell reads the page as it loads, so the page is stubbed here.
 * The check is that every view of the console is still registered: a
 * view that is dropped in a refactor is a view nobody sees.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

const ROUTES = [
  'dashboard',
  'scans',
  'new-scan',
  'scans/:id',
  'findings',
  'agents',
  'karton',
  'benchmarks',
  'users',
  'providers',
  'agent-defs',
  'audit',
];

function element() {
  return {
    value: '',
    textContent: '',
    innerHTML: '',
    disabled: false,
    checked: false,
    style: {},
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener() {},
    appendChild() {},
    querySelectorAll: () => [],
    remove() {},
  };
}

function stubPage() {
  const listeners = {};
  globalThis.document = {
    cookie: '',
    getElementById: () => element(),
    querySelectorAll: () => [],
    createElement: () => element(),
  };
  globalThis.window = {
    addEventListener: (kind, handler) => { listeners[kind] = handler; },
    open: () => {},
  };
  globalThis.location = { hash: '' };
  globalThis.history = { pushState: () => {} };
  globalThis.fetch = async () => ({ ok: false, status: 401, text: async () => '' });
  return listeners;
}

test('the console registers every view and wires the shell', async () => {
  const listeners = stubPage();
  const { routes } = await import('../../b_hunters/web/js/router.js');
  await import('../../b_hunters/web/js/main.js');

  for (const name of ROUTES) {
    assert.equal(typeof routes[name], 'function', `the ${name} route is not registered`);
  }
  assert.equal(typeof listeners.hashchange, 'function');
});
