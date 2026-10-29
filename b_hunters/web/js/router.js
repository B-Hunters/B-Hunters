/* The hash router.
 *
 * The hash has the form ``#/<name>`` or ``#/<name>/<id>``.  A route that
 * takes an identifier is registered as ``"<name>/:id"``; the resolution
 * picks the parameterised route when an identifier is present and falls
 * back to the list route otherwise.
 */

import { el } from './components.js';
import { escape } from './format.js';
import { state } from './state.js';
import { closeStream } from './stream.js';

/** The registered routes, by name. */
export const routes = {};

/** Register the handler for a route. */
export function registerRoute(name, handler) {
  routes[name] = handler;
}

/**
 * Resolve a hash fragment to a route.
 *
 * The table is a parameter so that the resolution can be checked
 * without registering anything; the console's own table is the default.
 */
export function resolveRoute(raw, table = routes) {
  const parts = String(raw || '').replace(/^#\/?/, '').split('/').filter(Boolean);
  if (!parts.length) return null;
  const name = parts[0];
  const id = parts.length > 1 ? parts[1] : '';
  if (id && table[`${name}/:id`]) return { name: `${name}/:id`, params: { id } };
  if (table[name]) return { name, params: id ? { id } : {} };
  return null;
}

/** The hash a route and an identifier stand for. */
export function routeHash(base, id = '') {
  return '#/' + base + (id ? '/' + id : '');
}

/**
 * Show a route.
 *
 * The route may be registered as "<name>/:id"; the identifier travels
 * in ``params.id`` and is appended to the hash separately.
 */
export async function navigate(route, params = {}, { updateHash = true } = {}) {
  const base = String(route).split('/:')[0];
  const id = params.id || '';
  const target = route;

  state.route = target;
  state.params = { ...params, id };
  closeStream();
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.classList.toggle('active', link.dataset.route === base);
  });

  if (updateHash) {
    const wanted = routeHash(base, id);
    if (location.hash !== wanted) {
      // Update the hash without re-entering the handler.
      history.pushState(null, '', wanted);
    }
  }

  const view = el('view');
  view.innerHTML = '<div class="row" style="padding:40px"><span class="spinner"></span><span class="muted">Loading…</span></div>';
  try {
    await routes[target]({ ...params, id });
  } catch (error) {
    view.innerHTML = `<div class="alert error">${escape(error.message)}</div>`;
  }
}
