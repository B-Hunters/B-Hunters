/* The api wrapper.
 *
 * Security notes:
 *  - The session cookie is HttpOnly; the CSRF token is read from a
 *    readable cookie and echoed in the X-CSRF-Token header.
 *  - A 401 clears the session and hands the page back to the login
 *    card.  The shell installs that handler, so this module never has
 *    to import the shell (the shell imports this module).
 */

import { state } from './state.js';

export const API = '/api/v1';

let unauthorizedHandler = null;

/** Install the handler that runs when the session has expired. */
export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler;
}

/** Read a cookie from the document; null when the cookie is not set. */
export function readCookie(name) {
  // The guard keeps the module importable outside a browser, where the
  // cookie jar does not exist.
  const jar = typeof document === 'undefined' ? '' : document.cookie;
  const match = jar.match(new RegExp('(^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[2]) : null;
}

/**
 * Call the platform API.
 *
 * A JSON body is sent as JSON; ``raw`` returns the response itself for
 * the callers that download a file.  A failed call throws an Error
 * whose message is the server's own explanation.
 */
export async function api(path, { method = 'GET', body = null, raw = false } = {}) {
  const headers = { 'Accept': 'application/json' };
  if (body !== null) headers['Content-Type'] = 'application/json';
  const csrf = readCookie('bh_csrf');
  if (csrf) headers['X-CSRF-Token'] = csrf;

  const response = await fetch(API + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === null ? null : JSON.stringify(body),
  });

  if (response.status === 401) {
    state.user = null;
    if (unauthorizedHandler) unauthorizedHandler();
    throw new Error('Your session has expired. Please sign in again.');
  }
  if (raw) return response;
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = { detail: text }; }
  }
  if (!response.ok) {
    const detail = payload && payload.detail;
    const message = typeof detail === 'string' ? detail
      : (detail && detail.message) ? detail.message
      : `Request failed with HTTP ${response.status}`;
    const error = new Error(message);
    error.payload = payload;
    error.status = response.status;
    throw error;
  }
  return payload;
}
