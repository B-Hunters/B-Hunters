/* The entry point of the console.
 *
 * The page is a shell: the login card, the sidebar and the view
 * container live in index.html and this module wires them together.
 * The views are imported here and registered as routes; every view
 * module is import-safe, so importing it runs no DOM code.
 */

import { api, setUnauthorizedHandler } from './api.js';
import { el, toast } from './components.js';
import { navigate, registerRoute, resolveRoute } from './router.js';
import { state } from './state.js';
import { closeStream } from './stream.js';
import { agentsView } from './views/agents.js';
import { agentDefinitionsView, auditView, providersView, usersView } from './views/admin.js';
import { benchmarksView } from './views/benchmarks.js';
import { dashboardView } from './views/dashboard.js';
import { findingsView } from './views/findings.js';
import { kartonView } from './views/karton.js';
import { newScanView } from './views/new-scan.js';
import { scanDetailView } from './views/scan-detail.js';
import { scansView } from './views/scans.js';
import { issuesView } from './views/issues.js';

/* --------------------------------------------------------------- routes */
registerRoute('dashboard', dashboardView);
registerRoute('scans', scansView);
registerRoute('new-scan', newScanView);
registerRoute('scans/:id', scanDetailView);
registerRoute('findings', findingsView);
registerRoute('issues', issuesView);
registerRoute('agents', agentsView);
registerRoute('karton', kartonView);
registerRoute('benchmarks', benchmarksView);
registerRoute('users', usersView);
registerRoute('providers', providersView);
registerRoute('agent-defs', agentDefinitionsView);
registerRoute('audit', auditView);

/* ---------------------------------------------------------------- shell */
function showLogin() {
  el('login-shell').classList.remove('hidden');
  el('app-shell').classList.remove('active');
  el('login-shell').style.display = 'grid';
  closeStream();
}

function showApp() {
  el('login-shell').style.display = 'none';
  el('app-shell').classList.add('active');
}

// The api wrapper cannot import the shell, so the shell tells it what
// to do when the session has expired.
setUnauthorizedHandler(() => {
  showLogin();
});

window.addEventListener('hashchange', () => {
  const resolved = resolveRoute(location.hash);
  if (resolved) navigate(resolved.name, resolved.params, { updateHash: false });
  else navigate('dashboard', {}, { updateHash: false });
});

el('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = el('login-submit');
  const errorBox = el('login-error');
  errorBox.classList.add('hidden');
  button.disabled = true;
  button.textContent = 'Signing in…';
  try {
    const result = await api('/auth/login', {
      method: 'POST',
      body: {
        username: el('login-username').value,
        password: el('login-password').value,
      },
    });
    state.user = result;
    state.csrf = result.csrf_token;
    el('login-password').value = '';
    await enterApp();
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove('hidden');
  } finally {
    button.disabled = false;
    button.textContent = 'Sign in';
  }
});

el('logout-btn').addEventListener('click', async () => {
  try { await api('/auth/logout', { method: 'POST' }); } catch { /* already gone */ }
  state.user = null;
  showLogin();
  toast('Signed out.', 'info');
});

el('refresh-btn').addEventListener('click', () => navigate(state.route, state.params));

document.querySelectorAll('.nav-link').forEach((link) => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    navigate(link.dataset.route);
  });
});

/* ------------------------------------------------------------- entering */
async function enterApp() {
  showApp();
  const me = await api('/auth/me');
  state.user = me;
  el('user-name').textContent = me.username;
  el('user-role').textContent = me.role;
  el('user-avatar').textContent = (me.username || '?').slice(0, 2).toUpperCase();
  el('admin-nav').style.display = me.role === 'admin' ? '' : 'none';
  const resolved = resolveRoute(location.hash);
  if (resolved) navigate(resolved.name, resolved.params, { updateHash: false });
  else navigate('dashboard', {}, { updateHash: false });
}

/* ------------------------------------------------------------- startup */
(async function start() {
  try {
    await api('/auth/me');
    await enterApp();
  } catch {
    showLogin();
  }
})();
