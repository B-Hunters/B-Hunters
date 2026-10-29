/* The entry point of the frontend test suite.
 *
 * `node --test tests/frontend/` must work on every Node the project
 * supports.  Node 24 treats a directory argument as a file to run, so
 * this file makes that command load the suite; the imports below are
 * the tests of this directory.
 */
import './api.test.js';
import './components.test.js';
import './escaping.test.js';
import './format.test.js';
import './main.test.js';
import './router.test.js';
import './scan-these-urls.test.js';
import './views.test.js';
