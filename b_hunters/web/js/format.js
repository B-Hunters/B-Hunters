/* The pure formatting helpers.
 *
 * Everything here is a function of its arguments: no DOM, no clock, no
 * network.  That is what makes the console testable under node --test.
 *
 * Security note: escape() is the boundary between the server's data and
 * the page.  The console renders target-derived content (host names,
 * page titles, tool output) and every one of those values goes through
 * escape() before it reaches innerHTML.
 */

/**
 * Escape a value for insertion into markup.
 *
 * Both the text and the attribute context use the same five entities,
 * so a value that is quoted back into an attribute cannot break out of
 * it either.
 */
export function escape(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Format a timestamp for the tables.
 *
 * A number is read as a unix time in seconds (what the API sends); a
 * string is read as a date.  An absent or unparsable value shows as a
 * dash, never as "Invalid Date".
 */
export function fmtTime(value) {
  if (!value) return '-';
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

/** Format a number of seconds as a short duration. */
export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return '-';
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) return `${total}s`;
  if (total < 3600) return `${Math.floor(total / 60)}m ${total % 60}s`;
  return `${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}m`;
}

/** A coloured pill for a status, a severity or a state. */
export function badge(value) {
  const text = escape(value || 'unknown');
  return `<span class="badge ${escape(String(value || 'unknown').toLowerCase())}">${text}</span>`;
}

/** The badge for a finding severity; kept apart so the intent reads. */
export function severityBadge(value) {
  return badge(value);
}

/** Split a textarea into the non-empty lines it holds. */
export function splitLines(text) {
  return String(text || '').split('\n').map((line) => line.trim()).filter(Boolean);
}
