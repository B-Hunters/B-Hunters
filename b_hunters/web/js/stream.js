/* The live event stream of a running scan.
 *
 * The server replays from Last-Event-ID, so a dropped connection costs
 * nothing: EventSource reconnects on its own and the browser sends the
 * last id it saw.
 */

import { API } from './api.js';
import { el } from './components.js';
import { escape, fmtTime } from './format.js';
import { state } from './state.js';

/** Close the stream and hide the live indicator. */
export function closeStream() {
  if (state.stream) {
    state.stream.close();
    state.stream = null;
  }
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  const indicator = el('live-indicator');
  if (indicator) indicator.style.display = 'none';
}

/** Open the event stream of a scan. */
export function startStream(scanId) {
  closeStream();
  const indicator = el('live-indicator');
  indicator.style.display = '';
  el('live-dot').className = 'conn-dot';

  const source = new EventSource(`${API}/scans/${scanId}/stream?last_event_id=${state.lastSeq}`);
  state.stream = source;

  const setStreamState = (text, kind) => {
    el('live-dot').className = 'conn-dot' + (kind ? ' ' + kind : '');
    el('live-text').textContent = text;
    const streamState = el('stream-state');
    if (streamState) streamState.textContent = text;
  };

  source.onopen = () => {
    setStreamState('live', 'live');
  };
  source.onerror = () => {
    // EventSource reconnects on its own; the server replays from
    // Last-Event-ID so no events are lost.
    setStreamState('reconnecting…', 'down');
  };
  source.onmessage = (event) => handleEvent(event);
  ['scan.started', 'scan.completed', 'scan.failed', 'scan.cancelled', 'agent.completed',
    'agent.message', 'scanner.completed', 'scanner.error', 'task.blocked', 'collaboration.summary',
    'scan.paused', 'scan.resumed', 'scan.stop_requested'].forEach((kind) => {
    source.addEventListener(kind, handleEvent);
  });
}

/** Append one event to the log of the live tab. */
export function handleEvent(event) {
  let payload = {};
  try { payload = JSON.parse(event.data); } catch { return; }
  state.lastSeq = Math.max(state.lastSeq, Number(payload.seq || 0));

  const log = el('event-log');
  if (!log) return;
  const line = document.createElement('div');
  const kind = String(payload.kind || 'message');
  line.className = 'log-line' + (kind.includes('error') || kind.includes('failed') ? ' error' : '');
  line.innerHTML = `<span class="ts">${escape(fmtTime(payload.at))}</span>` +
    `<span class="kind">${escape(kind)}</span>` +
    `<span>${escape(JSON.stringify(payload.payload || {}).slice(0, 600))}</span>`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}
