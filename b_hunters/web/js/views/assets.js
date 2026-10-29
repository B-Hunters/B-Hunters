/* The asset inventory of a scan.
 *
 * The inventory is one collection seen three ways: every URL the
 * platform knows, the JavaScript files among them, and the images.
 * The URL view is the whole inventory with a filter, so the kinds that
 * have no tab of their own — CSS, API endpoints — are still reachable.
 */

import { api } from '../api.js';
import { el } from '../components.js';
import { escape } from '../format.js';

/** The kinds the inventory holds. */
export const ASSET_KINDS = ['page', 'js', 'image', 'css', 'api', 'other'];

/** The label of a kind. */
const KIND_LABELS = {
  page: 'Pages',
  js: 'JS',
  image: 'Images',
  css: 'CSS',
  api: 'API',
  other: 'Other',
};

/**
 * Filter the assets.
 *
 * An empty kind means every kind.  The scope filter keeps the
 * third-party references out when it says `first_party`.
 */
export function filterAssets(assets, { kind = '', scope = '' } = {}) {
  let rows = assets || [];
  if (kind) rows = rows.filter((asset) => asset.kind === kind);
  if (scope) rows = rows.filter((asset) => (asset.scope || 'first_party') === scope);
  return rows;
}

/** The number of assets per kind. */
export function countByKind(assets) {
  const counts = {};
  for (const asset of assets || []) {
    const kind = asset.kind || 'other';
    counts[kind] = (counts[kind] || 0) + 1;
  }
  return counts;
}

/** One row of the table. */
function renderAssetRow(asset) {
  const scope = asset.scope || 'first_party';
  const scopeBadge = scope === 'external'
    ? '<span class="badge bg-secondary">external</span>'
    : '';
  const sources = (asset.sources || []).map((source) => escape(source)).join(', ');
  return `<tr>
    <td class="small"><span class="badge bg-secondary">${escape(asset.kind || 'other')}</span></td>
    <td class="small">${scopeBadge}</td>
    <td class="mono small">${escape(asset.url || '')}</td>
    <td class="num">${asset.status_code ? escape(asset.status_code) : '-'}</td>
    <td class="small">${escape(asset.content_type || '-')}</td>
    <td class="num">${asset.size_bytes ? escape(asset.size_bytes) : '-'}</td>
    <td class="small">${sources || '-'}</td>
    <td class="num">${asset.depth ?? '-'}</td>
    <td class="mono small">${escape(asset.discovered_from || '-')}</td>
  </tr>`;
}

/** The asset table. */
export function renderAssetTable(assets) {
  if (!assets || !assets.length) {
    return '<div class="empty"><div class="big">No assets</div>'
      + 'The inventory is empty: the crawlers found nothing on this target.</div>';
  }
  return `<div class="table-scroll"><table>
    <thead><tr>
      <th>Kind</th><th>Scope</th><th>URL</th><th>Status</th><th>Type</th>
      <th>Size</th><th>Sources</th><th>Depth</th><th>Found on</th>
    </tr></thead>
    <tbody>${assets.map(renderAssetRow).join('')}</tbody>
  </table></div>`;
}

/** The filter bar above the table. */
export function renderAssetFilters(counts, { kind = '', scope = '' } = {}) {
  const kinds = ASSET_KINDS.filter((name) => counts[name]);
  const options = ['<option value="">All kinds</option>']
    .concat(kinds.map((name) => {
      const selected = name === kind ? ' selected' : '';
      return `<option value="${name}"${selected}>${KIND_LABELS[name] || name} (${counts[name]})</option>`;
    }))
    .join('');
  const scopes = [
    `<option value=""${scope === '' ? ' selected' : ''}>First and third party</option>`,
    `<option value="first_party"${scope === 'first_party' ? ' selected' : ''}>First party only</option>`,
    `<option value="external"${scope === 'external' ? ' selected' : ''}>Third party only</option>`,
  ].join('');
  return `<div class="row" style="margin-bottom:10px">
    <select id="asset-kind" class="input small">${options}</select>
    <select id="asset-scope" class="input small">${scopes}</select>
    <span class="desc">${Object.values(counts).reduce((a, b) => a + b, 0)} asset(s)</span>
  </div>`;
}

/**
 * Render one of the three asset tabs.
 *
 * The tab is `urls`, `js` or `images`; the view fetches the whole
 * inventory once and filters it in the browser, so switching between
 * the tabs does not fetch again.
 */
export async function renderAssetsTab(tab, scanId) {
  const body = el('scan-tab-body');
  const kind = tab === 'js' ? 'js' : (tab === 'images' ? 'image' : '');
  const scope = tab === 'js' ? 'first_party' : '';

  let assets = [];
  let counts = {};
  try {
    const data = await api(`/scans/${scanId}/assets?limit=2000`);
    assets = data.items || [];
    counts = data.counts || countByKind(assets);
  } catch (error) {
    body.innerHTML = `<div class="empty"><div class="big">The inventory is not available</div>${escape(error.message)}</div>`;
    return;
  }

  const rows = filterAssets(assets, { kind, scope });
  body.innerHTML = `<div class="card">
    <div class="card-head"><h2>${KIND_LABELS[tab] || 'Assets'}</h2>
      <span class="desc">${rows.length} shown of ${assets.length}</span></div>
    <div class="card-body tight">
      ${renderAssetFilters(counts, { kind, scope })}
      ${renderAssetTable(rows)}
    </div>
  </div>`;

  const kindSelect = el('asset-kind');
  const scopeSelect = el('asset-scope');
  const apply = () => {
    const nextKind = kindSelect ? kindSelect.value : kind;
    const nextScope = scopeSelect ? scopeSelect.value : scope;
    const filtered = filterAssets(assets, { kind: nextKind, scope: nextScope });
    const table = body.querySelector('.table-scroll');
    if (table) table.outerHTML = renderAssetTable(filtered);
  };
  if (kindSelect) kindSelect.addEventListener('change', apply);
  if (scopeSelect) scopeSelect.addEventListener('change', apply);
}
