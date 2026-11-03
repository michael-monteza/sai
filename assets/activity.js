'use strict';
/* Detected-usage drill-down: which workstations used a service, and the consolidated event log behind the numbers. */

const DAY_OPTS = [['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days'], ['365', 'Last 12 months'], ['all', 'All time']];
const daySelect = (id, cur) => `<select id="${id}" class="form-select form-select-sm w-auto" aria-label="Period">${DAY_OPTS.map(([v, l]) => `<option value="${v}" ${String(cur) === v ? 'selected' : ''}>${l}</option>`).join('')}</select>`;

/** Workstations a service was detected on. opts: { onEvents(computer), onOpen(row) } */
async function serviceWorkstationsPanel(host, serviceId, opts = {}) {
  const days = opts.days || '30';
  host.innerHTML = '<div class="text-secondary small p-3">Loading&hellip;</div>';
  const { workstations: rows } = await api('GET', `services/${serviceId}/workstations?days=${days}`);
  host.innerHTML = `<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2"><div class="small text-secondary"><b class="text-white">${rows.length}</b> workstation${rows.length === 1 ? '' : 's'} with detected activity. Select a computer to see its events.</div>${daySelect('wsDays', days)}</div><div id="wsPanelGrid" class="border rounded"></div>`;
  $('#wsDays', host).onchange = e => serviceWorkstationsPanel(host, serviceId, { ...opts, days: e.target.value }).catch(() => {});
  new DataGrid({ el: $('#wsPanelGrid', host), id: 'svc-workstations', rows, rowKey: 'computer_name', exportName: 'service-workstations', pageSize: 10, sort: { key: 'events', dir: 'desc' },
    empty: 'No workstation has used this service in the selected period.', onRowClick: r => opts.onEvents && opts.onEvents(r.computer_name),
    columns: [
      { key: 'computer_name', label: 'Computer', filter: 'text', render: r => `<span class="fw-semibold text-white">${E(r.computer_name)}</span>` },
      { key: 'department', label: 'Department', filter: 'select', text: r => r.department || 'Unmapped', render: r => E(r.department) || '<span class="text-secondary">unmapped</span>' },
      { key: 'events', label: 'DNS events', num: true, render: r => fmtN(r.events) },
      { key: 'connections', label: 'Connections', num: true, render: r => fmtN(r.connections) },
      { key: 'domains', label: 'Hosts', num: true },
      { key: 'active_days', label: 'Active days', num: true },
      { key: 'first_seen', label: 'First seen', nowrap: true, render: r => `<span class="small">${fmtDT(r.first_seen)}</span>` },
      { key: 'last_seen', label: 'Last seen', nowrap: true, render: r => `<span class="small">${fmtDT(r.last_seen)}</span>` },
      { key: 'last_domain', label: 'Latest host', render: r => `<span class="mono small">${E(r.last_domain || '')}</span>` }],
    actions: () => [{ inline: true, key: 'events', label: 'View events', icon: 'fa-list' }, { inline: true, key: 'open', label: 'Open workstation history', icon: 'fa-desktop' }],
    onAction: (k, r) => { if (k === 'events') opts.onEvents && opts.onEvents(r.computer_name); else opts.onOpen && opts.onOpen(r); } });
}

/** Consolidated event log with server-side search, filters, sorting and paging (handles very large logs). opts: { serviceId?, computer?, days?, onClear? } */
async function activityPanel(host, opts = {}) {
  const days = opts.days || '30';
  const scope = `days=${days}${opts.serviceId ? '&service_id=' + opts.serviceId : ''}${opts.computer ? '&computer=' + encodeURIComponent(opts.computer) : ''}`;
  const params = ({ page, size, q, filters, sort }) => `${scope}${page ? `&page=${page}&size=${size}` : ''}${q ? '&q=' + encodeURIComponent(q) : ''}${sort ? `&sort=${sort.key}&dir=${sort.dir}` : ''}${Object.entries(filters || {}).map(([k, v]) => `&f[${k}]=${encodeURIComponent(v)}`).join('')}`;
  host.innerHTML = `<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
      <div class="small text-secondary">${opts.computer ? `Events on <b class="text-white">${E(opts.computer)}</b>. ` : ''}DNS lookups and network connections as observed by collectors, newest first. Search, filter and page run on the server, so any log size works.</div>
      <div class="d-flex gap-2">${opts.computer && opts.onClear ? '<button class="btn btn-sm btn-outline-info" id="actClear"><i class="fa-solid fa-xmark"></i> All workstations</button>' : ''}${daySelect('actDays', days)}</div></div><div id="actGrid" class="border rounded"></div>`;
  if ($('#actClear', host)) $('#actClear', host).onclick = opts.onClear;
  $('#actDays', host).onchange = e => activityPanel(host, { ...opts, days: e.target.value });
  new DataGrid({ el: $('#actGrid', host), id: 'activity', rowKey: 'id', exportName: 'activity', pageSize: 25, sort: { key: 'event_timestamp', dir: 'desc' }, empty: 'No events match.',
    server: async st => { const r = await api('GET', 'activity?' + params(st).replace(/&f\[([a-z_]+)\]=/g, '&f[$1]=')); return { rows: r.events, total: r.total, facets: r.facets }; },
    exportUrl: st => dl('activity?format=csv&' + params({ ...st, page: 0 })),
    columns: [
      { key: 'event_timestamp', label: 'Time (local time)', nowrap: true, render: r => `<span class="small">${fmtDT(r.event_timestamp)}</span>` },
      { key: 'computer_name', label: 'Computer', filter: opts.computer ? undefined : 'select', render: r => `<span class="fw-semibold">${E(r.computer_name)}</span>` },
      ...(opts.serviceId ? [] : [{ key: 'service_name', label: 'Service', filter: 'select' }]),
      { key: 'kind', label: 'Type', filter: 'select', render: r => `<span class="pill ${r.kind === 'DNS' ? 'p-info' : 'p-vio'}">${E(r.kind)}</span>` },
      { key: 'host', label: 'Host', filter: 'text', render: r => `<span class="mono small">${E(r.host)}</span>` },
      { key: 'process', label: 'Process', filter: 'select', render: r => `<span class="small">${E(r.process)}</span>` },
      { key: 'detail', label: 'Detail', render: r => `<span class="small text-secondary mono">${E(r.detail || '')}</span>` }] });
}

/** Modal with the full event log of one computer (all services). */
function openComputerEvents(name) {
  const m = modal(`<i class="fa-solid fa-list me-2 text-info"></i>${E(name)} &mdash; event log`, '<div id="ceHost"></div>', '', 'modal-xl');
  activityPanel($('#ceHost', m.el), { computer: name });
}
