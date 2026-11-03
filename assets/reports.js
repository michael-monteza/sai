'use strict';
/* Reports & Analytics: sanctioned vs unsanctioned, network activity, exports, coverage, retention. */
async function reports() {
  const days = S.repDays || 30, name = S.repName || 'usage-by-service';
  const [sm, cat, ret, rep] = await Promise.all([api('GET', 'dashboard/summary?days=' + days), api('GET', 'reports'), api('GET', 'retention'), api('GET', `reports/${name}?days=${days}`)]);
  const t = sm.totals, cv = sm.coverage, w = can('retention.write');
  const card = (label, val, sub, c) => `<div class="col-6 col-xl"><div class="card kpi h-100" style="--c:${c}"><div class="small text-secondary">${label}</div><div class="v">${val}</div><div class="small text-secondary">${sub}</div></div></div>`;
  const pct = v => v == null ? '-' : v + '%';
  const cell = (k, v) => k === 'sanction_status' ? statusPill(v) : /_(observed|seen)$|^first_|^last_/.test(k) ? fmtDT(v) : (k === 'active' || k === 'archived') ? (+v ? 'Yes' : 'No') : typeof v === 'number' || /^\d+$/.test(v ?? '') ? fmtN(v) : E(v ?? '');
  const q = f => dl(`reports/${name}?days=${days}&format=${f}`);
  $('#view').innerHTML = pageHead('<i class="fa-solid fa-chart-line text-info"></i> Reports &amp; Analytics', 'Sanctioned vs unsanctioned activity, network activity and exports', `
    <select id="rDays" class="form-select form-select-sm" style="width:auto">${[7, 30, 90, 180, 365].map(d => `<option value="${d}" ${d === days ? 'selected' : ''}>Last ${d} days</option>`).join('')}</select>`) + `
  <div class="disclaimer mb-3"><i class="fa-solid fa-circle-info me-1"></i> <b>Reporting only.</b> These figures are observed telemetry from monitored workstations. See <a href="#" id="lim">what this data cannot tell you</a>.</div>
  <div class="row g-3 mb-3">
    ${card('Observed DNS events', fmtN(t.dns_events), `${t.workstations_with_activity} workstations`, 'var(--cyan)')}
    ${card('Sanctioned', pct(t.sanctioned_pct), fmtN(t.sanctioned_events) + ' events', 'var(--ok)')}
    ${card('Unsanctioned / review', pct(t.unsanctioned_pct), fmtN(t.unsanctioned_events + t.under_review_events) + ' events', 'var(--bad, #ef4444)')}
    ${card('Network connections', cv.network_events_enabled ? fmtN(t.network_connections) : 'Off', cv.network_events_enabled ? 'Sysmon EID 3' : 'Enable in Collectors', 'var(--vio)')}
    ${card('Awaiting classification', fmtN(t.new_discoveries), '<a href="#discovery">Domain Discovery</a>', 'var(--warn)')}</div>
  <div class="row g-3 mb-3">
    <div class="col-lg-8"><div class="card p-3 h-100"><h6 class="text-white">Daily events: sanctioned vs unsanctioned</h6><div style="height:230px"><canvas id="cRt"></canvas></div></div></div>
    <div class="col-lg-4"><div class="card p-3 h-100"><h6 class="text-white">Monitoring coverage</h6><div class="small">
      <div class="d-flex justify-content-between"><span>Authorized collectors</span><b>${cv.authorized_collectors}</b></div>
      <div class="d-flex justify-content-between"><span>Online (15 min)</span><b>${cv.online} (${pct(cv.online_pct)})</b></div>
      <div class="d-flex justify-content-between"><span>Buffering offline</span><b>${cv.buffering}</b></div>
      <div class="d-flex justify-content-between"><span>Event ID 3 monitoring</span><b>${cv.network_events_enabled ? 'On' : 'Off'}</b></div>
      <div class="d-flex justify-content-between"><span>Last observed</span><b>${t.last_event ? fmtDT(t.last_event) : '-'}</b></div></div>
      <div class="small text-secondary mt-2">Devices without an authorized collector are not covered.</div></div></div></div>
  <div class="card mb-3"><div class="p-3 pb-0 d-flex flex-wrap justify-content-between align-items-center gap-2"><div><h6 class="text-white mb-0">${E(rep.title)}</h6><div class="small text-secondary">${E(rep.description)}</div></div>
    <div class="d-flex gap-2"><select id="rName" class="form-select form-select-sm" style="width:auto">${cat.reports.map(r => `<option value="${r.name}" ${r.name === name ? 'selected' : ''}>${E(r.title)}</option>`).join('')}</select>
      <a class="btn btn-sm btn-outline-secondary" href="${q('csv')}"><i class="fa-solid fa-file-csv"></i> CSV</a><a class="btn btn-sm btn-outline-secondary" href="${q('xlsx')}"><i class="fa-solid fa-file-excel"></i> Excel</a></div></div>
    <div id="rpGrid" class="mt-2"></div></div>
  <div class="card p-3"><h6 class="text-white">Data retention</h6><div class="small text-secondary mb-2">Older rows are removed by the scheduled <code>tools\\purge.php</code> job. 0 keeps data indefinitely. Purges are written to the audit log.</div>
    <div class="row g-3 small">${[['retention_events_days', 'Usage &amp; network events (days)'], ['retention_discovery_days', 'Excluded discovered domains (days)'], ['retention_heartbeat_days', 'Collector heartbeats (days)']].map(([k, l]) =>
      `<div class="col-md-4"><label class="form-label mb-1">${l}</label><input type="number" min="0" max="3650" class="form-control form-control-sm" data-r="${k}" value="${ret.retention[k]}" ${w ? '' : 'disabled'}></div>`).join('')}</div>
    ${w ? '<div class="mt-2"><button class="btn btn-info btn-sm" id="rSave">Save retention</button></div>' : ''}</div>`;
  new DataGrid({ el: '#rpGrid', id: 'report-' + name, rows: rep.rows.map((r, i) => ({ _i: i, ...r })), rowKey: '_i', exportName: name, pageSize: 10,
    columns: Object.entries(rep.columns).map(([k, l]) => ({ key: k, label: String(l).replace('(UTC)', '(local time)'), num: /events|connections|workstations|hits|services|spool|failed|count|share|port/i.test(k) || undefined,
      filter: /sanction_status|status|domain_type|matching_rule|active|archived/.test(k) ? 'select' : undefined, render: r => cell(k, r[k]) })), empty: 'No data in this period.' });
  chart('cRt', { type: 'bar', data: { labels: sm.trend.map(r => String(r.d).slice(5)), datasets: [
    { label: 'Sanctioned', data: sm.trend.map(r => +r.sanctioned), backgroundColor: '#10b981', stack: 's' },
    { label: 'Unsanctioned / review', data: sm.trend.map(r => +r.unsanctioned), backgroundColor: '#ef4444', stack: 's' }] },
    options: { maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } }, plugins: { legend: { position: 'bottom' } } } });
  $('#rDays').onchange = e => { S.repDays = +e.target.value; reports(); };
  $('#rName').onchange = e => { S.repName = e.target.value; reports(); };
  $('#lim').onclick = e => { e.preventDefault(); modal('What this data cannot tell you', `<ul class="small mb-0">${sm.limitations.map(l => `<li class="mb-2">${E(l)}</li>`).join('')}</ul>`); };
  if ($('#rSave')) $('#rSave').onclick = () => act(async () => {
    const b = {}; document.querySelectorAll('[data-r]').forEach(i => b[i.dataset.r] = +i.value);
    await api('POST', 'retention', b); toast('Retention saved', 'success'); });
}
