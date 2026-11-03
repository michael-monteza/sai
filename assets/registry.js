'use strict';
/* AI Services & DNS Registry, Domain Discovery, Collectors & Monitoring. Uses helpers defined in app.js (loaded after this file; used at call time). */

const CLASSES = { sanctioned: 'Sanctioned', unsanctioned: 'Unsanctioned', under_review: 'Under Review', excluded: 'Excluded' };
const classPill = c => ({ sanctioned: '<span class="pill p-ok">SANCTIONED</span>', unsanctioned: '<span class="pill p-bad">UNSANCTIONED</span>', under_review: '<span class="pill p-warn">UNDER REVIEW</span>', excluded: '<span class="pill p-mute">EXCLUDED</span>' }[c] || E(c));
const DOMAIN_TYPES = ['primary', 'secondary', 'api', 'authentication', 'cdn', 'other'];
const opts = (list, cur, label = x => x) => list.map(x => `<option value="${E(x)}" ${x === cur ? 'selected' : ''}>${E(label(x))}</option>`).join('');

/* ---------------- AI Services & DNS Registry ---------------- */
async function registry() {
  if (S.regView === 'fqdn') return fqdn();
  const r = await api('GET', 'registry');
  const w = can('registry.write'), dlt = can('registry.delete');
  const state = s => +s.archived ? 'Archived' : +s.active ? 'Active' : 'Inactive';
  $('#view').innerHTML = pageHead('AI Services &amp; DNS Registry',
    `The central list collectors watch for. Config version <b>${r.config_version}</b>: collectors re-sync automatically when it changes.`,
    `<button class="btn btn-sm btn-outline-secondary" id="rgHist"><i class="fa-solid fa-clock-rotate-left"></i> Change history</button>` +
    (w ? `<button class="btn btn-sm btn-info" id="rgAdd"><i class="fa-solid fa-plus"></i> Add AI service</button>` : '')) + regTabs('services', r.services.length, r.services.reduce((a, x) => a + x.domains.length, 0)) + '<div class="card"><div id="rgGrid"></div></div>';
  bindRegTabs();
  const again = () => { S.services = null; registry(); };
  new DataGrid({ el: '#rgGrid', id: 'registry', rows: r.services, exportName: 'ai-registry', sort: { key: 'service_name', dir: 'asc' }, onRowClick: s => domainsModal(s),
    rowClass: s => +s.archived ? 'text-secondary' : '',
    columns: [
      { key: 'service_name', label: 'Service', filter: 'text', text: s => `${s.service_name} ${s.provider} ${s.domains.map(d => d.domain).join(' ')}`, sort: s => s.service_name,
        render: s => `<b>${E(s.service_name)}</b><div class="small text-secondary">${E(s.provider)} &middot; ${E(s.category)}</div>` },
      { key: 'sanction_status', label: 'Classification', filter: 'select', text: s => CLASSES[s.sanction_status] || s.sanction_status, render: s => classPill(s.sanction_status) },
      { key: 'domains', label: 'Domains', num: true, text: s => s.domains.length, sort: s => s.domains.length, render: s => `<span class="small mono">${s.domains.filter(d => +d.active).length} active / ${s.domains.length}</span>` },
      { key: 'website', label: 'Official website', text: s => s.website || '', render: s => s.website ? `<a class="small" href="${E(/^https?:\/\//.test(s.website) ? s.website : '#')}" target="_blank" rel="noopener noreferrer">${E(s.website)}</a>` : '<span class="text-secondary">-</span>' },
      { key: 'state', label: 'State', filter: 'select', text: state, render: s => `<span class="pill ${+s.archived ? 'p-mute' : +s.active ? 'p-ok' : 'p-warn'}">${state(s).toUpperCase()}</span>` },
      { key: 'updated_at', label: 'Updated', nowrap: true, text: s => `${s.updated_at || ''} ${s.updated_by || ''}`, sort: s => s.updated_at, render: s => `<span class="small">${fmtDT(s.updated_at)}</span><div class="small text-secondary">${E(s.updated_by || '')}</div>` }],
    actions: s => [{ inline: true, key: 'domains', label: 'DNS domains', icon: 'fa-sitemap' }, { inline: true, key: 'manage', label: w ? 'Edit service' : 'View service', icon: w ? 'fa-pen' : 'fa-eye' }]
      .concat(w ? [{ key: 'archive', label: +s.archived ? 'Restore' : 'Archive', icon: +s.archived ? 'fa-box-open' : 'fa-box-archive' }] : [], dlt ? [{ inline: true, key: 'delete', label: 'Delete service', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, s) => {
      if (k === 'domains') domainsModal(s); else if (k === 'manage') openService(s.id, registry);
      else if (k === 'archive') act(async () => { await api('POST', 'services/' + s.id, { archived: !+s.archived }); toast(+s.archived ? 'Restored' : 'Archived', 'success'); again(); });
      else if (k === 'delete' && await deleteServices([s])) again(); },
    bulk: w ? [{ label: 'Set classification', icon: 'fa-tags', fn: rs => bulkClassify(rs, again) },
      { label: 'Archive', icon: 'fa-box-archive', fn: rs => act(async () => { for (const s of rs) await api('POST', 'services/' + s.id, { archived: true }); toast(`${rs.length} archived`, 'success'); again(); }) }].concat(dlt ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await deleteServices(rs)) again(); } }] : []) : null });
  $('#rgHist').onclick = registryHistory;
  if ($('#rgAdd')) $('#rgAdd').onclick = () => addServiceModal();
}

/** Set one classification on many services (Inventory and Registry bulk action). */
function bulkClassify(rs, after) {
  const m = modal(`Set classification for ${rs.length} service${rs.length > 1 ? 's' : ''}`, `<select id="bcCls" class="form-select form-select-sm">${opts(Object.keys(CLASSES), 'unsanctioned', k => CLASSES[k])}</select>
    <div class="small text-secondary mt-2">Excluded means known non-AI: collectors stop reporting these domains.</div>`, '<button class="btn btn-info btn-sm" id="bcGo">Apply</button>');
  $('#bcGo', m.el).onclick = () => act(async () => { for (const s of rs) await api('POST', 'services/' + s.id, { sanction_status: $('#bcCls', m.el).value }); m.close(); toast(`${rs.length} updated`, 'success'); after(); });
}

function domainsModal(s) {
  const w = can('registry.write'), dlt = can('registry.delete');
  const m = modal(`${E(s.service_name)} &mdash; DNS domains`, `
    <div class="d-flex align-items-center gap-2 mb-3"><span class="small text-secondary">Classification</span>
      <select id="dmCls" class="form-select form-select-sm w-auto" ${w ? '' : 'disabled'}>${opts(Object.keys(CLASSES), s.sanction_status, k => CLASSES[k])}</select>
      ${w ? `<label class="form-check-label small ms-3"><input type="checkbox" class="form-check-input me-1" id="dmArch" ${+s.archived ? 'checked' : ''}>Archived</label>` : ''}</div>
    <div class="table-responsive"><table class="table table-sm align-middle"><thead><tr><th>Domain</th><th>Type</th><th>Matching</th><th>Observed</th><th>Active</th>${dlt ? '<th></th>' : ''}</tr></thead><tbody>
    ${s.domains.map(d => `<tr><td class="mono small">${E(d.domain)}${+d.shared ? ' <span class="pill p-warn">SHARED</span>' : ''}<div class="text-secondary">${E(d.notes || '')}</div></td>
      <td><select class="form-select form-select-sm" data-f="domain_type" data-id="${d.id}" ${w ? '' : 'disabled'}>${opts(DOMAIN_TYPES, d.domain_type)}</select></td>
      <td><select class="form-select form-select-sm" data-f="matching_rule" data-id="${d.id}" ${w ? '' : 'disabled'}>${opts(['subdomain', 'exact'], d.matching_rule, x => x === 'exact' ? 'Exact only' : 'Domain + subdomains')}</select></td>
      <td class="small">${fmtN(d.hits)} events<div class="text-secondary">${d.last_observed ? 'last ' + fmtDT(d.last_observed) : ''}</div></td>
      <td><input type="checkbox" class="form-check-input" data-f="active" data-id="${d.id}" ${+d.active ? 'checked' : ''} ${w ? '' : 'disabled'}></td>${dlt ? `<td class="text-end"><button class="btn btn-sm btn-outline-danger" data-dd="${d.id}" title="Delete domain" aria-label="Delete domain"><i class="fa-solid fa-trash"></i></button></td>` : ''}</tr>`).join('') || '<tr><td colspan="6" class="text-center text-secondary py-3">No domains.</td></tr>'}</tbody></table></div>
    ${w ? `<hr><div class="row g-2 align-items-end"><div class="col-md-4"><label class="form-label small">Add domain</label><input id="nd" class="form-control form-control-sm mono" placeholder="api.example.com or *.example.com"></div>
      <div class="col-md-3"><label class="form-label small">Type</label><select id="nt" class="form-select form-select-sm">${opts(DOMAIN_TYPES, 'secondary')}</select></div>
      <div class="col-md-3"><label class="form-label small">Matching</label><select id="nr" class="form-select form-select-sm"><option value="subdomain">Domain + subdomains</option><option value="exact">Exact only</option></select></div>
      <div class="col-md-2"><button class="btn btn-info btn-sm w-100" id="nadd">Add</button></div>
      <div class="col-12"><input id="nn" class="form-control form-control-sm" placeholder="Notes (optional)"></div></div>
      <div class="small text-secondary mt-2">Deactivating a domain stops collectors watching it; existing events and history are kept.</div>` : ''}`, '', 'modal-lg');
  const done = (msg) => { toast(msg, 'success'); m.close(); registry(); };
  m.el.querySelectorAll('[data-f]').forEach(el => el.onchange = () => act(async () => {
    await api('POST', 'registry/domains/' + el.dataset.id, { [el.dataset.f]: el.type === 'checkbox' ? el.checked : el.value }); toast('Saved', 'success'); }));
  if (!w) return;
  m.el.querySelectorAll('[data-dd]').forEach(b => b.onclick = async () => {
    if (await deleteFlow({ path: 'registry/domains/delete', ids: [+b.dataset.dd], title: 'Delete domain', describe: () => `<p class="small mb-0">Collectors stop watching this domain on their next sync. Events already recorded for it are kept.</p>`, done: 'Domain deleted' })) registry(); else domainsModal(s); });
  $('#dmCls', m.el).onchange = e => act(async () => { await api('POST', 'services/' + s.id, { sanction_status: e.target.value }); done('Classification updated'); });
  $('#dmArch', m.el).onchange = e => act(async () => { await api('POST', 'services/' + s.id, { archived: e.target.checked }); done(e.target.checked ? 'Archived' : 'Restored'); });
  $('#nadd', m.el).onclick = () => act(async () => {
    await api('POST', 'registry/domains', { service_id: s.id, domain: $('#nd', m.el).value, domain_type: $('#nt', m.el).value, matching_rule: $('#nr', m.el).value, notes: $('#nn', m.el).value });
    done('Domain added'); });
}

async function registryHistory() {
  const { history } = await api('GET', 'registry/history');
  const diff = h => { try { const b = JSON.parse(h.before_json || 'null') || {}, a = JSON.parse(h.after_json || 'null') || {};
    return Object.keys({ ...b, ...a }).map(k => `<span class="mono">${E(k)}</span>: ${E(JSON.stringify(b[k] ?? null))} &rarr; <b>${E(JSON.stringify(a[k] ?? null))}</b>`).join('<br>'); } catch { return ''; } };
  modal('Registry change history', `<div class="table-responsive" style="max-height:60vh"><table class="table table-sm"><thead><tr><th>Time (local time)</th><th>By</th><th>Action</th><th>Record</th><th>Change</th></tr></thead><tbody>
    ${history.map(h => `<tr><td class="small text-nowrap">${fmtDT(h.timestamp)}</td><td>${E(h.administrator)}</td><td><span class="pill p-info">${E(h.action)}</span></td><td>${E(h.affected_record)}</td><td class="small">${diff(h)}</td></tr>`).join('') || '<tr><td colspan="5" class="text-center text-secondary py-3">No changes recorded yet.</td></tr>'}</tbody></table></div>`, '', 'modal-xl');
}

/* ---------------- Domain Discovery ---------------- */
async function discovery() {
  const st = (S.discStatus ||= 'open');
  const { domains, counts } = await api('GET', 'discovery?status=' + st);
  const { services } = can('inventory.read') ? await api('GET', 'services') : { services: [] };
  const w = can('discovery.write'), dlt = can('discovery.delete');
  const chips = [['open', 'New + Under review', (counts.new || 0) + (counts.under_review || 0)], ['new', 'New', counts.new || 0], ['under_review', 'Under review', counts.under_review || 0], ['classified', 'Classified', counts.classified || 0], ['excluded', 'Excluded', counts.excluded || 0], ['all', 'All', Object.values(counts).reduce((a, b) => a + b, 0)]];
  const pill = { new: 'p-info', under_review: 'p-warn', classified: 'p-ok', excluded: 'p-mute' };
  const label = k => k.replace('_', ' ');
  $('#view').innerHTML = pageHead('Domain Discovery', 'Hostnames reported by collectors that are not in the registry. They are <b>not</b> counted as AI usage until you classify them. Only hostnames matching server-defined hints are sent by collectors.') + `
  <div class="d-flex flex-wrap gap-2 mb-3">${chips.map(([k, l, n]) => `<button class="btn btn-sm ${k === st ? 'btn-info' : 'btn-outline-secondary'}" data-st="${k}">${l} <span class="badge text-bg-light">${n}</span></button>`).join('')}</div>
  <div class="card"><div id="dcGrid"></div></div>`;
  document.querySelectorAll('[data-st]').forEach(b => b.onclick = () => { S.discStatus = b.dataset.st; discovery(); });
  const setStatus = (rs, action, notes) => act(async () => { for (const d of rs) await api('POST', 'discovery/' + d.id, { action, notes }); toast(`${rs.length} updated`, 'success'); discovery(); });
  const open = d => d.status === 'new' || d.status === 'under_review';
  const excludeModal = rs => formModal({ title: `Exclude ${rs.length} hostname${rs.length > 1 ? 's' : ''}`, icon: 'fa-ban', note: 'Excluded hostnames are known non-AI: collectors skip them and they are not counted.', submit: 'Exclude', submitIcon: 'fa-ban',
    fields: [{ name: 'notes', label: 'Note (why is this not AI?)', type: 'textarea', rows: 2, maxlength: 500 }], save: async v => { for (const d of rs) await api('POST', 'discovery/' + d.id, { action: 'exclude', notes: v.notes }); }, done: () => { toast('Excluded', 'success'); discovery(); } });
  new DataGrid({ el: '#dcGrid', id: 'discovery', rows: domains, exportName: 'domain-discovery', sort: { key: 'last_seen', dir: 'desc' },
    columns: [
      { key: 'domain', label: 'Domain', filter: 'text', text: d => `${d.domain} ${d.notes || ''} ${d.service_name || ''}`, sort: d => d.domain,
        render: d => `<span class="mono">${E(d.domain)}</span><div class="small text-secondary">${E(d.notes || '')}${d.service_name ? ' &rarr; ' + E(d.service_name) : ''}</div>` },
      { key: 'status', label: 'Status', filter: 'select', text: d => label(d.status), render: d => `<span class="pill ${pill[d.status]}">${E(label(d.status)).toUpperCase()}</span>` },
      { key: 'hit_count', label: 'Hits', num: true, render: d => fmtN(d.hit_count) },
      { key: 'workstations', label: 'Workstations', num: true, render: d => `<a href="#" data-h="${d.id}" data-d="${E(d.domain)}">${d.workstations}</a>` },
      { key: 'first_seen', label: 'First seen', nowrap: true, render: d => `<span class="small">${fmtDT(d.first_seen)}</span>` },
      { key: 'last_seen', label: 'Last seen', nowrap: true, render: d => `<span class="small">${fmtDT(d.last_seen)}</span>` }],
    actions: d => [{ inline: true, key: 'hosts', label: 'Workstations', icon: 'fa-eye' }].concat(w ? (open(d)
      ? [d.status === 'new' ? { key: 'review', label: 'Mark under review', icon: 'fa-magnifying-glass' } : null, { inline: true, key: 'classify', label: 'Classify as AI service', icon: 'fa-pen' }, { key: 'exclude', label: 'Exclude (not AI)', icon: 'fa-ban' }].filter(Boolean)
      : [{ key: 'reopen', label: 'Reopen', icon: 'fa-rotate-left' }]).concat(dlt ? [{ inline: true, key: 'delete', label: 'Delete record', icon: 'fa-trash', danger: true }] : []) : []),
    onAction: async (k, d) => {
      if (k === 'hosts') return showHosts(d.id, d.domain);
      if (k === 'classify') return classifyModal({ dataset: { c: d.id, d: d.domain } });
      if (k === 'exclude') return excludeModal([d]);
      if (k === 'delete') { if (await deleteDiscovery([d])) discovery(); return; }
      setStatus([d], k); },
    bulk: w ? [{ label: 'Mark under review', icon: 'fa-eye', fn: rs => setStatus(rs.filter(open), 'review') }, { label: 'Exclude', icon: 'fa-ban', fn: rs => excludeModal(rs.filter(open)) },
      { label: 'Reopen', icon: 'fa-rotate-left', fn: rs => setStatus(rs.filter(d => !open(d)), 'reopen') },
      ].concat(dlt ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await deleteDiscovery(rs)) discovery(); } }] : []) : null });
  $('#dcGrid').addEventListener('click', e => { const a = e.target.closest('[data-h]'); if (a) { e.preventDefault(); showHosts(a.dataset.h, a.dataset.d); } });
  const showHosts = (id, name) => act(async () => {
    const { hosts } = await api('GET', `discovery/${id}/hosts`);
    modal(E(name) + ' &mdash; workstations', `<table class="table table-sm"><thead><tr><th>Computer</th><th>Hits</th><th>First</th><th>Last</th></tr></thead><tbody>${hosts.map(h => `<tr><td>${E(h.computer_name)}</td><td>${h.hit_count}</td><td class="small">${fmtDT(h.first_seen)}</td><td class="small">${fmtDT(h.last_seen)}</td></tr>`).join('')}</tbody></table>`); });
  const classifyModal = b => {
    const m = modal('Classify ' + E(b.dataset.d), `<label class="form-label small">Classification</label><select id="cl" class="form-select form-select-sm mb-2">${opts(['unsanctioned', 'under_review', 'sanctioned'], 'unsanctioned', k => CLASSES[k])}</select>
      <label class="form-label small">Attach to existing service</label><select id="p_sid" class="form-select form-select-sm mb-2"><option value="">- create a new service -</option>${services.map(s => `<option value="${s.id}">${E(s.service_name)}</option>`).join('')}</select>
      <div id="p_new"><label class="form-label small">New service name</label><input id="p_name" class="form-control form-control-sm mb-2"><label class="form-label small">Provider</label><input id="p_prov" class="form-control form-control-sm"></div>
      <div class="small text-secondary mt-2">Choose <b>Exclude</b> instead if this is not an AI service.</div>`, '<button class="btn btn-info btn-sm" id="p_ok">Add to registry</button>');
    $('#p_sid', m.el).onchange = () => $('#p_new', m.el).style.display = $('#p_sid', m.el).value ? 'none' : '';
    $('#p_ok', m.el).onclick = () => act(async () => { await api('POST', 'discovery/' + b.dataset.c, { action: 'classify', classification: $('#cl', m.el).value, service_id: $('#p_sid', m.el).value || null, service_name: $('#p_name', m.el).value, provider: $('#p_prov', m.el).value });
      m.close(); toast('Added to the registry; collectors pick it up on next sync', 'success'); S.services = null; discovery(); });
  };
}

const deleteDiscovery = rs => deleteFlow({ path: 'discovery/delete', ids: rs.map(d => +d.id), title: `Delete ${rs.length} discovery record${rs.length > 1 ? 's' : ''}`,
  describe: () => '<p class="small mb-0">Only the discovery records and their per-workstation hit counts are removed. If a collector reports the hostname again it is rediscovered as new. To stop seeing a hostname, <b>Exclude</b> it instead.</p>', done: 'Discovery records deleted' });

/* ---------------- Collectors & Monitoring ---------------- */
async function collectors() {
  const { collectors: rows, monitoring: mon, config_version: cv } = await api('GET', 'collectors');
  const ipm = can('registry.read') ? await api('GET', 'ip-map') : null;
  const base = location.origin + BASE + '/api/v1';
  const w = can('collectors.write'), dlt = can('collectors.delete'), mw = can('monitoring.write');
  const cs = { authorized: 'p-ok', pending: 'p-warn', suspended: 'p-mute', revoked: 'p-bad' };
  const health = r => {
    if (r.status !== 'authorized') return '<span class="text-secondary">-</span>';
    if (!+r.online) return '<span class="pill p-bad">OFFLINE</span>';
    if (r.last_error || +r.spool_depth > 0) return '<span class="pill p-warn">DEGRADED</span>';
    if (r.config_version_applied != null && +r.config_version_applied < cv) return '<span class="pill p-info">SYNC PENDING</span>';
    return '<span class="pill p-ok">HEALTHY</span>';
  };
  $('#view').innerHTML = pageHead('Collectors &amp; Monitoring', 'Sysmon-based collectors reporting activity for this company. Rules and options below are delivered to collectors centrally.', `<a class="btn btn-sm btn-outline-secondary" href="${dl('collector-package')}" title="Scripts and Sysmon configuration, with this server's address filled in"><i class="fa-solid fa-download"></i> Download collector package</a>` + '<button class="btn btn-sm btn-outline-secondary" id="smCap"><i class="fa-solid fa-microchip"></i> Sysmon capabilities</button>' + (w ? '<button class="btn btn-sm btn-outline-info" id="enr"><i class="fa-solid fa-key"></i> New enrollment key</button>' : '')) + `
  <div class="card p-3 mb-3 small">Collector <span class="mono">serverUrl</span>: <code>${E(base)}</code>. New collectors register with this company's <b>enrollment key</b>; ${rows.some(r => r.status === 'pending') ? '<b class="text-warning">some are pending authorization</b>.' : 'authorize each one before it can send data.'}</div>
  <div class="card p-3 mb-3"><div class="d-flex justify-content-between align-items-center mb-2"><b>Monitoring options</b><span class="small text-secondary">config version ${cv}</span></div>
    <div class="row g-3 small">
      <div class="col-md-3"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="mDns" checked disabled><label class="form-check-label" for="mDns">DNS queries (Sysmon EID 22)</label></div><div class="text-secondary">Always on. Hostnames only.</div></div>
      <div class="col-md-3"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="mNet" ${mon.network_events ? 'checked' : ''} ${mw ? '' : 'disabled'}><label class="form-check-label" for="mNet">Network connections (EID 3)</label></div><div class="text-secondary">Higher volume. Requires the optional Sysmon block.</div></div>
      <div class="col-md-3"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="mDisc" ${mon.discovery ? 'checked' : ''} ${mw ? '' : 'disabled'}><label class="form-check-label" for="mDisc">Domain discovery</label></div><div class="text-secondary">Report unregistered hostnames that contain a hint below.</div></div>
      <div class="col-md-3"><label class="form-label mb-1">Check interval (min)</label><input id="mInt" type="number" min="1" max="1440" class="form-control form-control-sm" value="${mon.interval_minutes}" ${mw ? '' : 'disabled'}></div>
      <div class="col-12"><label class="form-label mb-1">Discovery hints (comma separated keywords)</label><input id="mHints" class="form-control form-control-sm mono" value="${E(mon.discovery_hints.join(', '))}" ${mw ? '' : 'disabled'}></div></div>
    ${mw ? '<div class="mt-2"><button class="btn btn-info btn-sm" id="mSave">Save monitoring options</button></div>' : ''}
    <div class="small text-secondary mt-2">EID 1 (process creation) and EID 5 (process end) are not collected: they add volume and privacy exposure without improving AI-service identification.</div></div>
  ${ipm ? `<div class="card p-3 mb-3"><div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2"><b><i class="fa-solid fa-network-wired me-1 text-info"></i> Network connection matching (Event ID 3)</b>${mw ? '<button class="btn btn-sm btn-outline-info" id="ipRef"><i class="fa-solid fa-rotate"></i> Refresh addresses</button>' : ''}</div>
    <div class="small text-secondary mb-2">Event ID 3 sees the connection itself, so it also works for browsers that bypass the Windows DNS client, with no browser setting changed. When Sysmon has no host name, the destination <b>address</b> is matched against the addresses your registered services resolve to. Only <b>dedicated</b> addresses count. CDN and shared addresses (Cloudflare, Google front ends, CloudFront, Akamai, Fastly) are ignored, because they cannot show which site was visited; services hosted there, such as ChatGPT and Gemini, are still detected through DNS events.</div>
    <div class="row g-2 text-center small">${[['Addresses known', ipm.status.ips], ['Dedicated (used)', ipm.status.usable], ['Shared (ignored)', ipm.status.shared], ['Services covered', ipm.status.services]].map(([l, n]) => `<div class="col-6 col-md-3"><div class="p-2 rounded" style="background:var(--surface)"><div class="fw-bold fs-5 text-white">${fmtN(n)}</div><div class="text-secondary">${l}</div></div></div>`).join('')}</div>
    <div class="small text-secondary mt-2">${ipm.status.refreshed ? 'Last refreshed ' + fmtDT(ipm.status.refreshed) + '.' : 'Not refreshed yet.'} ${ipm.network_events ? '' : '<b class="text-warning">Network connections are switched off above, so collectors ignore this list.</b>'} Schedule <code>php tools\\refresh-ip-map.php</code> hourly: it also runs the reverse-DNS checks that spot CDN addresses (the first run takes a few minutes).</div></div>` : ''}
  <div class="card"><div id="coGrid"></div></div>`;
  const healthOf = r => r.status !== 'authorized' ? '-' : !+r.online ? 'Offline' : (r.last_error || +r.spool_depth > 0) ? 'Degraded' : (r.config_version_applied != null && +r.config_version_applied < cv) ? 'Sync pending' : 'Healthy';
  const doAct = (action, rs) => act(async () => {
    if (action === 'revoke' && !(await confirmModal({ title: 'Revoke collectors', danger: true, button: 'Revoke', icon: 'fa-ban', body: `<p class="small mb-0">Revoke <b>${rs.length}</b> collector(s) permanently? They must re-register to send data again.</p>` }))) return;
    let key = null;
    for (const r of rs) { const x = await api('POST', 'collectors/' + r.id, { action }); if (x.api_key) key = x.api_key; }
    if (key) { modal('New collector API key', `<p class="small text-warning">Shown once. Apply on the workstation: <code>Collect-AiUsage.ps1 -SetApiKey &lt;key&gt;</code></p><pre class="feed">${E(key)}</pre>`); document.querySelector('.modal').addEventListener('hidden.bs.modal', collectors); }
    else { toast(`${rs.length} collector(s) updated`, 'success'); collectors(); } });
  new DataGrid({ el: '#coGrid', id: 'collectors', rows, exportName: 'collectors', sort: { key: 'computer_name', dir: 'asc' },
    columns: [
      { key: 'computer_name', label: 'Computer', filter: 'text', text: r => `${r.computer_name} ${r.workstation_ip || r.mac_address || ''}`, sort: r => r.computer_name,
        render: r => `<span class="fw-semibold">${E(r.computer_name)}</span><div class="small text-secondary mono">${E(r.workstation_ip || r.mac_address || '')}</div>` },
      { key: 'status', label: 'Status', filter: 'select', render: r => `<span class="pill ${cs[r.status]}">${E(r.status).toUpperCase()}</span>` },
      { key: 'health', label: 'Health', filter: 'select', text: healthOf, render: r => health(r) },
      { key: 'last_seen', label: 'Last seen', nowrap: true, render: r => `<span class="small">${fmtDT(r.last_seen)}</span>` },
      { key: 'collector_version', label: 'Version', filter: 'select' },
      { key: 'config_version_applied', label: 'Config', num: true, render: r => `<span class="small">${r.config_version_applied ?? '-'}</span><div class="small text-secondary">${r.last_config_sync ? fmtDT(r.last_config_sync) : ''}</div>` },
      { key: 'spool_depth', label: 'Spool', num: true },
      { key: 'failed_submissions', label: 'Failures', num: true },
      { key: 'last_error', label: 'Last error', render: r => `<span class="small text-secondary" style="display:inline-block;max-width:220px;overflow-wrap:anywhere">${E(r.last_error || '')}</span>` }],
    actions: r => [].concat(r.status !== 'authorized' && r.status !== 'revoked' && w ? [{ inline: true, key: 'authorize', label: 'Authorize', icon: 'fa-check' }] : [], r.status === 'authorized' && w ? [{ inline: true, key: 'suspend', label: 'Suspend', icon: 'fa-pause' }] : [],
      r.status !== 'revoked' && w ? [{ key: 'rotate', label: 'Rotate API key', icon: 'fa-key' }, { key: 'revoke', label: 'Revoke', icon: 'fa-ban' }] : [],
      dlt ? [{ key: 'clear', label: 'Clear collected data', icon: 'fa-eraser' }, { inline: true, key: 'delete', label: 'Delete collector', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, r) => { if (k === 'delete' || k === 'clear') { if (await deleteCollectors([r], k === 'clear')) collectors(); } else doAct(k, [r]); },
    bulk: w ? [{ label: 'Authorize', icon: 'fa-check', fn: rs => doAct('authorize', rs.filter(r => r.status !== 'revoked')) }, { label: 'Suspend', icon: 'fa-pause', fn: rs => doAct('suspend', rs.filter(r => r.status === 'authorized')) }].concat(dlt ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await deleteCollectors(rs, false)) collectors(); } }] : []) : null });
  if ($('#mSave')) $('#mSave').onclick = () => act(async () => {
    await api('POST', 'monitoring', { network_events: $('#mNet').checked, discovery: $('#mDisc').checked, discovery_hints: $('#mHints').value, interval_minutes: +$('#mInt').value });
    toast('Saved; collectors apply it on their next sync', 'success'); collectors(); });
  $('#smCap').onclick = () => act(sysmonModal);
  if ($('#ipRef')) $('#ipRef').onclick = () => { const b = $('#ipRef'); b.disabled = true; b.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Resolving&hellip;'; act(async () => { const r = await api('POST', 'ip-map/refresh', {}); toast(`${r.status.usable} dedicated and ${r.status.shared} shared addresses; collectors resync automatically`, 'success'); }).finally(collectors); };
  if ($('#enr')) $('#enr').onclick = async () => { if (!(await confirmModal({ title: 'New enrollment key', icon: 'fa-key', danger: true, button: 'Generate', body: '<p class="small mb-0">The previous key stops working for new registrations. Registered collectors are unaffected.</p>' }))) return; act(async () => {
    const r = await api('POST', 'enrollment/regenerate');
    modal('Enrollment key', `<p class="small text-warning">Shown once. Put it in <code>collector.config.json</code> on workstations to be enrolled.</p><pre class="feed">${E(JSON.stringify({ serverUrl: base, enrollmentKey: r.enrollment_key }, null, 2))}</pre>`); }); };
}
