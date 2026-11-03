/* ---------------- shell ---------------- */
const TABS = { guide, overview, inventory, risk, workstations, adoption, reports, registry, fqdn: () => { S.regView = 'fqdn'; location.hash = '#registry'; }, discovery, governance, iso, collectors, integrations, audit, users, companies, authentication };

async function boot() {
  S.me = await api('GET', 'me'); S.csrf = S.me.csrf;
  const u = S.me.user;
  $('#userAvatar').textContent = (u.display_name || u.username).split(/[\s._-]+/).map(x => x[0]).join('').slice(0, 2).toUpperCase();
  $('#userName').textContent = u.display_name || u.username;
  $('#userRole').textContent = u.role_label || u.role;
  if ($('#tzNote')) $('#tzNote').textContent = 'Times: ' + TZ;
  $('#btnPassword').onclick = changePasswordModal;
  if (can('tenants.read')) {
    const sel = $('#tenantSelect'); sel.classList.remove('d-none');
    sel.innerHTML = S.me.tenants.map(t => `<option value="${t.id}" ${S.me.tenant && t.id == S.me.tenant.id ? 'selected' : ''}>${E(t.name)}</option>`).join('');
    sel.onchange = () => act(async () => { await api('POST', 'tenant/switch', { tenant_id: +sel.value }); location.reload(); });
  } else $('#tenantName').textContent = S.me.tenant?.name || '';
  document.querySelectorAll('.nav-toggle').forEach(b => b.onclick = () =>
    window.innerWidth >= 992 ? document.body.classList.toggle('collapsed') : $('#sidebar').classList.toggle('open'));
  window.addEventListener('hashchange', route);
  route();
}

async function route() {
  const tab = (location.hash || '#overview').slice(1);
  const fn = TABS[tab] || overview;
  document.querySelectorAll('.sidebar a').forEach(a => a.classList.toggle('active', a.dataset.tab === tab));
  $('#sidebar').classList.remove('open');
  if (!S.me.tenant && tab !== 'companies') {
    $('#view').innerHTML = `<div class="card p-4"><h5>No company selected</h5><p class="text-secondary mb-0">${can('tenants.write') ? 'Create your first company under <a href="#companies">Companies</a>.' : 'Your account is not linked to a company.'}</p></div>`;
    return;
  }
  $('#view').innerHTML = '<div class="text-secondary p-4">Loading&hellip;</div>';
  try { await fn(); } catch (e) { if (e.message !== 'signed out') $('#view').innerHTML = `<div class="alert alert-danger">${E(e.message)}</div>`; }
}

function setBadges(d) {
  $('#bShadow').textContent = d.kpi.shadow || ''; $('#bDisc').textContent = d.unknown_domains || '';
  $('#bReq').textContent = d.pending_requests || ''; $('#bIso').textContent = d.kpi.iso_score + '%';
}

/* ---------------- Executive dashboard ---------------- */
async function overview() {
  const d = await api('GET', 'dashboard'); setBadges(d);
  const k = d.kpi, c = d.collectors, t = d.telemetry;
  const card = (label, val, sub, color, extra = '') => `<div class="col-6 col-xl"><div class="card kpi h-100" style="--c:${color}"><div class="small text-secondary">${label}</div><div class="v">${val}</div><div class="small text-secondary">${sub}</div>${extra}</div></div>`;
  $('#view').innerHTML = DISCLAIMER + `
  <div class="row g-3 mb-3">
    ${card('Total AI Tools', fmtN(k.total_services), 'In the AI register', 'var(--cyan)')}
    ${card('Shadow AI (Unapproved)', `<span class="text-danger">${fmtN(k.shadow)}</span> <small class="text-danger">${k.shadow_ratio}%</small>`, 'Without authorization', 'var(--bad)')}
    ${card('Critical &amp; High Risk', fmtN(k.critical + k.high), `${k.critical} critical / ${k.high} high`, 'var(--warn)')}
    ${card('Sensitive-Data AI In Use', fmtN(k.sensitive_active), 'Confidential/PII-class tools with activity (30d)', 'var(--cyan)')}
    ${card('ISO 42001 Posture', `<span class="text-success">${k.iso_score}%</span>`, `${E(k.iso_tier)} &middot; ${k.iso_passed}/${k.iso_total} controls`, 'var(--ok)', `<div class="progress mt-2" style="height:5px"><div class="progress-bar bg-success" style="width:${k.iso_score}%"></div></div>`)}
  </div>
  <div class="card p-3 mb-3 d-flex flex-row flex-wrap gap-3 mono small">
    <span class="text-success"><i class="fa-solid fa-satellite"></i> ${c.online}/${c.authorized} collectors online (${c.total} registered)</span>
    <span>Observed AI DNS events (30d): <b class="text-white">${fmtN(t.events)}</b></span>
    <span>Workstations with AI activity: <b class="text-white">${fmtN(t.workstations)}</b></span>
    <span>Last event: ${fmtDT(t.last_event)}</span>
    <a href="#discovery">${d.unknown_domains} domain(s) to review</a>
  </div>
  <div class="row g-3 mb-3">
    <div class="col-lg-8"><div class="card p-3 h-100"><h6 class="text-white">Observed AI DNS events by approval status &mdash; last 30 days</h6><div style="height:250px"><canvas id="cTrend"></canvas></div></div></div>
    <div class="col-lg-4"><div class="card p-3 h-100"><h6 class="text-white">AI Fleet Risk Categorization</h6><div style="height:170px"><canvas id="cRisk"></canvas></div>
      <div class="row g-2 text-center mono mt-2">${['Low', 'Medium', 'High', 'Critical'].map((l, i) => `<div class="col-3"><div class="small text-secondary">${l.slice(0, 4).toUpperCase()}</div><b style="color:${['#10b981', '#22d3ee', '#f59e0b', '#f43f5e'][i]}">${d.risk_distribution[l]}</b></div>`).join('')}</div></div></div>
  </div>
  <div class="card p-3"><h6 class="text-white"><span class="text-danger">&#9679;</span> Active Shadow AI (awaiting governance review)</h6>
    <div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Application</th><th>Vendor</th><th>Domain</th><th>Risk</th><th>Workstations (30d)</th><th>Data class</th><th class="text-end">Triage</th></tr></thead><tbody>
    ${d.recent_shadow.map(s => `<tr><td class="fw-semibold text-white">${E(s.service_name)}</td><td>${E(s.provider)}</td><td class="mono small">${E(s.primary_domain)}</td><td>${riskPill(s.risk_level, s.risk_score)}</td><td>${s.workstations_30d}</td><td>${dcPill(s.data_class)}</td>
      <td class="text-end"><button class="btn btn-sm btn-outline-info" data-manage="${s.id}">Review</button></td></tr>`).join('') || '<tr><td colspan="7" class="text-center text-secondary py-3">No shadow AI activity observed in the last 30 days.</td></tr>'}
    </tbody></table></div></div>`;
  document.querySelectorAll('[data-manage]').forEach(b => b.onclick = () => openService(+b.dataset.manage));

  const days = [...new Set(d.trend.map(r => r.d))].sort();
  const series = (st) => days.map(day => +(d.trend.find(r => r.d === day && r.st === st)?.c || 0));
  chart('cTrend', { type: 'line', data: { labels: days, datasets: [
    { label: 'Sanctioned', data: series('sanctioned'), borderColor: '#10b981', backgroundColor: '#10b98122', tension: .3, fill: true },
    { label: 'Shadow (unapproved)', data: series('unsanctioned'), borderColor: '#f43f5e', backgroundColor: '#f43f5e22', tension: .3, fill: true },
    { label: 'Under review', data: series('under_review'), borderColor: '#f59e0b', tension: .3 }] }, options: { maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } } });
  chart('cRisk', { type: 'doughnut', data: { labels: ['Low', 'Medium', 'High', 'Critical'], datasets: [{ data: ['Low', 'Medium', 'High', 'Critical'].map(l => d.risk_distribution[l]), backgroundColor: ['#10b981', '#22d3ee', '#f59e0b', '#f43f5e'], borderWidth: 0 }] }, options: { maintainAspectRatio: false, cutout: '68%', plugins: { legend: { display: false } } } });
}

/* ---------------- Inventory ---------------- */
async function inventory() {
  const { services } = await api('GET', 'services'); S.services = services;
  const w = can('inventory.write'), quad = S.quad; S.quad = null;
  const inv = services.filter(x => x.in_inventory), registryOnly = services.length - inv.length;
  $('#view').innerHTML = pageHead('<i class="fa-solid fa-list-check text-info"></i> AI Asset Inventory Register (ISO/IEC 42001 cl. 8.2)', 'Every AI service known to this company, with approval status, ownership, data class and risk',
    (w ? '<button class="btn btn-sm btn-outline-info" id="bAdd"><i class="fa-solid fa-plus"></i> Register AI System</button><button class="btn btn-sm btn-outline-secondary" id="bRecalc"><i class="fa-solid fa-arrows-rotate"></i> Recalculate risk</button>' : '') +
    '<a class="btn btn-sm btn-outline-secondary" href="' + dl('export/inventory') + '"><i class="fa-solid fa-file-arrow-down"></i> Export all (CSV)</a>') + DISCLAIMER + `<div class="small text-secondary mb-3"><i class="fa-solid fa-radar me-1 text-info"></i> Services with <b>detected usage</b> (found by collectors) or <b>entered by your team</b>. ${registryOnly ? `${registryOnly} more known AI services are listed only in <a href="#registry">AI Services &amp; DNS Registry</a> until they are detected or adopted.` : ''}</div>
    <div class="card"><div id="invGrid"></div></div>`;
  const base = quad ? inv.filter(s => inQuad(s, quad)) : inv;
  const rows = base;
  if (quad) toast('Filtered by risk quadrant. Reload this tab to clear.', 'info');
  const reload = () => { S.services = null; inventory(); };
  new DataGrid({ el: '#invGrid', id: 'inventory', rows, empty: 'No AI services detected or registered yet. Collectors add services here when they see them; check Domain Discovery for unregistered hostnames, or use Register AI System.', exportName: 'ai-inventory', sort: { key: 'risk', dir: 'desc' }, onRowClick: r => openService(r.id),
    rowClass: r => +r.active ? '' : 'opacity-50',
    columns: [
      { key: 'service_name', label: 'AI application', filter: 'text', text: r => `${r.service_name} ${r.domains.map(d => d.domain).join(' ')}`, sort: r => r.service_name,
        render: r => `<div class="fw-semibold text-white">${E(r.service_name)}</div><div class="mono small text-secondary">${E(r.primary_domain)}${r.domains.length > 1 ? ' +' + (r.domains.length - 1) : ''}</div>` },
      { key: 'provider', label: 'Vendor', filter: 'select' },
      { key: 'status', label: 'Status', filter: 'select', text: r => CLASSES[r.sanction_status] || r.sanction_status, render: r => statusPill(r.sanction_status) },
      { key: 'risk', label: 'Risk', filter: 'select', text: r => r.risk_level, sort: r => +r.risk_score, num: true, render: r => riskPill(r.risk_level, r.risk_score) },
      { key: 'data_class', label: 'Data class', filter: 'select', render: r => dcPill(r.data_class) },
      { key: 'owner', label: 'Owner', filter: 'select' },
      { key: 'workstations_30d', label: 'Workst. (30d)', num: true },
      { key: 'events_30d', label: 'Events (30d)', num: true, render: r => fmtN(r.events_30d) },
      { key: 'last_seen', label: 'Last observed (local time)', nowrap: true, render: r => `<span class="small">${fmtDT(r.last_seen)}</span>` },
      { key: 'active', label: 'Registry', filter: 'select', text: r => +r.active ? 'Active' : 'Inactive', render: r => +r.active ? 'Active' : '<span class="text-secondary">Inactive</span>' }],
    actions: r => [{ inline: true, key: 'open', label: 'View', icon: 'fa-eye' }].concat(w ? [{ inline: true, key: 'edit', label: 'Edit', icon: 'fa-pen' }] : [], can('inventory.delete') ? [{ inline: true, key: 'delete', label: 'Delete service', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, r) => { if (k === 'open' || k === 'edit') openService(r.id); else if (k === 'delete' && await deleteServices([r])) reload(); },
    bulk: w ? [{ label: 'Set classification', icon: 'fa-tags', fn: rs => bulkClassify(rs, reload) }].concat(can('inventory.delete') ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await deleteServices(rs)) reload(); } }] : []) : null });
  if ($('#bAdd')) $('#bAdd').onclick = addServiceModal;
  if ($('#bRecalc')) $('#bRecalc').onclick = () => act(async () => { const r = await api('POST', 'risk/recalculate'); toast(`Risk recalculated for ${r.updated} services`, 'success'); inventory(); });
}

/** Shared by Inventory and Registry: delete services after showing the impact. */
const deleteServices = rs => deleteFlow({ path: 'services/delete', ids: rs.map(r => +r.id), title: rs.length > 1 ? `Delete ${rs.length} AI services` : 'Delete AI service',
  describe: i => `<p class="small mb-0">Also removes <b>${fmtN(i.domains)}</b> registry domain(s) and <b>${fmtN(i.events + i.network_events)}</b> collected event(s) recorded against ${i.records > 1 ? 'them' : 'it'}. Collectors stop watching these domains on their next sync. To keep the history, set the classification to <b>Excluded</b> or archive the service instead.</p>`, done: 'Service deleted' });

function addServiceModal() {
  const m = modal('Register AI System', `<div class="row g-2">
    <div class="col-md-6"><label class="form-label small">Service name *</label><input id="n_name" class="form-control form-control-sm"></div>
    <div class="col-md-6"><label class="form-label small">Vendor / provider</label><input id="n_prov" class="form-control form-control-sm"></div>
    <div class="col-md-6"><label class="form-label small">Primary domain * <span class="text-secondary">(e.g. claude.ai)</span></label><input id="n_dom" class="form-control form-control-sm"></div>
    <div class="col-md-6"><label class="form-label small">Data class</label><select id="n_dc" class="form-select form-select-sm"><option>Public</option><option selected>Internal</option><option>Confidential</option><option>Restricted / PII</option></select></div>
    <div class="col-12"><label class="form-label small">Owner</label><input id="n_owner" class="form-control form-control-sm" placeholder="Unassigned"></div>
    <div class="col-12"><label class="form-label small">Business purpose</label><textarea id="n_pur" rows="2" class="form-control form-control-sm"></textarea></div></div>
    <div class="small text-secondary mt-2">New systems start as Shadow (unapproved) until sanctioned. Do not register a broad shared domain like github.com.</div>`,
    '<button class="btn btn-info btn-sm" id="n_save">Register</button>');
  $('#n_save', m.el).onclick = () => act(async () => {
    await api('POST', 'services', { service_name: $('#n_name', m.el).value, provider: $('#n_prov', m.el).value, primary_domain: $('#n_dom', m.el).value, data_class: $('#n_dc', m.el).value, owner: $('#n_owner', m.el).value, purpose: $('#n_pur', m.el).value });
    m.close(); toast('AI system registered', 'success'); inventory();
  });
}

/* governance record modal (ISO 42001 cl. 8.2 documentation) */
async function openService(id, after) {
  let s = (S.services || []).find(x => x.id == id);
  if (!s) { S.services = (await api('GET', 'services')).services; s = S.services.find(x => x.id == id); }
  if (!s) return;
  const w = can('inventory.write'), dis = w ? '' : 'disabled';
  const life = ['Shadow Usage Detected', 'Under Security Evaluation', 'Formally Sanctioned', 'Decommissioned']; if (!life.includes(s.lifecycle)) life.push(s.lifecycle);
  const rng = (id2, label, v) => `<div class="col-md-4"><label class="form-label small">${label} <b id="${id2}v">${v}</b></label><input type="range" class="form-range" id="${id2}" min="0" max="100" value="${v}" ${dis}></div>`;
  const m = modal(`${E(s.service_name)} <span class="small text-secondary">${E(s.provider)}</span>`, `
    <div class="row g-2 mono mb-3 text-center">
      <div class="col-6 col-md-3"><div class="card p-2"><div class="small text-secondary">STATUS</div>${statusPill(s.sanction_status)}</div></div>
      <div class="col-6 col-md-3"><div class="card p-2"><div class="small text-secondary">RISK</div>${riskPill(s.risk_level, s.risk_score)}</div></div>
      <div class="col-6 col-md-3"><button type="button" class="card p-2 w-100 tile-btn" data-go="tpWs" title="Show the computers this service was detected on"><div class="small text-secondary">WORKSTATIONS (30d) <i class="fa-solid fa-arrow-right-long"></i></div><b class="text-white">${s.workstations_30d}</b></button></div>
      <div class="col-6 col-md-3"><button type="button" class="card p-2 w-100 tile-btn" data-go="tpEv" title="Open the event log"><div class="small text-secondary">OBSERVED DNS EVENTS <i class="fa-solid fa-arrow-right-long"></i></div><b class="text-white">${fmtN(s.events_30d)}</b></button></div></div>
    <ul class="nav nav-tabs mb-3" role="tablist">
      <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tpGov" type="button" role="tab"><i class="fa-solid fa-sliders me-1"></i> Governance record</button></li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#tpWs" type="button" role="tab"><i class="fa-solid fa-desktop me-1"></i> Workstations</button></li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#tpEv" type="button" role="tab"><i class="fa-solid fa-list me-1"></i> Event log</button></li></ul>
    <div class="tab-content"><div class="tab-pane fade show active" id="tpGov">
    <div class="row g-2">
      <div class="col-md-6"><label class="form-label small">Designated system owner</label><input id="g_owner" class="form-control form-control-sm" value="${E(s.owner)}" ${dis}></div>
      <div class="col-md-6"><label class="form-label small">Lifecycle state</label><select id="g_life" class="form-select form-select-sm" ${dis}>${life.map(l => `<option ${l === s.lifecycle ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="col-12"><label class="form-label small">Intended business purpose &amp; scope</label><textarea id="g_pur" rows="2" class="form-control form-control-sm" ${dis}>${E(s.purpose)}</textarea></div>
      <div class="col-md-6"><label class="form-label small">Data categories processed</label><input id="g_cats" class="form-control form-control-sm" value="${E(s.data_categories)}" ${dis}></div>
      <div class="col-md-6"><label class="form-label small">Data classification</label><select id="g_dc" class="form-select form-select-sm" ${dis}>${['Public', 'Internal', 'Confidential', 'Restricted / PII'].map(c => `<option ${c === s.data_class ? 'selected' : ''}>${c}</option>`).join('')}</select></div>
      ${rng('g_tr', 'Model-training exposure', s.training_exposure)}${rng('g_vr', 'Vendor risk', s.vendor_risk)}${rng('g_ir', 'Identity / auth risk', s.identity_risk)}
      <div class="col-12"><label class="form-label small">Domains (one per line; subdomains match automatically)</label><textarea id="g_dom" rows="3" class="form-control form-control-sm mono" ${dis}>${E(s.domains.map(d => d.domain).join('\n'))}</textarea></div>
      <div class="col-md-6"><label class="form-label small">Provider</label><input id="g_prov" class="form-control form-control-sm" value="${E(s.provider)}" ${dis}></div>
      <div class="col-md-3"><label class="form-label small">Category</label><input id="g_cat" class="form-control form-control-sm" value="${E(s.category)}" ${dis}></div>
      <div class="col-md-3"><label class="form-label small">Registry</label><select id="g_act" class="form-select form-select-sm" ${dis}><option value="1" ${+s.active ? 'selected' : ''}>Active</option><option value="0" ${+s.active ? '' : 'selected'}>Inactive</option></select></div></div></div><div class="tab-pane fade" id="tpWs"><div id="svcWs"></div></div><div class="tab-pane fade" id="tpEv"><div id="svcEv"></div></div></div>`,
    w ? `<button class="btn btn-success btn-sm" id="g_sanc">Sanction tool</button><button class="btn btn-info btn-sm" id="g_save">Save governance record</button>` : '', 'modal-lg');
  ['g_tr', 'g_vr', 'g_ir'].forEach(i => { const el = $('#' + i, m.el); el.oninput = () => $('#' + i + 'v', m.el).textContent = el.value; });
  // Detected usage: which computers, and the consolidated event log behind the counts.
  const tab = pane => $(`[data-bs-target="#${pane}"]`, m.el), foot = m.el.querySelector('.modal-footer');
  let evComputer = null;
  const showEvents = computer => { evComputer = computer; const t = bootstrap.Tab.getOrCreateInstance(tab('tpEv')); if (tab('tpEv').classList.contains('active')) loadEv(); else t.show(); };
  const loadWs = () => serviceWorkstationsPanel($('#svcWs', m.el), id, { onEvents: showEvents, onOpen: r => wsHistory(r.computer_name, r) }).catch(e => toast(e.message, 'danger'));
  const loadEv = () => activityPanel($('#svcEv', m.el), { serviceId: id, computer: evComputer, onClear: () => { evComputer = null; loadEv(); } }).catch(e => toast(e.message, 'danger'));
  tab('tpWs').addEventListener('shown.bs.tab', loadWs);
  tab('tpEv').addEventListener('shown.bs.tab', loadEv);
  m.el.querySelectorAll('[data-bs-toggle="tab"]').forEach(t => t.addEventListener('shown.bs.tab', e => { if (foot) foot.style.display = e.target.dataset.bsTarget === '#tpGov' ? '' : 'none'; }));
  m.el.querySelectorAll('[data-go]').forEach(b => b.onclick = () => { if (b.dataset.go === 'tpEv') evComputer = null; bootstrap.Tab.getOrCreateInstance(tab(b.dataset.go)).show(); });
  if (S.openServiceTab) { const x = S.openServiceTab; S.openServiceTab = null; m.el.addEventListener('shown.bs.modal', () => bootstrap.Tab.getOrCreateInstance(tab(x)).show()); }
  if (!w) return;
  const send = (extra = {}) => act(async () => {
    await api('POST', 'services/' + id, Object.assign({
      owner: $('#g_owner', m.el).value, purpose: $('#g_pur', m.el).value, data_categories: $('#g_cats', m.el).value, data_class: $('#g_dc', m.el).value, lifecycle: $('#g_life', m.el).value,
      training_exposure: +$('#g_tr', m.el).value, vendor_risk: +$('#g_vr', m.el).value, identity_risk: +$('#g_ir', m.el).value, provider: $('#g_prov', m.el).value, category: $('#g_cat', m.el).value,
      active: $('#g_act', m.el).value === '1', domains: $('#g_dom', m.el).value.split('\n').map(x => x.trim()).filter(Boolean)
    }, extra));
    m.close(); toast('Governance record saved', 'success'); S.services = null; (after || route)();
  });
  $('#g_save', m.el).onclick = () => send();
  $('#g_sanc', m.el).onclick = () => send({ lifecycle: 'Formally Sanctioned' });
}

/* ---------------- Risk matrix & engine ---------------- */
const inQuad = (s, q) => ((s.data_sensitivity >= 60) ? 'High' : 'Low') + 'Data-' + ((+s.usage_volume >= 40) ? 'High' : 'Low') + 'Exp' === q;
async function risk() {
  const { services: allSvc } = await api('GET', 'services'); S.services = allSvc; const services = allSvc.filter(x => x.in_inventory);
  const act1 = services.filter(s => +s.active);
  const Q = [['LowData-HighExp', 'BROAD CONSUMPTION', 'Medium Risk', 'info', 'Internal/public data &bull; high usage'], ['HighData-HighExp', 'CRITICAL EXPOSURE ZONE', 'Critical', 'danger', 'Sensitive data &bull; high usage'],
             ['LowData-LowExp', 'LOW RISK / CONTAINED', 'Low Risk', 'success', 'Internal/public data &bull; low usage'], ['HighData-LowExp', 'SENSITIVE PILOTS', 'High Risk', 'warning', 'Sensitive data &bull; low usage']];
  const cnt = q => act1.filter(s => inQuad(s, q)).length;
  S.selRisk = S.selRisk && act1.find(s => s.id == S.selRisk) ? S.selRisk : (act1[0] || {}).id;
  $('#view').innerHTML = pageHead('SAIP 4-Quadrant Risk &amp; Exposure Matrix', 'Data sensitivity (X) vs observed usage exposure (Y). Usage = 10 per workstation + 1 per 20 DNS events (30 days)') + `
  <div class="row g-3"><div class="col-lg-7"><div class="card p-3"><div class="row g-3">${Q.map(([k, t, l, c, d]) => `<div class="col-6"><div class="quad border-${c} clickable" data-q="${k}">
      <div class="d-flex justify-content-between"><b class="text-${c}" style="font-size:.72rem">${t}</b><span class="pill p-${{ info: 'info', danger: 'bad', success: 'ok', warning: 'warn' }[c]}">${l}</span></div>
      <div class="n text-${c}">${cnt(k)}</div><div class="small text-secondary text-center">${d}</div></div></div>`).join('')}</div>
    <div class="small text-secondary text-center mt-2">Click a quadrant to filter the inventory. Data sensitivity &ge; Confidential counts as high.</div></div></div>
  <div class="col-lg-5"><div class="card p-3 h-100" id="engine"></div></div></div>
  <div class="card p-3 mt-3"><h6 class="text-white">Assets (select to inspect)</h6><div id="assetList" class="d-flex flex-wrap gap-2"></div></div>`;
  document.querySelectorAll('[data-q]').forEach(el => el.onclick = () => { S.quad = el.dataset.q; location.hash = '#inventory'; });
  $('#assetList').innerHTML = act1.map(s => `<button class="btn btn-sm ${s.id == S.selRisk ? 'btn-info' : 'btn-outline-secondary'}" data-a="${s.id}">${E(s.service_name)} <span class="mono">${s.risk_score}</span></button>`).join('');
  document.querySelectorAll('[data-a]').forEach(b => b.onclick = () => { S.selRisk = +b.dataset.a; risk(); });
  const s = act1.find(x => x.id == S.selRisk);
  if (!s) { $('#engine').innerHTML = '<div class="text-secondary">No assets.</div>'; return; }
  const F = [['Data sensitivity (' + E(s.data_class) + ')', s.data_sensitivity, 30, '#f43f5e'], ['Model-training exposure', s.training_exposure, 20, '#fb7185'], ['Vendor trust &amp; security posture', s.vendor_risk, 20, '#f59e0b'], ['Identity &amp; authentication', s.identity_risk, 15, '#22d3ee'], ['Usage volume (observed)', s.usage_volume, 15, '#06b6d4']];
  const col = { Critical: '#f43f5e', High: '#f59e0b', Medium: '#22d3ee', Low: '#10b981' }[s.risk_level];
  $('#engine').innerHTML = `<div class="d-flex justify-content-between mb-2"><h6 class="text-white mb-0">SAIP Quantitative Risk Engine</h6><span class="pill p-info">${E(s.service_name)}</span></div>
    <div class="d-flex align-items-center gap-3 p-3 mb-3 rounded" style="background:var(--surface)"><div style="font:700 2rem Poppins,sans-serif;color:${col}">${s.risk_score}</div><div><div class="mono fw-bold" style="color:${col}">${s.risk_level.toUpperCase()} THREAT BAND</div><div class="small">${statusPill(s.sanction_status)} ${E(s.lifecycle)}</div></div></div>
    ${F.map(([n, v, wt, c]) => `<div class="factor mb-2"><div class="d-flex justify-content-between small"><span>${n} <span class="text-secondary">&times;${wt}%</span></span><b class="mono" style="color:${c}">${v}/100</b></div><div class="bar"><div style="width:${v}%;background:${c}"></div></div></div>`).join('')}
    <div class="d-flex justify-content-between align-items-center mt-3 pt-2 border-top border-secondary-subtle"><span class="small text-secondary mono">Score = weighted average of the five factors</span>
    ${can('inventory.write') ? '<button class="btn btn-sm btn-outline-info" id="rcalc"><i class="fa-solid fa-arrows-rotate"></i> Recalculate</button>' : ''}</div>`;
  if ($('#rcalc')) $('#rcalc').onclick = () => act(async () => { await api('POST', 'risk/recalculate'); toast('Risk recalculated from latest telemetry', 'success'); risk(); });
}

/* ---------------- Workstations ---------------- */
async function workstations() {
  const { workstations: rows } = await api('GET', 'workstations');
  const w = can('workstations.write'), dlt = can('collectors.delete');
  const csPill = s => ({ authorized: 'p-ok', pending: 'p-warn', suspended: 'p-mute', revoked: 'p-bad' }[s] || 'p-mute');
  $('#view').innerHTML = pageHead('Workstation AI Activity', 'Per-computer observed AI DNS events (last 30 days). Computer name is the identifier; no Windows usernames are collected.') + DISCLAIMER + '<div class="card"><div id="wsGrid"></div></div>';
  const edit = r => formModal({ title: `Edit ${r.computer_name}`, icon: 'fa-desktop', values: r, note: 'Department mapping groups this workstation in adoption analytics. The computer name comes from the collector and cannot be edited.',
    fields: [{ name: 'computer_name', label: 'Computer', readonly: true, col: 12 }, { name: 'department', label: 'Department', col: 6, maxlength: 100 }, { name: 'business_unit', label: 'Business unit', col: 6, maxlength: 100 }, { name: 'employee_reference', label: 'Employee / asset reference', maxlength: 100 }],
    save: v => api('POST', 'workstations/map', v), done: () => { toast('Workstation updated', 'success'); workstations(); } });
  new DataGrid({ el: '#wsGrid', id: 'workstations', rows, rowKey: 'collector_id', exportName: 'workstations', sort: { key: 'events_30d', dir: 'desc' }, onRowClick: r => wsHistory(r.computer_name, r),
    columns: [
      { key: 'computer_name', label: 'Computer', filter: 'text', render: r => `<span class="fw-semibold text-white">${E(r.computer_name)}</span>` },
      { key: 'mac_address', label: 'MAC', render: r => `<span class="mono small">${E(r.mac_address) || '-'}</span>` },
      { key: 'department', label: 'Department', filter: 'select', text: r => r.department || 'Unmapped', render: r => E(r.department) || '<span class="text-secondary">unmapped</span>' },
      { key: 'collector_status', label: 'Collector', filter: 'select', render: r => `<span class="pill ${csPill(r.collector_status)}">${E(r.collector_status).toUpperCase()}</span>` },
      { key: 'services_30d', label: 'AI services', num: true },
      { key: 'events_30d', label: 'Events', num: true, render: r => fmtN(r.events_30d) },
      { key: 'shadow_events_30d', label: 'Shadow events', num: true, render: r => fmtN(r.shadow_events_30d) },
      { key: 'active_days_30d', label: 'Active days', num: true },
      { key: 'first_seen', label: 'First', nowrap: true, render: r => `<span class="small">${fmtDT(r.first_seen)}</span>` },
      { key: 'last_event', label: 'Last', nowrap: true, render: r => `<span class="small">${fmtDT(r.last_event)}</span>` }],
    actions: r => [{ inline: true, key: 'history', label: 'View history', icon: 'fa-eye' }, { inline: true, key: 'events', label: 'View event log', icon: 'fa-list' }].concat(w ? [{ inline: true, key: 'edit', label: 'Edit mapping', icon: 'fa-pen' }] : [], dlt ? [{ key: 'clear', label: 'Clear collected data', icon: 'fa-eraser' }, { inline: true, key: 'delete', label: 'Delete workstation', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, r) => { if (k === 'history') wsHistory(r.computer_name, r); else if (k === 'events') openComputerEvents(r.computer_name); else if (k === 'edit') edit(r); else if (await deleteCollectors([r], k === 'clear')) workstations(); },
    bulk: dlt ? [{ label: 'Clear collected data', icon: 'fa-eraser', fn: async rs => { if (await deleteCollectors(rs, true)) workstations(); } }, { label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await deleteCollectors(rs, false)) workstations(); } }] : null });
}

/** Shared by Workstations and Collectors. Rows may carry collector_id (workstations) or id (collectors). */
const deleteCollectors = (rs, dataOnly) => deleteFlow({ path: 'collectors/delete', ids: rs.map(r => +(r.collector_id ?? r.id)), extra: { data_only: dataOnly },
  title: dataOnly ? `Clear collected data for ${rs.length} workstation${rs.length > 1 ? 's' : ''}` : (rs.length > 1 ? `Delete ${rs.length} workstations` : 'Delete workstation'),
  intro: dataOnly ? '<p class="small">The collector stays registered and keeps reporting; only the events it already sent are removed.</p>' : '',
  describe: i => `<p class="small mb-0">Removes <b>${fmtN(i.events)}</b> DNS event(s)${i.network_events ? `, <b>${fmtN(i.network_events)}</b> connection event(s)` : ''}${dataOnly ? '' : `, <b>${fmtN(i.heartbeats)}</b> heartbeat(s), the department mapping and discovery hits for ${i.records > 1 ? 'these computers' : 'this computer'}`}.${dataOnly ? '' : ' <b>Uninstall the collector on the workstation first</b>: if it is still running it will re-register (and, if auto-authorize is on, start reporting again).'}</p>`,
  button: dataOnly ? 'Clear data' : 'Delete permanently', done: dataOnly ? 'Collected data cleared' : 'Workstation deleted' });

async function wsHistory(name, row) {
  const h = await api('GET', 'workstations/history?name=' + encodeURIComponent(name));
  const m = modal(`${E(name)} &mdash; historical activity`, `${DISCLAIMER}
    <div class="btn-group btn-group-sm mb-2" id="gran"><button class="btn btn-info" data-g="day">Daily</button><button class="btn btn-outline-info" data-g="week">Weekly</button><button class="btn btn-outline-info" data-g="month">Monthly</button></div>
    <div style="height:230px"><canvas id="cWs"></canvas></div>
    <h6 class="text-white mt-3">By AI service</h6><div id="wsSvc" class="small"></div>
    <h6 class="text-white mt-3 mb-2">Event log</h6><div id="wsEvents"></div>
    `, '', 'modal-xl');
  const bucket = (d, g) => { const dt = new Date(d + 'T00:00:00Z'); if (g === 'month') return d.slice(0, 7); if (g === 'week') { const x = new Date(dt); x.setUTCDate(x.getUTCDate() - ((x.getUTCDay() + 6) % 7)); return x.toISOString().slice(0, 10); } return d; };
  const draw = g => {
    const keys = [...new Set(h.daily.map(r => bucket(r.d, g)))].sort(); const svcs = [...new Set(h.daily.map(r => r.service))];
    const pal = ['#22d3ee', '#f43f5e', '#10b981', '#f59e0b', '#8b5cf6', '#06b6d4', '#fb7185', '#a3e635'];
    chart('cWs', { type: 'bar', data: { labels: keys, datasets: svcs.map((sv, i) => ({ label: sv, backgroundColor: pal[i % pal.length], data: keys.map(k => h.daily.filter(r => r.service === sv && bucket(r.d, g) === k).reduce((a, r) => a + +r.c, 0)) })) }, options: { maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true } }, plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } } } });
  };
  const tot = {}; h.daily.forEach(r => tot[r.service] = (tot[r.service] || 0) + +r.c);
  $('#wsSvc', m.el).innerHTML = Object.entries(tot).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<span class="pill p-info me-1">${E(k)}: ${fmtN(v)}</span>`).join('') || '<span class="text-secondary">No observed activity.</span>';
  activityPanel($('#wsEvents', m.el), { computer: name }).catch(e => toast(e.message, 'danger'));
  m.el.addEventListener('shown.bs.modal', () => draw('day'));
  $('#gran', m.el).onclick = e => { const g = e.target.dataset.g; if (!g) return; document.querySelectorAll('#gran button').forEach(b => b.className = 'btn ' + (b === e.target ? 'btn-info' : 'btn-outline-info')); draw(g); };
}

/* ---------------- Getting started guide ---------------- */
async function guide() {
  const base = location.origin + BASE + '/api/v1';
  const lab = base.startsWith('http://') ? ' -AllowInsecureHttp' : '';   // plain http only works in a lab
  const step = (n, t, body) => `<div class="d-flex gap-3 mb-3"><div class="avatar" style="width:32px;height:32px;flex-basis:32px;border:0">${n}</div><div><div class="fw-semibold text-white">${t}</div><div class="small">${body}</div></div></div>`;
  const sec = (id, icon, title, body) => `<div class="card p-4 mb-3" id="g-${id}"><h5 class="mb-3"><i class="fa-solid ${icon} text-info me-2"></i>${title}</h5>${body}</div>`;
  const feat = (icon, name, where, text) => `<div class="col-md-6"><div class="p-3 h-100 rounded" style="background:var(--surface)"><div class="fw-semibold text-white"><i class="fa-solid ${icon} text-info me-2"></i>${name} <span class="pill p-vio ms-1">${where}</span></div><div class="small mt-1">${text}</div></div></div>`;
  const code = c => `<pre class="feed" style="color:#1f2340">${E(c)}</pre>`;
  const toc = [['what', 'What it is'], ['how', 'How it works'], ['features', 'Feature tour'], ['start', 'Quick start'], ['collect', 'Install the collector'], ['daily', 'Day-to-day use'], ['admin', 'Administration'], ['numbers', 'Reading the numbers'], ['trouble', 'Troubleshooting']];
  $('#view').innerHTML = `
  <div class="card p-4 mb-3" style="background:linear-gradient(90deg,#fff,#eef0ff)"><span class="pill p-vio mb-2" style="width:fit-content">GETTING STARTED</span>
    <h4 class="mb-1">Shadow AI Platform</h4><div class="text-secondary">Find out which AI tools your people reach from company Windows workstations, decide which are approved, manage the risk, and track your ISO/IEC 42001 readiness &mdash; one company at a time.</div>
    <div class="d-flex flex-wrap gap-2 mt-3">${toc.map(([id, t]) => `<button class="btn btn-sm btn-outline-info" data-go="g-${id}">${t}</button>`).join('')}</div></div>

  ${sec('what', 'fa-lightbulb', 'What it is', `<p>Staff increasingly use AI tools (ChatGPT, Claude, Gemini, Copilot, Perplexity and many more) without IT knowing. This platform gives management visibility and a governance workflow:</p>
    <ul class="mb-2"><li><b>Discover</b> which AI services are reached, from which workstations and how often.</li><li><b>Classify</b> each service as <span class="pill p-ok">Sanctioned</span>, <span class="pill p-warn">Under review</span> or <span class="pill p-bad">Shadow (unapproved)</span>.</li>
    <li><b>Score risk</b> per service and see where sensitive data meets heavy use.</li><li><b>Govern</b> with policies, an access-request queue, owners and lifecycle states.</li><li><b>Evidence</b> ISO/IEC 42001 controls and produce a readiness report.</li><li><b>Enable</b> people: adoption analytics show where training would help.</li></ul>
    <div class="disclaimer"><b>It is a reporting tool.</b> It does not block traffic, intercept content, or record prompts, passwords, keystrokes, browser contents or Windows usernames. Any blocking is done by your own firewall or resolver, outside SAIP.</div>`)}

  ${sec('how', 'fa-diagram-project', 'How it works', `<div class="row g-3 text-center mb-2">
      ${[['fa-desktop', '1. Workstation', 'Microsoft Sysmon logs DNS lookups (Event ID 22) in the Windows event log.'], ['fa-terminal', '2. Collector', 'A PowerShell task runs every 5 minutes, keeps only lookups for AI domains in your register, and sends them over HTTP(S).'], ['fa-server', '3. Server', 'The PHP API authenticates the collector, ignores duplicates, matches the domain to a service and stores it in MariaDB.'], ['fa-chart-line', '4. Console', 'This console turns the data into dashboards, risk scores, adoption analytics and compliance evidence.']]
        .map(([i, t, d]) => `<div class="col-md-3"><div class="p-3 h-100 rounded" style="background:var(--surface)"><i class="fa-solid ${i} fa-lg text-info mb-2"></i><div class="fw-semibold text-white">${t}</div><div class="small">${d}</div></div></div>`).join('')}</div>
    <p class="small mb-1"><b>Companies (tenants).</b> One installation serves many companies. Each has its own AI register, collectors, telemetry, policies, ISO register, audit log and users, and cannot see the others' data.</p>
    <p class="small mb-0"><b>Unknown domains.</b> AI-looking hostnames that are not in the register go to <a href="#discovery">Domain Discovery</a>. They are never counted as AI usage until you add them.</p>`)}

  ${sec('features', 'fa-table-cells-large', 'Feature tour', `<div class="row g-3">
      ${feat('fa-gauge-high', 'Executive Dashboard', 'overview', 'KPI cards, 30-day trend by approval status, risk distribution and the shadow AI awaiting review.')}
      ${feat('fa-microscope', 'AI Fleet Inventory', 'register', 'Every AI service with status, risk, data class, owner and activity. Open <i>Manage</i> to set owner, purpose, lifecycle, domains and risk factors. Export to CSV.')}
      ${feat('fa-cubes-stacked', 'Risk Matrix &amp; Engine', 'risk', 'Four quadrants (data sensitivity vs usage) and a transparent 0-100 score: data class 30%, training exposure 20%, vendor risk 20%, identity risk 15%, observed usage 15%.')}
      ${feat('fa-desktop', 'Workstations', 'activity', 'Per-computer activity with daily, weekly and monthly history. Map each computer to a department.')}
      ${feat('fa-seedling', 'AI Adoption', 'analytics', 'None / Low / Moderate / High per workstation and department, trends, an enablement list, and editable thresholds. For training, not for judging individuals.')}
      ${feat('fa-magnifying-glass-chart', 'Domain Discovery', 'triage', 'New AI-looking domains found by collectors. Add to the register (as Shadow) or dismiss.')}
      ${feat('fa-scale-balanced', 'Governance &amp; Requests', 'policy', 'Policy catalogue and the staff request queue. Approving a request adds the tool to the register as Sanctioned.')}
      ${feat('fa-shield-halved', 'ISO 42001 Readiness', 'compliance', 'Annex A control register: compliant or not, with evidence, readiness score and tier, a printable report and an evidence export.')}
      ${feat('fa-satellite-dish', 'Collectors &amp; Monitoring', 'operations', 'Authorize, suspend, revoke, rotate and delete collectors; set what is collected; open <i>Sysmon capabilities</i> for the events read, the JSON sent and a Sysmon config builder.')}
      ${feat('fa-sitemap', 'FQDNs &amp; registrars', 'registry', 'Second tab of AI Services &amp; DNS Registry: every hostname with its service, root domain, DNS registrar and purpose. Add, edit, import (CSV) or delete in modals.')}
      ${feat('fa-plug', 'SIEM &amp; Webhooks', 'operations', 'Send audit events, shadow-AI alerts and discovered domains to Splunk, syslog (CEF/JSON) or signed webhooks, or let your SIEM pull them with an API token.')}
      ${feat('fa-key', 'Authentication &amp; users', 'admin', 'Sign in with Google or a password, four roles (platform admin, IT admin, auditor, viewer) and full user management. Every change is in the audit log.')}</div>`)}

  ${sec('start', 'fa-rocket', 'Quick start (about 15 minutes)', `
    ${step(1, 'Sign in and check your company', 'The company name is shown at the bottom of the sidebar (platform administrators pick it from the selector). A new company starts with a catalogue of common AI services, all treated as <b>Shadow</b> until you approve them, plus the 14 ISO 42001 controls (all <b>not compliant</b> until assessed).')}
    ${step(2, 'Decide what is approved', 'Open <a href="#inventory">AI Fleet Inventory</a>. For each tool your company allows, click <b>Manage → Sanction tool</b>. Add any missing tool with <b>Register AI System</b>. Anything left as Shadow is reported as unapproved.')}
    ${step(3, 'Give services an owner and a data class', 'In <i>Manage</i> set the owner, purpose, data classification and the three risk sliders. This drives the risk score and the ISO 42001 asset record.')}
    ${step(4, 'Install the collector on a pilot workstation', 'Follow <a href="#" data-go="g-collect">Install the collector on workstations</a> below: one command (<code>Install-Collector.ps1</code>) installs Sysmon, enrolls the PC and schedules the collector. Start with one or two machines and confirm events arrive before rolling out.')}
    ${step(5, 'Map computers to departments', 'In <a href="#workstations">Workstations</a> open a computer and save its department. Adoption and department comparisons depend on this.')}
    ${step(6, 'Work through the ISO 42001 register', 'In <a href="#iso">ISO 42001 Readiness</a> mark a control compliant only when you can record its evidence. The score and tier update as you go.')}`)}

  ${sec('collect', 'fa-satellite-dish', 'Install the collector on workstations', `
    <p class="small">SAIP learns which AI services are used from <b>Sysmon</b>, a free Microsoft Sysinternals service that records DNS lookups on Windows. A small PowerShell <b>collector</b> reads the new Sysmon events, keeps only hostnames that match this company's registry (the rules are downloaded from SAIP, none are hard-coded), and sends them here as JSON. It never reads page content, prompts, passwords, keystrokes or Windows user names. Open <a href="#collectors">Collectors &amp; Monitoring &rarr; Sysmon capabilities</a> to see exactly which Sysmon events are read and the JSON that is sent.</p>
    <div class="table-responsive mb-3"><table class="table table-sm small mb-0"><thead><tr><th style="width:28%">Requirement</th><th>Detail</th></tr></thead><tbody>
      <tr><td>Workstation</td><td>Windows 10/11 (or Server 2016+), PowerShell 5.1 or later, local <b>Administrator</b> rights.</td></tr>
      <tr><td>Network</td><td>The PC must reach the SAIP server address (test it in a browser). From other PCs the address cannot be <code>127.0.0.1</code>/<code>localhost</code>: use the server's name or IP and allow its port in the firewall. Use HTTPS in production.</td></tr>
      <tr><td>Sysmon download</td><td>Internet access to <code>live.sysinternals.com</code>, <b>or</b> copy <code>Sysmon64.exe</code> into the collector folder beforehand (offline PCs).</td></tr>
      <tr><td>Clock</td><td>Keep Windows time in sync; event times come from the PC.</td></tr></tbody></table></div>

    <h6 class="text-white mt-3">A. Prepare once (on an administrator PC)</h6>
    ${step(1, 'Get the enrollment key', 'Go to <a href="#collectors">Collectors &amp; Monitoring &rarr; New enrollment key</a>. It is shown once. It only enrolls PCs into this company; each PC then receives its own private key.')}
    ${step(2, 'Note the server address', 'This server&rsquo;s API address is: <code>' + E(base) + '</code>. Replace the host with the name or IP that workstations can reach if it differs.')}
    ${step(3, 'Download the package', 'On <a href="#collectors">Collectors &amp; Monitoring</a> click <b>Download collector package</b>. You get <code>SaipCollector.zip</code> with all scripts and the Sysmon configurations, and <code>collector.config.json</code> already holding this server&rsquo;s address (edit it if workstations reach the server by a different name or IP). It never contains the enrollment key. Copy the zip to a protected share, USB stick or software-distribution package.')}

    <h6 class="text-white mt-3">B. Install on one workstation (one command)</h6>
    <p class="small">Pilot first: install on one or two PCs and confirm events arrive before rolling out wider. On the target workstation: copy <code>SaipCollector.zip</code> to it, right-click &rarr; <b>Extract All</b> (e.g. to <code>C:\Temp\SaipCollector</code>), open <b>PowerShell as Administrator</b>, go to the extracted folder (<code>cd C:\Temp\SaipCollector</code>) and run:</p>
    ${code('Set-ExecutionPolicy -Scope Process Bypass -Force\n.\\Install-Collector.ps1 -ServerUrl ' + base + ' -EnrollmentKey <your-enrollment-key>' + lab)}
    <p class="small">For a lab with plain <code>http://</code>, add <code>-AllowInsecureHttp</code>. The installer is hands-off and does seven things, then prints a pass/fail summary table: (1) copies the collector to <code>C:\\Tools\\SaipCollector</code>; (2) writes and protects the configuration; (3) checks the server is reachable; (4) installs or repairs <b>Sysmon</b> and <b>proves it works</b> by recording a test lookup (it reloads or reinstalls Sysmon automatically if it is not logging); (5) sets the <b>browser DNS policy</b> so Chrome, Edge, Brave and Firefox lookups are visible, with no manual registry or browser settings; (6) enrolls the PC and runs the collector once; (7) schedules it every 5 minutes as SYSTEM. It is safe to run again: it repairs and updates.</p>
    <div class="row g-2 small mb-2"><div class="col-md-6"><div class="p-2 rounded" style="background:var(--surface)"><b class="text-white">Options</b><br><code>-SkipSysmon</code> Sysmon already installed &middot; <code>-SkipBrowserPolicy</code> leave browser settings alone &middot; <code>-RestartBrowsers</code> close open browsers so the policy applies now (unsaved browser work is lost; default is to apply at the next browser start) &middot; <code>-EnableNetwork</code> also log network connections &middot; <code>-IntervalMinutes N</code></div></div>
      <div class="col-md-6"><div class="p-2 rounded" style="background:var(--surface)"><b class="text-white">If the summary shows ATTENTION</b><br>Read the detail, fix it and run the same command again. If Sysmon reports a file in use, restart Windows first. To see what browsers looked up: <code>C:\\Tools\\SaipCollector\\Show-SysmonDns.ps1 -Match 'chrome|msedge'</code></div></div></div>

    <h6 class="text-white mt-3">C. Or install step by step</h6>
    ${step(1, 'Edit <code>collector.config.json</code>', 'Set <code>serverUrl</code> and <code>enrollmentKey</code>. Keep <code>allowInsecureHttp: true</code> only in a lab.')}
    ${step(2, 'Install Sysmon (elevated PowerShell)', 'Downloads Sysmon from Microsoft if missing and applies the DNS-only configuration with a 64 MB log.' + code('.\\Install-Sysmon.ps1'))}
    ${step(3, 'Run the collector once', 'Test without sending anything, then run it for real (this enrolls the PC).' + code('.\\Collect-AiUsage.ps1 -DryRun -Verbose\n.\\Collect-AiUsage.ps1'))}
    ${step(4, 'Schedule it', 'Creates the task <code>SAIP-AI-Usage-Collector</code> that runs as SYSTEM.' + code('.\\Register-ScheduledTask.ps1 -IntervalMinutes 5'))}

    <h6 class="text-white mt-3">Browsers that bypass Windows DNS (Chrome/Edge)</h6>
    <p class="small">Sysmon DNS events only cover lookups that go through the Windows DNS client. Chrome and Edge often use their own resolver or encrypted DNS, so sites opened in a browser can be missed while apps such as the Claude app are seen. The installer covers this for you (option 2); option 1 is an optional extra:</p>
    <div class="row g-3 small mb-2">
      <div class="col-lg-6"><div class="p-3 h-100 rounded" style="background:var(--surface)"><b class="text-white">1. Network connections (optional extra)</b>
        <div class="mt-1">Turn on <i>Network connections</i> in <a href="#collectors">Collectors &rarr; Monitoring options</a>, then switch Sysmon to log outbound HTTPS connections (one change per PC, or add <code>-EnableNetwork</code> to <code>Install-Collector.ps1</code>):</div>${code('.\\Install-Sysmon.ps1 -EnableNetwork')}
        <div>SAIP matches a connection by host name when Sysmon has one, otherwise by the destination address of a registered service (refresh the list under Collectors &rarr; Network connection matching; schedule <code>tools\\refresh-ip-map.php</code> hourly). <b>Limit:</b> addresses behind shared CDNs (Cloudflare, Google, CloudFront, Akamai, Fastly) cannot show which site was visited and are ignored. ChatGPT (Cloudflare) and Gemini (Google) are in that group, so browser visits to them are <b>not</b> detected this way.</div></div></div>
      <div class="col-lg-6"><div class="p-3 h-100 rounded" style="background:var(--surface)"><b class="text-white">2. Browser DNS policy (reliable for any site) &mdash; done by the installer</b>
        <div class="mt-1"><code>Install-Collector.ps1</code> now sets this automatically, with no manual registry or browser clicks. It makes the browsers use the Windows DNS client so their lookups appear as DNS events:</div>${code('Chrome / Edge / Brave:  BuiltInDnsClientEnabled = 0,  DnsOverHttpsMode = off\nFirefox:                DNSOverHTTPS  Enabled = 0, Locked = 1')}
        <div>It applies the next time the browser starts (fully quit and reopen it, or use <code>-RestartBrowsers</code>). Add <code>-SkipBrowserPolicy</code> to leave browser settings untouched. The previous values are saved and <code>Uninstall-Collector.ps1</code> restores them. The policies show under <code>edge://policy</code> and <code>chrome://policy</code>.</div></div></div></div>

    <h6 class="text-white mt-3">D. Roll out to many workstations</h6>
    <div class="row g-3 small mb-2">
      <div class="col-lg-4"><div class="p-3 h-100 rounded" style="background:var(--surface)"><b class="text-white">PowerShell remoting</b><div class="mt-1">From an administrator PC (WinRM enabled):</div>${code("foreach ($pc in 'PC01','PC02') {\n  Copy-Item .\\collector \"\\\\$pc\\C$\\Tools\\SaipCollector\" -Recurse -Force\n  Invoke-Command -ComputerName $pc -ScriptBlock {\n    & C:\\Tools\\SaipCollector\\Install-Collector.ps1 -ServerUrl '" + base + "' -EnrollmentKey '<key>'" + lab + "\n  }\n}")}</div></div>
      <div class="col-lg-4"><div class="p-3 h-100 rounded" style="background:var(--surface)"><b class="text-white">Group Policy</b><div class="mt-1">Computer Configuration &rarr; Windows Settings &rarr; Scripts &rarr; <b>Startup</b> &rarr; PowerShell Scripts. Point it at <code>Install-Collector.ps1</code> on a share readable only by <i>Domain Computers</i>, with the parameters above. It runs as SYSTEM and is safe to repeat at each start.</div></div></div>
      <div class="col-lg-4"><div class="p-3 h-100 rounded" style="background:var(--surface)"><b class="text-white">Intune / SCCM / other tools</b><div class="mt-1">Package the folder and run as SYSTEM, 64-bit:</div>${code('powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-Collector.ps1 -ServerUrl <url> -EnrollmentKey <key>')}<div>Detection: the scheduled task <code>SAIP-AI-Usage-Collector</code> exists. Uninstall: <code>Uninstall-Collector.ps1 -RemoveSysmon -RemoveData</code>.</div></div></div></div>
    <p class="small text-warning"><i class="fa-solid fa-triangle-exclamation me-1"></i>A script that contains the enrollment key must not be world-readable. After rollout, rotate it (<b>New enrollment key</b>): installed collectors keep working, and the old key stops enrolling new PCs.</p>

    <h6 class="text-white mt-3">E. Authorize and verify</h6>
    ${step(1, 'Check the Collectors page', 'Each PC appears within a minute. Lab setups authorize automatically; otherwise click <b>Authorize</b> on a <span class="pill p-warn">PENDING</span> collector. Only authorized collectors can send data. A healthy collector shows <span class="pill p-ok">HEALTHY</span>, a recent <i>Last seen</i> and the current <i>Config</i> version.')}
    ${step(2, 'Generate some activity', 'On the PC open an AI site such as <code>chatgpt.com</code>, then force a run without waiting:' + code("Start-ScheduledTask -TaskName 'SAIP-AI-Usage-Collector'"))}
    ${step(3, 'See it in SAIP', 'The service appears in <a href="#inventory">AI Fleet Inventory</a> (Discovered in use) and the PC in <a href="#workstations">Workstations</a>; open either to see the event log. Hostnames that look like AI but are not in the registry appear in <a href="#discovery">Domain Discovery</a>.')}

    <h6 class="text-white mt-3">F. Keep it running</h6>
    <ul class="small mb-2"><li><b>Change what is collected</b> under Collectors &rarr; Monitoring options (network connections, discovery, interval). It reaches every PC on its next sync; no reinstall. Network connections (Event ID 3) also need the Sysmon config updated: build it under <i>Sysmon capabilities &rarr; Config builder</i> and apply with <code>Sysmon64.exe -c sysmon-config.xml</code>.</li>
      <li><b>Updates:</b> copy the new collector folder and run <code>Install-Collector.ps1</code> again. The registry rules update centrally; nothing to redeploy.</li>
      <li><b>Server unreachable:</b> events are buffered in <code>C:\\ProgramData\\SaipCollector\\spool</code> and sent in order when it returns. <i>Spool</i> and <i>Failures</i> on the Collectors page show a backlog.</li>
      <li><b>Credentials:</b> <i>Rotate API key</i>, <i>Suspend</i> or <i>Revoke</i> a collector from its row. A rotated key is applied on the PC with <code>Collect-AiUsage.ps1 -SetApiKey &lt;key&gt;</code>.</li>
      <li><b>Remove a PC:</b> run <code>.\\Uninstall-Collector.ps1</code> (add <code>-RemoveSysmon -RemoveData</code> for everything) and then delete or revoke the collector in SAIP. A deleted collector that is still installed will try to enroll again.</li></ul>
    <p class="small mb-0"><b>Local files:</b> <code>C:\\ProgramData\\SaipCollector</code> holds the checkpoint (nothing is sent twice), the protected API key, the cached rules and <code>collector-error.log</code>.</p>`)}

  ${sec('daily', 'fa-calendar-check', 'Day-to-day use', `<div class="row g-3 small">
      <div class="col-md-6"><div class="fw-semibold text-white mb-1">Weekly review (IT / security)</div><ol class="mb-0"><li>Check the dashboard for new Shadow AI with recent activity.</li><li>Clear <a href="#discovery">Domain Discovery</a>: add real AI tools, dismiss noise.</li><li>Decide on each shadow tool: <b>Sanction</b>, <b>Under review</b>, or leave it <b>Unsanctioned</b> (the platform reports; it does not block).</li><li>Handle the <a href="#governance">request queue</a>.</li><li>Confirm all collectors are online.</li></ol></div>
      <div class="col-md-6"><div class="fw-semibold text-white mb-1">Monthly review (management)</div><ol class="mb-0"><li>Read <a href="#adoption">AI Adoption</a>: which departments need training or enablement?</li><li>Review the risk matrix for sensitive-data tools with high usage.</li><li>Update ISO 42001 controls and evidence; export the readiness report.</li><li>Export the inventory CSV, or a report from <a href="#reports">Reports &amp; Analytics</a> (CSV or Excel), for governance meetings.</li></ol></div></div>`)}

  ${sec('admin', 'fa-user-gear', 'Basic administration', `<div class="row g-3 small">
      <div class="col-md-6"><div class="fw-semibold text-white mb-1">Roles</div><table class="table table-sm"><tbody>
        <tr><td><span class="pill p-vio">Super Administrator</span></td><td>Everything, across all companies: create companies, users, switch company.</td></tr>
        <tr><td><span class="pill p-info">IT Administrator</span></td><td>Manage one company: register, governance, collectors, thresholds, ISO controls.</td></tr>
        <tr><td><span class="pill p-mute">Management Viewer</span></td><td>Read dashboards and reports and export; cannot change anything.</td></tr></tbody></table></div>
      <div class="col-md-6"><div class="fw-semibold text-white mb-1">Common tasks</div><ul class="mb-0">
        <li><b>Add a customer:</b> <a href="#platform">Companies &amp; Users → New company</a>; give its enrollment key to whoever installs collectors.</li>
        <li><b>Add a user:</b> same page → New user (12+ character password, role, company).</li>
        <li><b>Rotate a collector key:</b> Collectors → Rotate key; apply with <code>Collect-AiUsage.ps1 -SetApiKey &lt;key&gt;</code>.</li>
        <li><b>Lost or retired PC:</b> Collectors → Suspend or Revoke.</li>
        <li><b>New enrollment key:</b> Collectors → New enrollment key (invalidates the old one for new registrations).</li>
        <li><b>Tune adoption:</b> AI Adoption → Thresholds.</li>
        <li><b>Who changed what:</b> <a href="#audit">Audit Log</a>.</li></ul></div></div>
    <div class="disclaimer mt-3"><b>Before going live:</b> use HTTPS, turn off <code>auto_authorize</code>, use a dedicated database user instead of <code>root</code>, delete <code>config/initial-admin.txt</code>, never expose phpMyAdmin or MariaDB to the internet, and back up the database.</div>`)}

  ${sec('numbers', 'fa-scale-unbalanced', 'Reading the numbers correctly', `<ul class="small mb-0">
      <li><b>Counts are observed DNS lookups, not sessions or time spent.</b> Browsers can look up names in the background, so one lookup does not prove someone used the tool.</li>
      <li><b>Low activity does not mean low AI use.</b> Personal devices, phones, cached or encrypted (DNS-over-HTTPS) lookups, and tools not in the register are not seen.</li>
      <li><b>Shared domains are excluded on purpose.</b> <code>github.com</code>, <code>microsoft.com</code> and <code>google.com</code> carry mostly non-AI traffic, so only AI-specific hostnames (for example <code>api.githubcopilot.com</code>) are registered.</li>
      <li><b>No people are identified.</b> Reporting is by computer name; the optional department mapping is yours to maintain.</li>
      <li><b>The ISO 42001 view is a self-assessment</b> that helps you prepare. It is not a certification.</li></ul>`)}

  ${sec('trouble', 'fa-wrench', 'Troubleshooting', `<div class="table-responsive"><table class="table table-sm small mb-0"><thead><tr><th style="width:34%">Symptom</th><th>Check</th></tr></thead><tbody>
      <tr><td>Collector not listed</td><td>Open <code>collector-error.log</code>. Confirm <code>serverUrl</code> is reachable from the PC (open it in a browser) and the enrollment key is current.</td></tr>
      <tr><td>Install fails: cannot reach the server</td><td>From another PC the address cannot be <code>127.0.0.1</code>/<code>localhost</code>. Use the server's name or IP, allow its port in the firewall, and check proxy settings. Open the <code>serverUrl</code> in a browser on that PC.</td></tr>
      <tr><td>Sysmon download blocked / PC offline</td><td>Copy <code>Sysmon64.exe</code> into the collector folder before running <code>Install-Collector.ps1</code>.</td></tr>
      <tr><td>"Running scripts is disabled"</td><td>Start with <code>Set-ExecutionPolicy -Scope Process Bypass -Force</code> in the same elevated window, or run <code>powershell -ExecutionPolicy Bypass -File ...</code>.</td></tr>
      <tr><td>Events have wrong times</td><td>Fix Windows time synchronisation; event times come from the PC.</td></tr>
      <tr><td>Listed as PENDING</td><td>An administrator must <b>Authorize</b> it in Collectors.</td></tr>
      <tr><td>Apps are detected but browser visits are not</td><td>The browser bypasses the Windows DNS client. See <i>Browsers that bypass Windows DNS</i> above: network connections (partial) or the optional browser DNS policy.</td></tr>
      <tr><td>Registered but no events</td><td>Confirm Sysmon is running and EID 22 events exist: <code>Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5</code>. Visit an AI site to generate lookups.</td></tr>
      <tr><td>"409 already registered"</td><td>The local state was deleted. Revoke the old collector entry and re-enroll, or rotate its key and use <code>-SetApiKey</code>.</td></tr>
      <tr><td>401 / 403 errors</td><td>Key rotated or revoked, or the collector is suspended. Check its status in Collectors.</td></tr>
      <tr><td>A site is not counted</td><td>Its domain is not in the register. Check Domain Discovery, or add the domain under Inventory → Manage.</td></tr>
      <tr><td>Too many requests (429)</td><td>Rate limit hit; wait a minute. Sign-in is also limited to 10 attempts per minute.</td></tr></tbody></table></div>`)}
  `;
  document.querySelectorAll('[data-go]').forEach(b => b.onclick = () => document.getElementById(b.dataset.go).scrollIntoView({ behavior: 'smooth', block: 'start' }));
}

/* ---------------- AI adoption analytics ---------------- */
async function adoption() {
  const d = await api('GET', 'adoption'); const s = d.settings, sm = d.summary;
  const LC = { None: '#64748b', Low: '#f59e0b', Moderate: '#22d3ee', High: '#10b981' };
  const lvlPill = l => `<span class="pill" style="color:${LC[l]};border-color:${LC[l]}66;background:${LC[l]}22">${l.toUpperCase()}</span>`;
  const opp = d.workstations.filter(w => w.level === 'None' || w.level === 'Low');
  const card = (label, val, sub, c) => `<div class="col-6 col-xl"><div class="card kpi h-100" style="--c:${c}"><div class="small text-secondary">${label}</div><div class="v">${val}</div><div class="small text-secondary">${sub}</div></div></div>`;
  $('#view').innerHTML = pageHead('<i class="fa-solid fa-seedling text-success"></i> AI Adoption Analytics', `Observed activity over the last ${s.adopt_window_days} days, to target training and enablement &mdash; not to evaluate individuals`,
    '<a class="btn btn-sm btn-outline-secondary" href="' + dl('export/adoption') + '"><i class="fa-solid fa-file-arrow-down"></i> Export CSV</a>' + (can('adoption.write') ? '<button class="btn btn-sm btn-outline-info" id="aTh"><i class="fa-solid fa-sliders"></i> Thresholds</button>' : '')) + `
  <div class="disclaimer mb-3"><i class="fa-solid fa-circle-info me-1"></i> This measures <b>observed DNS activity</b> on monitored Windows workstations. <b>Low observed activity does not necessarily mean low actual AI usage</b> (personal devices, cached or encrypted DNS, unlisted tools). Use it to offer training and enablement, not to penalise employees.</div>
  <div class="row g-3 mb-3">
    ${card('Workstations monitored', fmtN(sm.monitored), 'Authorized collectors', 'var(--cyan)')}
    ${card('With observed AI activity', sm.active_pct + '%', `${sm.monitored - sm.levels.None} of ${sm.monitored}`, 'var(--ok)')}
    ${card('Average adoption score', sm.avg_score, 'Scale 0-100', 'var(--vio)')}
    ${card('Enablement opportunities', fmtN(opp.length), 'None or Low observed activity', 'var(--warn)')}
    ${card('High adopters', fmtN(sm.levels.High), 'Candidates for peer champions', 'var(--ok)')}</div>
  <div class="row g-3 mb-3">
    <div class="col-lg-4"><div class="card p-3 h-100"><h6 class="text-white">Adoption levels</h6><div style="height:210px"><canvas id="cLvl"></canvas></div></div></div>
    <div class="col-lg-8"><div class="card p-3 h-100"><h6 class="text-white">Department comparison</h6><div style="height:210px"><canvas id="cDept"></canvas></div></div></div></div>
  <div class="row g-3 mb-3">
    <div class="col-lg-6"><div class="card p-3 h-100"><h6 class="text-white">Weekly: workstations with AI activity (12 weeks)</h6><div style="height:210px"><canvas id="cWk"></canvas></div></div></div>
    <div class="col-lg-6"><div class="card p-3 h-100"><h6 class="text-white">Monthly adoption: active workstations (6 months)</h6><div style="height:210px"><canvas id="cMo"></canvas></div></div></div></div>
  <div class="card mb-3"><div class="p-3 pb-0"><h6 class="text-white">Department summary</h6></div><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Department</th><th>Workstations</th><th>Avg score</th><th>% with activity</th><th>None</th><th>Low</th><th>Moderate</th><th>High</th><th>Sanctioned share of events</th></tr></thead><tbody>
  ${d.departments.map(x => `<tr><td class="fw-semibold text-white">${E(x.department)}</td><td>${x.workstations}</td><td><b>${x.avg_score}</b></td><td>${x.active_pct}%</td><td>${x.None}</td><td>${x.Low}</td><td>${x.Moderate}</td><td>${x.High}</td><td>${x.sanctioned_pct == null ? '-' : x.sanctioned_pct + '%'}</td></tr>`).join('') || '<tr><td colspan="9" class="text-center text-secondary py-3">No authorized collectors yet.</td></tr>'}</tbody></table></div></div>
  <div class="card"><div class="p-3 pb-0 d-flex flex-wrap justify-content-between"><h6 class="text-white">Workstation adoption <span class="text-secondary small">(score = active days 40 + AI services 20 + event frequency 25 + sanctioned-service activity 15)</span></h6>
    <select id="lvlF" class="form-select form-select-sm w-auto"><option value="">All levels</option><option value="opp">Enablement opportunities (None + Low)</option><option>None</option><option>Low</option><option>Moderate</option><option>High</option></select></div>
  <div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>Computer</th><th>Department</th><th>Level</th><th>Score</th><th>Active days</th><th>AI services</th><th>Observed DNS events</th><th>Sanctioned-service events</th><th>Last observed (local time)</th></tr></thead><tbody id="aBody"></tbody></table></div></div>`;
  const draw = () => { const f = $('#lvlF').value; $('#aBody').innerHTML = d.workstations.filter(w => !f || (f === 'opp' ? (w.level === 'None' || w.level === 'Low') : w.level === f)).sort((a, b) => a.score - b.score)
    .map(w => `<tr><td class="fw-semibold text-white">${E(w.computer_name)}</td><td>${E(w.department)}</td><td>${lvlPill(w.level)}</td><td><div class="d-flex align-items-center gap-2"><b class="mono">${w.score}</b><div class="progress flex-grow-1" style="height:5px;min-width:60px"><div class="progress-bar" style="width:${w.score}%;background:${LC[w.level]}"></div></div></div></td><td>${w.active_days}</td><td>${w.services}</td><td>${fmtN(w.events)}</td><td>${fmtN(w.sanctioned_events)}</td><td class="small">${fmtDT(w.last_event)}</td></tr>`).join('') || '<tr><td colspan="9" class="text-center text-secondary py-3">No workstations in this view.</td></tr>'; };
  $('#lvlF').onchange = draw; draw();
  const L = ['None', 'Low', 'Moderate', 'High'];
  chart('cLvl', { type: 'doughnut', data: { labels: L, datasets: [{ data: L.map(l => sm.levels[l]), backgroundColor: L.map(l => LC[l]), borderWidth: 0 }] }, options: { maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } } } });
  chart('cDept', { type: 'bar', data: { labels: d.departments.map(x => x.department), datasets: L.map(l => ({ label: l, backgroundColor: LC[l], data: d.departments.map(x => x[l]) })) }, options: { maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true, ticks: { precision: 0 } } }, plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } } } });
  chart('cWk', { type: 'line', data: { labels: d.weekly.map(w => w.week_start), datasets: [{ label: 'Active workstations', data: d.weekly.map(w => +w.active_workstations), borderColor: '#22d3ee', backgroundColor: '#22d3ee22', fill: true, tension: .3 }] }, options: { maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } } } });
  chart('cMo', { type: 'bar', data: { labels: d.monthly.map(m => m.month), datasets: [{ label: 'Active workstations', data: d.monthly.map(m => +m.active_workstations), backgroundColor: '#10b981' }] }, options: { maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } } } });
  if ($('#aTh')) $('#aTh').onclick = () => {
    const F = [['adopt_window_days', 'Look-back window (days)'], ['adopt_days_target', 'Active days for full points (of 40)'], ['adopt_services_target', 'Distinct AI services for full points (of 20)'], ['adopt_events_target', 'Observed events for full points (of 25)'], ['adopt_sanctioned_target', 'Sanctioned-service events for full points (of 15)'], ['adopt_low_max', 'Low if score below'], ['adopt_high_min', 'High if score at or above']];
    const m = modal('Adoption thresholds', `<p class="small text-secondary">None = zero observed events. Low &lt; Low ceiling &le; Moderate &lt; High threshold &le; High. Targets decide how quickly each component reaches its full points.</p>
      ${F.map(([k, l]) => `<div class="row g-2 mb-2 align-items-center"><div class="col-8 small">${l}</div><div class="col-4"><input type="number" class="form-control form-control-sm" data-k="${k}" value="${s[k]}"></div></div>`).join('')}`, '<button class="btn btn-info btn-sm" id="aSave">Save thresholds</button>');
    $('#aSave', m.el).onclick = () => act(async () => { const b = {}; m.el.querySelectorAll('[data-k]').forEach(i => b[i.dataset.k] = +i.value); await api('POST', 'adoption/settings', b); m.close(); toast('Thresholds saved', 'success'); adoption(); });
  };
}

/* ---------------- Governance & requests ---------------- */
async function governance() {
  const [{ policies }, { requests }] = await Promise.all([api('GET', 'policies'), api('GET', 'requests')]);
  const w = can('governance.write'), d = can('governance.delete');
  const PS = ['Enforced', 'Draft', 'Disabled'];
  const polPill = s => `<span class="pill ${{ Enforced: 'p-ok', Draft: 'p-warn', Disabled: 'p-mute' }[s] || 'p-mute'}">${E(s).toUpperCase()}</span>`;
  const rqPill = s => `<span class="pill ${{ pending: 'p-warn', approved: 'p-ok', rejected: 'p-bad' }[s]}">${E(s).toUpperCase()}</span>`;
  $('#view').innerHTML = pageHead('Governance &amp; Requests', 'AI usage policies and the staff access-request queue for this company') + `
  <div class="card mb-3"><div class="d-flex flex-wrap justify-content-between align-items-center p-3 pb-0"><h6 class="text-white mb-0"><i class="fa-solid fa-scale-balanced me-2 text-info"></i>Enterprise AI policies &amp; baselines</h6>${w ? addBtn('Add policy', 'pAdd') : ''}</div><div id="polGrid"></div></div>
  <div class="card"><div class="d-flex flex-wrap justify-content-between align-items-center p-3 pb-0"><h6 class="text-white mb-0"><i class="fa-solid fa-inbox me-2 text-info"></i>Staff AI access requests <span class="pill p-warn ms-2">${requests.filter(r => r.status === 'pending').length} pending</span></h6>${w ? addBtn('New request', 'rAdd') : ''}</div><div id="reqGrid"></div></div>`;
  const policyForm = p => formModal({ title: p ? 'Edit policy' : 'Add policy', icon: 'fa-scale-balanced', values: p || { status: 'Draft', policy_type: 'General' },
    fields: [{ name: 'name', label: 'Policy name', required: true, maxlength: 150 }, { name: 'policy_type', label: 'Type', col: 6, maxlength: 60 }, { name: 'status', label: 'Status', type: 'select', options: PS, col: 6 }, { name: 'description', label: 'Description', type: 'textarea', maxlength: 500 }],
    save: v => api('POST', p ? 'policies/' + p.id : 'policies', v), done: () => { toast('Policy saved', 'success'); governance(); } });
  const requestForm = r => formModal({ title: r ? 'Edit request' : 'New access request', icon: 'fa-inbox', values: r || { data_class: 'Internal' },
    fields: [{ name: 'tool_name', label: 'AI tool', required: true, maxlength: 150, col: 6 }, { name: 'domain', label: 'Domain', placeholder: 'tool.example.com', col: 6, mono: true }, { name: 'requester', label: 'Requester', required: true, maxlength: 150, col: 6 },
      { name: 'data_class', label: 'Data class', type: 'select', options: ['Public', 'Internal', 'Confidential', 'Restricted / PII'], col: 6 }, { name: 'justification', label: 'Business justification', type: 'textarea', required: true, maxlength: 500 }],
    save: v => api('POST', r ? 'requests/' + r.id : 'requests', v), done: () => { toast('Request saved', 'success'); governance(); } });
  const decide = (r, decision) => act(async () => {
    try { await api('POST', `requests/${r.id}/decide`, { decision }); toast(decision === 'approve' ? 'Approved and added to the AI register as Sanctioned' : 'Request rejected', 'success'); governance(); }
    catch (e) {
      if (e.code !== 'domain_required') throw e;
      formModal({ title: 'Service domain', icon: 'fa-globe', note: 'This tool is not in the register yet. Enter its domain so collectors can recognise it.', fields: [{ name: 'domain', label: 'Domain', required: true, mono: true, placeholder: 'tool.example.com' }], submit: 'Approve',
        save: v => api('POST', `requests/${r.id}/decide`, { decision, domain: v.domain }), done: () => { toast('Approved and added to the AI register', 'success'); governance(); } });
    } });
  const del = (path, rs, title) => deleteFlow({ path, ids: rs.map(x => +x.id), title, describe: () => '', done: 'Deleted' });
  new DataGrid({ el: '#polGrid', id: 'policies', rows: policies, exportName: 'policies', sort: { key: 'name', dir: 'asc' },
    columns: [{ key: 'name', label: 'Policy', filter: 'text', render: p => `<b>${E(p.name)}</b>` }, { key: 'policy_type', label: 'Type', filter: 'select' }, { key: 'status', label: 'Status', filter: 'select', render: p => polPill(p.status) }, { key: 'description', label: 'Description', render: p => `<span class="small text-secondary">${E(p.description || '')}</span>` }],
    actions: p => [{ inline: true, key: 'view', label: 'View', icon: 'fa-eye' }].concat(w ? [{ inline: true, key: 'edit', label: 'Edit', icon: 'fa-pen' }] : [], d ? [{ inline: true, key: 'delete', label: 'Delete', icon: 'fa-trash', danger: true }] : []),
    onRowClick: p => policyForm(p),
    onAction: async (k, p) => { if (k === 'delete') { if (await del('policies/delete', [p], 'Delete policy')) governance(); } else policyForm(p); },
    bulk: d ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await del('policies/delete', rs, `Delete ${rs.length} policies`)) governance(); } }] : null });
  new DataGrid({ el: '#reqGrid', id: 'requests', rows: requests, exportName: 'access-requests', sort: { key: 'created_at', dir: 'desc' },
    columns: [{ key: 'tool_name', label: 'AI tool', filter: 'text', render: r => `<b>${E(r.tool_name)}</b><div class="small mono text-secondary">${E(r.domain || '')}</div>`, text: r => `${r.tool_name} ${r.domain || ''}` }, { key: 'requester', label: 'Requester', filter: 'text' }, { key: 'data_class', label: 'Data class', filter: 'select', render: r => dcPill(r.data_class) },
      { key: 'status', label: 'Status', filter: 'select', render: r => rqPill(r.status) }, { key: 'created_at', label: 'Requested', nowrap: true, render: r => `<span class="small">${fmtDT(r.created_at)}</span>` }, { key: 'justification', label: 'Justification', render: r => `<span class="small text-secondary">${E(r.justification)}</span>` }],
    actions: r => (r.status === 'pending' && w ? [{ inline: true, key: 'approve', label: 'Approve', icon: 'fa-check' }, { inline: true, key: 'reject', label: 'Reject', icon: 'fa-xmark' }, { inline: true, key: 'edit', label: 'Edit', icon: 'fa-pen' }] : [{ inline: true, key: 'view', label: 'View', icon: 'fa-eye' }]).concat(d ? [{ inline: true, key: 'delete', label: 'Delete', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, r) => { if (k === 'approve') decide(r, 'approve'); else if (k === 'reject') decide(r, 'reject'); else if (k === 'delete') { if (await del('requests/delete', [r], 'Delete request')) governance(); } else requestForm(r); },
    bulk: d ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await del('requests/delete', rs, `Delete ${rs.length} requests`)) governance(); } }] : null });
  if ($('#pAdd')) $('#pAdd').onclick = () => policyForm(null);
  if ($('#rAdd')) $('#rAdd').onclick = () => requestForm(null);
}

/* ---------------- ISO/IEC 42001 hub ---------------- */
async function iso() {
  const d = await api('GET', 'iso'); $('#bIso').textContent = d.score + '%';
  const groups = {}; d.controls.forEach(c => (groups[c.domain] ||= []).push(c));
  $('#view').innerHTML = `<div class="card p-3 mb-3 d-flex flex-column flex-md-row justify-content-between gap-3" style="background:linear-gradient(90deg,#fff,#eef0ff)"><div>
      <span class="pill p-ok">ISO/IEC 42001:2023 AIMS</span> <span class="pill p-info">ANNEX A CONTROL REGISTER</span><h5 class="text-white mt-2 mb-1">ISO 42001 Organizational Readiness &amp; Audit Evidence Hub</h5>
      <div class="small">Self-assessed register: each control is marked compliant only with recorded evidence, and every change is audit-logged. This is a readiness aid, not a certification.</div></div>
    <div class="d-flex gap-2 align-items-start"><button class="btn btn-success btn-sm" id="bRep"><i class="fa-solid fa-file-shield"></i> Readiness report</button><a class="btn btn-outline-secondary btn-sm" href="${dl('export/iso')}">Export evidence JSON</a></div></div>
  <div class="card p-3 mb-3"><div class="d-flex flex-wrap justify-content-between align-items-center gap-3"><div class="d-flex align-items-center gap-3"><div style="font:700 2.4rem Poppins,sans-serif" class="text-success">${d.score}%</div>
    <div><div class="fw-bold text-white">${E(d.tier)}</div><div class="small text-secondary">${E(d.tier_desc)}</div></div></div>
    <div style="min-width:240px"><div class="small mono d-flex justify-content-between"><span>Compliant controls</span><b class="text-white">${d.passed} of ${d.total}</b></div><div class="progress" style="height:8px"><div class="progress-bar bg-success" style="width:${d.score}%"></div></div></div></div></div>
  ${Object.entries(groups).map(([g, cs]) => `<div class="card p-3 mb-2"><div class="mono small text-info fw-bold mb-2">${E(g)}</div>${cs.map(c => `<div class="d-flex align-items-start gap-3 py-2 border-top border-secondary-subtle">
      <div class="form-check form-switch pt-1"><input class="form-check-input" type="checkbox" data-c="${c.id}" ${+c.compliant ? 'checked' : ''} ${can('iso.write') ? '' : 'disabled'}></div>
      <div class="flex-grow-1"><div class="fw-semibold text-white">${E(c.name)} <span class="pill ${+c.compliant ? 'p-ok' : 'p-bad'}">${+c.compliant ? 'COMPLIANT' : 'NOT COMPLIANT'}</span></div><div class="small text-secondary">${E(c.description)}</div>
      <div class="small mono mt-1">Evidence: ${c.evidence ? E(c.evidence) : '<span class="text-warning">none recorded</span>'}${c.notes ? ' &middot; ' + E(c.notes) : ''}${c.updated_at ? ` <span class="text-secondary">(${fmtDT(c.updated_at)} by ${E(c.updated_by)})</span>` : ''}</div></div>
      ${can('iso.write') ? `<button class="btn btn-sm btn-outline-secondary" data-e="${c.id}">Evidence</button>` : ''}</div>`).join('')}</div>`).join('')}
  <div class="card p-3 mt-3"><h6 class="text-white">Documented governance records (generated from live platform data)</h6><div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Standard reference</th><th>Artifact</th><th>Source</th><th>Last updated (local time)</th><th>Status</th></tr></thead><tbody>
  ${d.evidence.map(e => `<tr><td class="mono text-info">${E(e.standard_ref)}</td><td>${E(e.artifact)}</td><td class="small mono">${E(e.source)}</td><td class="small">${fmtDT(e.verified_at)}</td><td><span class="pill ${e.status === 'VERIFIED' ? 'p-ok' : 'p-warn'}">${e.status}</span></td></tr>`).join('')}</tbody></table></div></div>`;
  const edit = (c, wantOn) => { const m = modal(E(c.name), `<label class="form-label small">Evidence (what proves this control?) ${wantOn ? '*' : ''}</label><input id="e_ev" class="form-control form-control-sm mb-2" value="${E(c.evidence)}"><label class="form-label small">Notes</label><textarea id="e_no" rows="2" class="form-control form-control-sm">${E(c.notes)}</textarea>
      <div class="form-check form-switch mt-3"><input class="form-check-input" type="checkbox" id="e_ok" ${wantOn || +c.compliant ? 'checked' : ''}><label class="form-check-label" for="e_ok">Control is compliant</label></div>`, '<button class="btn btn-info btn-sm" id="e_save">Save</button>');
    m.el.addEventListener('hidden.bs.modal', () => iso());
    $('#e_save', m.el).onclick = () => act(async () => { await api('POST', 'iso/controls/' + c.id, { compliant: $('#e_ok', m.el).checked, evidence: $('#e_ev', m.el).value, notes: $('#e_no', m.el).value }); m.close(); toast('Control updated', 'success'); }); };
  document.querySelectorAll('[data-e]').forEach(b => b.onclick = () => edit(d.controls.find(c => c.id == b.dataset.e), false));
  document.querySelectorAll('[data-c]').forEach(cb => cb.onchange = () => { const c = d.controls.find(x => x.id == cb.dataset.c); if (cb.checked) { cb.checked = false; edit(c, true); } else act(async () => { await api('POST', 'iso/controls/' + c.id, { compliant: false }); iso(); }); });
  $('#bRep').onclick = () => report(d);
}

async function report(d) {
  const dash = await api('GET', 'dashboard'); const k = dash.kpi; const gaps = d.controls.filter(c => !+c.compliant);
  const html = `<h2>AI Governance &amp; ISO/IEC 42001 Readiness Report</h2><p>${E(S.me.tenant?.name)} &middot; generated ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC</p>
    <h3>1. Executive summary</h3><p>The platform records <b>${k.total_services}</b> AI services, of which <b>${k.shadow}</b> (${k.shadow_ratio}%) are unapproved (Shadow). ${dash.telemetry.workstations} workstations showed AI-related DNS activity in the last 30 days (${fmtN(dash.telemetry.events)} observed DNS events &mdash; telemetry, not verified sessions). Readiness is <b>${d.score}%</b> (${E(d.tier)}): ${d.passed} of ${d.total} controls recorded as compliant with evidence. This is a self-assessment, not a certification.</p>
    <h3>2. Statement of applicability &amp; control status</h3><table><tr><th>Domain</th><th>Control</th><th>Status</th><th>Evidence</th></tr>${d.controls.map(c => `<tr><td>${E(c.domain)}</td><td>${E(c.name)}</td><td>${+c.compliant ? 'Compliant' : 'NOT compliant'}</td><td>${E(c.evidence) || '-'}</td></tr>`).join('')}</table>
    <h3>3. Corrective actions (open gaps)</h3>${gaps.length ? '<ul>' + gaps.map(c => `<li><b>${E(c.name)}</b> (${E(c.domain)}) &mdash; ${E(c.description)}</li>`).join('') + '</ul>' : '<p>No open gaps recorded.</p>'}
    <h3>4. Unapproved AI requiring decision</h3><ul>${(dash.recent_shadow.length ? dash.recent_shadow : []).map(s => `<li>${E(s.service_name)} &mdash; risk ${s.risk_score} (${s.risk_level}), ${s.workstations_30d} workstation(s)</li>`).join('') || '<li>None with recent activity.</li>'}</ul>
    <p style="margin-top:24px;font-size:11px">Sign-off: CISO / Compliance Officer &nbsp; ______________________</p>`;
  const m = modal('Readiness report', `<div class="bg-white text-dark p-4 rounded" id="repBody" style="font-size:.85rem">${html}</div>`, '<button class="btn btn-success btn-sm" id="repPrint"><i class="fa-solid fa-print"></i> Print / Save as PDF</button>', 'modal-xl');
  $('#repPrint', m.el).onclick = () => { const w = window.open('', '_blank'); if (!w) return toast('Allow pop-ups to print', 'danger'); w.document.write(`<html><head><title>ISO 42001 readiness</title><style>body{font:13px Arial;margin:30px;color:#111}table{border-collapse:collapse;width:100%}td,th{border:1px solid #999;padding:4px;text-align:left}h2,h3{margin-bottom:4px}</style></head><body>${html}</body></html>`); w.document.close(); w.print(); };
}

/* Collectors & monitoring, registry and discovery live in registry.js */


boot().catch(e => { if (e.message !== "signed out") document.getElementById("view").innerHTML = `<div class="alert alert-danger">${E(e.message)}</div>`; });
