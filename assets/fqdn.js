'use strict';
/* FQDN Directory: every registered hostname with its service, root domain, DNS registrar and functional purpose. Full CRUD in modals, CSV import. */

const FQDN_TYPES = ['primary', 'secondary', 'api', 'authentication', 'cdn', 'other'];
const FQDN_HEADERS = { service: ['service name', 'service', 'product'], fqdn: ['fqdn / endpoint', 'fqdn', 'endpoint', 'domain', 'hostname'], root: ['root domain / site', 'root domain', 'root', 'site'],
  registrar: ['dns registrar / registry', 'dns registrar', 'registrar', 'registry'], purpose: ['functional purpose & role', 'functional purpose', 'purpose', 'role', 'description'], category: ['primary category', 'category'] };

/** The registry is one page with two views: Services (what the AI products are) and FQDNs (every hostname that identifies them). */
const regTabs = (cur, nSvc, nFq) => `<ul class="nav nav-pills reg-tabs mb-3" role="tablist">
  <li class="nav-item"><button class="nav-link ${cur === 'services' ? 'active' : ''}" data-rv="services" role="tab" aria-selected="${cur === 'services'}"><i class="fa-solid fa-cubes me-1"></i> Services <span class="badge text-bg-light ms-1">${nSvc ?? ''}</span></button></li>
  <li class="nav-item"><button class="nav-link ${cur === 'fqdn' ? 'active' : ''}" data-rv="fqdn" role="tab" aria-selected="${cur === 'fqdn'}"><i class="fa-solid fa-sitemap me-1"></i> FQDNs &amp; registrars <span class="badge text-bg-light ms-1">${nFq ?? ''}</span></button></li></ul>`;
const bindRegTabs = () => document.querySelectorAll('[data-rv]').forEach(b => b.onclick = () => { S.regView = b.dataset.rv; registry(); });

/** Minimal RFC-4180 CSV parser (quoted fields, doubled quotes, CRLF). */
function parseCsv(text) {
  const rows = []; let row = [], cur = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',' || c === '\t') { row.push(cur); cur = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cur); if (row.some(x => x.trim() !== '')) rows.push(row); row = []; cur = ''; }
    else cur += c;
  }
  row.push(cur); if (row.some(x => x.trim() !== '')) rows.push(row);
  return rows;
}

/** Maps CSV columns to import fields by header name; returns [{service,fqdn,...}] or throws a readable error. */
function csvToImportRows(text) {
  const t = parseCsv(text.replace(/^﻿/, ''));
  if (t.length < 2) throw new Error('The file needs a header row and at least one data row.');
  const head = t[0].map(h => h.trim().toLowerCase()), idx = {};
  for (const [k, names] of Object.entries(FQDN_HEADERS)) idx[k] = head.findIndex(h => names.includes(h));
  if (idx.fqdn < 0) throw new Error('No FQDN column found. Expected a header such as "FQDN / Endpoint".');
  if (idx.service < 0) throw new Error('No service column found. Expected a header such as "Service Name".');
  return t.slice(1).map(r => Object.fromEntries(Object.entries(idx).map(([k, i]) => [k, i >= 0 ? (r[i] || '').trim() : ''])));
}

async function fqdn() {
  const [{ domains }, { services }] = await Promise.all([api('GET', 'registry/domains'), api('GET', 'registry')]);
  const w = can('registry.write'), dlt = can('registry.delete');
  const svcOptions = services.filter(s => !+s.archived).map(s => [s.id, s.service_name]);
  const registrars = new Set(domains.map(d => d.registrar).filter(Boolean)), shared = domains.filter(d => +d.shared).length;
  const chip = (n, l, ic) => `<div class="col-6 col-md-3"><div class="card p-3 h-100 d-flex flex-row align-items-center gap-3"><div class="fs-4 text-info"><i class="fa-solid ${ic}"></i></div><div><div class="fw-bold fs-5 text-white">${fmtN(n)}</div><div class="small text-secondary">${l}</div></div></div></div>`;
  $('#view').innerHTML = pageHead('AI Services &amp; DNS Registry', 'Every hostname collectors watch, with its service, root domain, DNS registrar and functional purpose. Add, edit, import or remove entries here; collectors pick changes up on their next sync.',
    (w ? `<button class="btn btn-sm btn-outline-info" id="fqImp"><i class="fa-solid fa-file-import"></i> Import CSV</button>${addBtn('Add FQDN', 'fqAdd')}` : '')) + regTabs('fqdn', services.length, domains.length) + `
  <div class="row g-3 mb-3">${chip(domains.length, 'FQDNs registered', 'fa-globe')}${chip(new Set(domains.map(d => d.service_id)).size, 'Services', 'fa-cubes')}${chip(registrars.size, 'DNS registrars', 'fa-building-columns')}${chip(shared, 'Shared domains (non-AI traffic)', 'fa-triangle-exclamation')}</div>
  <div class="card"><div id="fqGrid"></div></div>`;
  bindRegTabs();
  const again = () => { S.services = null; fqdn(); };
  const form = d => formModal({ title: d ? `Edit ${d.domain}` : 'Add FQDN', icon: 'fa-globe', size: 'modal-lg', values: d ? { ...d, shared: !!+d.shared, active: !!+d.active } : { domain_type: 'secondary', matching_rule: 'exact', service_id: svcOptions[0]?.[0] },
    note: 'Exact matches only this hostname. Domain + subdomains also matches every host beneath it. Mark a domain Shared when it also carries non-AI traffic (for example a productivity suite).',
    fields: [(d ? { name: 'service_id', label: 'Service', type: 'select', options: svcOptions, col: 6, readonly: true } : { name: 'service_id', label: 'Service', type: 'select', options: svcOptions, col: 6, required: true }),
      { name: 'domain', label: 'FQDN', required: true, mono: true, col: 6, placeholder: 'api.example.com or *.example.com', maxlength: 253 },
      { name: 'root_domain', label: 'Root domain / site', mono: true, col: 4, maxlength: 253 }, { name: 'registrar', label: 'DNS registrar / registry', col: 4, maxlength: 150 }, { name: 'category', label: 'Primary category', col: 4, maxlength: 100 },
      { name: 'purpose', label: 'Functional purpose & role', type: 'textarea', rows: 2, maxlength: 400 },
      { name: 'domain_type', label: 'Type', type: 'select', options: FQDN_TYPES, col: 4 }, { name: 'matching_rule', label: 'Matching', type: 'select', options: [['exact', 'Exact only'], ['subdomain', 'Domain + subdomains']], col: 4 },
      { name: 'shared', label: 'Shared domain', type: 'checkbox', col: 2 }, ...(d ? [{ name: 'active', label: 'Active', type: 'checkbox', col: 2 }] : []), { name: 'notes', label: 'Notes', maxlength: 500 }],
    save: v => { const b = { ...v }; if (d) { delete b.service_id; } else b.service_id = +b.service_id; return api('POST', d ? 'registry/domains/' + d.id : 'registry/domains', b); },
    done: () => { toast(d ? 'FQDN updated' : 'FQDN added', 'success'); again(); } });
  const setActive = (rs, on) => act(async () => { for (const d of rs) await api('POST', 'registry/domains/' + d.id, { active: on }); toast(on ? 'Activated' : 'Deactivated', 'success'); again(); });
  const remove = rs => deleteFlow({ path: 'registry/domains/delete', ids: rs.map(d => +d.id), title: rs.length > 1 ? `Delete ${rs.length} FQDNs` : 'Delete FQDN', done: 'Deleted',
    describe: () => '<p class="small mb-0">Collectors stop watching these hostnames on their next sync. Events already recorded are kept. A service must keep at least one FQDN; delete the service instead to remove it entirely.</p>' });
  new DataGrid({ el: '#fqGrid', id: 'fqdn', rows: domains, exportName: 'fqdn-directory', sort: { key: 'domain', dir: 'asc' }, onRowClick: d => form(d),
    rowClass: d => +d.active ? '' : 'opacity-50',
    columns: [
      { key: 'domain', label: 'FQDN', filter: 'text', render: d => `<span class="mono fw-semibold text-white">${E(d.domain)}</span>${+d.shared ? ' <span class="pill p-warn" title="Also carries non-AI traffic">SHARED</span>' : ''}` },
      { key: 'service_name', label: 'Service', filter: 'text', render: d => E(d.service_name) },
      { key: 'sanction_status', label: 'Classification', filter: 'select', text: d => CLASSES[d.sanction_status] || d.sanction_status, render: d => classPill(d.sanction_status) },
      { key: 'root_domain', label: 'Root domain', render: d => `<span class="mono small">${E(d.root_domain || '')}</span>`, filter: 'text' },
      { key: 'registrar', label: 'DNS registrar', filter: 'select' },
      { key: 'purpose', label: 'Functional purpose', render: d => `<span class="small text-secondary" style="display:inline-block;max-width:340px">${E(d.purpose || '')}</span>` },
      { key: 'category', label: 'Category', filter: 'select' },
      { key: 'matching_rule', label: 'Matching', filter: 'select', text: d => d.matching_rule === 'exact' ? 'Exact' : 'Domain + subdomains' },
      { key: 'domain_type', label: 'Type', filter: 'select' },
      { key: 'hits', label: 'Events', num: true, render: d => fmtN(d.hits) },
      { key: 'active', label: 'Status', filter: 'select', text: d => +d.archived ? 'Archived' : +d.active ? 'Active' : 'Inactive', render: d => `<span class="pill ${+d.archived ? 'p-mute' : +d.active ? 'p-ok' : 'p-warn'}">${+d.archived ? 'ARCHIVED' : +d.active ? 'ACTIVE' : 'INACTIVE'}</span>` }],
    actions: d => [{ inline: true, key: 'edit', label: w ? 'Edit FQDN' : 'View FQDN', icon: w ? 'fa-pen' : 'fa-eye' }].concat(w ? [{ key: 'toggle', label: +d.active ? 'Deactivate' : 'Activate', icon: +d.active ? 'fa-pause' : 'fa-play' }] : [], dlt ? [{ inline: true, key: 'delete', label: 'Delete FQDN', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, d) => { if (k === 'edit') form(d); else if (k === 'toggle') setActive([d], !+d.active); else if (await remove([d])) again(); },
    bulk: w ? [{ label: 'Activate', icon: 'fa-play', fn: rs => setActive(rs, true) }, { label: 'Deactivate', icon: 'fa-pause', fn: rs => setActive(rs, false) }].concat(dlt ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await remove(rs)) again(); } }] : []) : null });
  if ($('#fqAdd')) $('#fqAdd').onclick = () => form(null);
  if ($('#fqImp')) $('#fqImp').onclick = () => importModal(again);
}

function importModal(done) {
  const m = modal('<i class="fa-solid fa-file-import me-2 text-info"></i>Import services &amp; FQDNs', `
    <p class="small text-secondary mb-2">Paste CSV or choose a file (in Excel: <b>Save As &rarr; CSV</b>). Columns: <b>Service Name, FQDN / Endpoint, Root Domain / Site, DNS Registrar / Registry, Functional Purpose &amp; Role, Primary Category</b>. Rows with the same Service Name become one service with several FQDNs. New services start as Unsanctioned; existing services and FQDNs are never overwritten, only enriched.</p>
    <div class="d-flex gap-2 mb-2"><input type="file" id="imFile" accept=".csv,.tsv,.txt,text/csv" class="form-control form-control-sm"><button class="btn btn-sm btn-outline-secondary text-nowrap" id="imTpl"><i class="fa-solid fa-download"></i> Template</button></div>
    <textarea id="imText" class="form-control form-control-sm mono" rows="9" placeholder="Service Name,FQDN / Endpoint,Root Domain / Site,DNS Registrar / Registry,Functional Purpose &amp; Role,Primary Category"></textarea>
    <div id="imOut" class="mt-3 small"></div>`,
    '<button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Close</button><button class="btn btn-sm btn-outline-info" id="imCheck"><i class="fa-solid fa-list-check"></i> Validate</button><button class="btn btn-sm btn-info" id="imGo"><i class="fa-solid fa-file-import"></i> Import</button>', 'modal-lg');
  $('#imFile', m.el).onchange = e => { const f = e.target.files[0]; if (!f) return; if (f.size > 1048576) return toast('File is larger than 1 MB.', 'danger'); const r = new FileReader(); r.onload = () => { $('#imText', m.el).value = r.result; }; r.readAsText(f); };
  $('#imTpl', m.el).onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['﻿Service Name,FQDN / Endpoint,Root Domain / Site,DNS Registrar / Registry,Functional Purpose & Role,Primary Category\r\nExample AI,api.example.ai,example.ai,Cloudflare Inc.,Inference API for the Example AI service,Foundation Models & API\r\n'], { type: 'text/csv' })); a.download = 'fqdn-import-template.csv'; a.click(); };
  const run = dry => act(async () => {
    let rows; try { rows = csvToImportRows($('#imText', m.el).value); } catch (e) { return toast(e.message, 'danger'); }
    if (rows.length > 1000) return toast('At most 1000 rows per import.', 'danger');
    const r = await api('POST', 'registry/import', { rows, dry_run: dry });
    const li = a => a.slice(0, 8).map(x => `<li>row ${x.row}${x.domain ? ' ' + E(x.domain) : ''}: ${E(x.reason)}</li>`).join('');
    $('#imOut', m.el).innerHTML = `<div class="alert alert-${r.errors.length ? 'warning' : 'success'} py-2 mb-2"><b>${dry ? 'Validation (nothing saved)' : 'Imported'}:</b> ${r.services_created} new service(s), ${r.services_matched} existing matched, ${r.domains_added} FQDN(s) added, ${r.domains_updated} enriched, ${r.skipped.length} skipped, ${r.errors.length} error(s).</div>
      ${r.errors.length ? `<div class="text-danger">Errors</div><ul>${li(r.errors)}</ul>` : ''}${r.skipped.length ? `<div class="text-secondary">Skipped (already present or owned by another service)</div><ul>${li(r.skipped)}</ul>` : ''}`;
    if (!dry) { toast('Import complete; collectors resync automatically', 'success'); $('#imGo', m.el).disabled = true; m.el.addEventListener('hidden.bs.modal', done); }
  });
  $('#imCheck', m.el).onclick = () => run(true);
  $('#imGo', m.el).onclick = () => run(false);
}
