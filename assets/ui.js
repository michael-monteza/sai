'use strict';
/* SAIP console core: helpers, API client, permissions, modal system (forms, confirmations). Loaded first. */
const E = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const $ = (sel, root = document) => root.querySelector(sel);
const S = { me: null, csrf: '', charts: {}, selRisk: null, quad: null };
const BASE = (document.querySelector('meta[name="saip-base"]') || {}).content || '';

/** RBAC: the server sends the permissions of the signed-in role; the UI only hides what the API would refuse anyway. */
const can = p => !!(S.me && S.me.permissions.includes(p));
const canWrite = () => can('inventory.write');

async function api(method, path, body) {
  const opt = { method, headers: { 'Accept': 'application/json' }, credentials: 'same-origin' };
  if (method !== 'GET') { opt.headers['Content-Type'] = 'application/json'; opt.headers['X-CSRF-Token'] = S.csrf; opt.body = JSON.stringify(body || {}); }
  const r = await fetch(`${BASE}/api/v1/console/${path}`, opt);
  if (r.status === 401) { location.href = BASE + '/login'; throw new Error('signed out'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.error?.message || 'Request failed'); e.code = j.error?.code; e.details = j.error?.details; throw e; }
  return j;
}
const dl = path => `${BASE}/api/v1/console/${path}`;
const act = async (fn) => { try { return await fn(); } catch (e) { if (e.message !== 'signed out') toast(e.message, 'danger'); return null; } };

function toast(msg, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast align-items-center text-bg-${kind === 'danger' ? 'danger' : kind === 'success' ? 'success' : 'dark'} border-0`;
  el.setAttribute('role', 'alert');
  el.innerHTML = `<div class="d-flex"><div class="toast-body">${E(msg)}</div><button class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>`;
  $('#toasts').appendChild(el);
  const t = new bootstrap.Toast(el, { delay: 4500 }); t.show(); el.addEventListener('hidden.bs.toast', () => el.remove());
}

/** Low-level modal. title/body/footer are HTML (callers escape dynamic values). A modal opened from another modal replaces it cleanly. */
function modal(title, body, footer = '', size = '') {
  const host = $('#modalHost');
  const old = host.firstElementChild;
  if (old) { bootstrap.Modal.getInstance(old)?.dispose(); document.querySelectorAll('.modal-backdrop').forEach(b => b.remove()); document.body.classList.remove('modal-open'); document.body.style.removeProperty('overflow'); document.body.style.removeProperty('padding-right'); }
  host.innerHTML = `<div class="modal fade" tabindex="-1"><div class="modal-dialog ${size} modal-dialog-scrollable"><div class="modal-content">
    <div class="modal-header"><h6 class="modal-title">${title}</h6><button class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
    <div class="modal-body">${body}</div>${footer ? `<div class="modal-footer">${footer}</div>` : ''}</div></div></div>`;
  const el = host.firstElementChild; const m = new bootstrap.Modal(el); m.show();
  el.addEventListener('hidden.bs.modal', () => { if (host.firstElementChild === el) host.innerHTML = ''; });
  return { el, close: () => m.hide() };
}

/**
 * Standard data-entry modal.
 *   formModal({ title, icon, fields: [{ name, label, type, options, required, help, col, placeholder, maxlength, readonly, rows }], values, submit, size,
 *               save: async data => api(...), done: result => {} })
 * Types: text (default), textarea, select ([[value, label]] or [value]), checkbox, password, number, email, range. Server field errors are shown inline.
 */
function formModal(o) {
  const v = o.values || {};
  const fld = f => {
    const id = 'f_' + f.name, val = v[f.name] ?? f.value ?? '', col = f.col || 12, req = f.required ? ' <span class="text-danger">*</span>' : '';
    const common = `id="${id}" name="${E(f.name)}" ${f.required ? 'required' : ''} ${f.readonly ? 'readonly' : ''} ${f.maxlength ? `maxlength="${f.maxlength}"` : ''} ${f.placeholder ? `placeholder="${E(f.placeholder)}"` : ''}`;
    let input;
    if (f.type === 'textarea') input = `<textarea class="form-control form-control-sm" rows="${f.rows || 3}" ${common}>${E(val)}</textarea>`;
    else if (f.type === 'select') input = `<select class="form-select form-select-sm" ${common}>${(f.options || []).map(x => { const [k, l] = Array.isArray(x) ? x : [x, x]; return `<option value="${E(k)}" ${String(k) === String(val) ? 'selected' : ''}>${E(l)}</option>`; }).join('')}</select>`;
    else if (f.type === 'checkbox') return `<div class="col-md-${col}"><div class="form-check form-switch"><input type="checkbox" class="form-check-input" id="${id}" name="${E(f.name)}" ${val ? 'checked' : ''}><label class="form-check-label small" for="${id}">${E(f.label)}</label></div>${f.help ? `<div class="form-text">${E(f.help)}</div>` : ''}</div>`;
    else if (f.type === 'range') input = `<input type="range" class="form-range" min="0" max="100" value="${E(val || 0)}" ${common}>`;
    else input = `<input type="${f.type || 'text'}" class="form-control form-control-sm ${f.mono ? 'mono' : ''}" value="${f.type === 'password' ? '' : E(val)}" ${f.type === 'password' ? 'autocomplete="new-password"' : ''} ${common}>`;
    return `<div class="col-md-${col}"><label class="form-label small" for="${id}">${E(f.label)}${req}</label>${input}<div class="invalid-feedback" data-err="${E(f.name)}"></div>${f.help ? `<div class="form-text">${f.help}</div>` : ''}</div>`;
  };
  const m = modal(`${o.icon ? `<i class="fa-solid ${o.icon} me-2 text-info"></i>` : ''}${E(o.title)}`,
    `<form id="fm" novalidate><div class="row g-2">${o.fields.map(fld).join('')}</div>${o.note ? `<div class="small text-secondary mt-2">${o.note}</div>` : ''}</form>`,
    `<button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-sm btn-info" id="fmOk"><i class="fa-solid ${o.submitIcon || 'fa-floppy-disk'}"></i> ${E(o.submit || 'Save')}</button>`, o.size || '');
  const form = $('#fm', m.el);
  const collect = () => { const d = {}; o.fields.forEach(f => { const el = form.elements[f.name]; if (!el) return; d[f.name] = f.type === 'checkbox' ? el.checked : f.type === 'number' || f.type === 'range' ? +el.value : el.value; }); return d; };
  const go = async () => {
    form.querySelectorAll('.is-invalid').forEach(e => e.classList.remove('is-invalid'));
    const ok = $('#fmOk', m.el); ok.disabled = true;
    try { const r = await o.save(collect()); m.close(); if (o.done) o.done(r); }
    catch (e) {
      if (e.message === 'signed out') return;
      Object.keys(e.details || {}).forEach(k => { const el = form.elements[k]; if (el) { el.classList.add('is-invalid'); const fb = form.querySelector(`[data-err="${k}"]`); if (fb) fb.textContent = e.details[k] === 'required' ? 'Required' : e.details[k] === 'invalid' ? 'Invalid value' : e.details[k]; } });
      toast(e.message, 'danger');
    } finally { ok.disabled = false; }
  };
  $('#fmOk', m.el).onclick = go;
  form.onsubmit = e => { e.preventDefault(); go(); };
  m.el.addEventListener('shown.bs.modal', () => { const f = form.querySelector('input:not([type=checkbox]):not([readonly]),select,textarea'); if (f) f.focus(); });
  return m;
}

/** Yes/No confirmation as a modal. Resolves true on confirm. */
function confirmModal({ title, body, button = 'Confirm', danger = false, icon = 'fa-circle-question' }) {
  return new Promise(resolve => {
    const m = modal(`<i class="fa-solid ${icon} me-2 ${danger ? 'text-danger' : 'text-info'}"></i>${E(title)}`, body, `<button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-sm ${danger ? 'btn-danger' : 'btn-info'}" id="cmOk">${E(button)}</button>`);
    let ok = false;
    m.el.addEventListener('hidden.bs.modal', () => resolve(ok));
    $('#cmOk', m.el).onclick = () => { ok = true; m.close(); };
  });
}

/** Icon button helpers (CRUD actions use icons with accessible labels). */
const iconBtn = (icon, label, attrs = '', cls = 'btn-outline-secondary') => `<button class="btn btn-sm ${cls}" title="${E(label)}" aria-label="${E(label)}" ${attrs}><i class="fa-solid ${icon}"></i></button>`;
const addBtn = (label, id) => `<button class="btn btn-sm btn-info" id="${id}"><i class="fa-solid fa-plus"></i> ${E(label)}</button>`;

/* Times are stored and exchanged in UTC; the console shows them in this browser's time zone (hover for the UTC value). */
const TZ = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time'; } catch { return 'local time'; } })();
const UTC_RE = /^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)/;
const isUtcStamp = v => typeof v === 'string' && UTC_RE.test(v);
const localDT = s => {
  const m = UTC_RE.exec(String(s ?? '')); if (!m) return String(s ?? '');
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])), p2 = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
};
const fmtDT = s => s ? `<span title="UTC ${E(String(s).replace('T', ' ').slice(0, 19))}">${E(localDT(s))}</span>` : '<span class="text-secondary">-</span>';
const fmtN = n => Number(n || 0).toLocaleString();
const statusPill = s => ({ sanctioned: '<span class="pill p-ok">SANCTIONED</span>', unsanctioned: '<span class="pill p-bad">SHADOW</span>', under_review: '<span class="pill p-warn">UNDER REVIEW</span>', excluded: '<span class="pill p-mute">EXCLUDED</span>' }[s] || E(s));
const riskPill = (lvl, score) => `<span class="pill ${{ Critical: 'p-bad', High: 'p-warn', Medium: 'p-info', Low: 'p-ok' }[lvl]}">${E(lvl).toUpperCase()} ${score != null ? E(score) : ''}</span>`;
const dcPill = c => `<span class="pill ${{ 'Restricted / PII': 'p-bad', Confidential: 'p-warn', Internal: 'p-info', Public: 'p-ok' }[c] || 'p-mute'}">${E(c)}</span>`;
const DISCLAIMER = '<div class="disclaimer mb-3"><i class="fa-solid fa-circle-info me-1"></i> Figures are <strong>observed DNS telemetry</strong>, not verified AI sessions or time spent. Low observed activity does not mean low actual AI use.</div>';
const pageHead = (title, sub, actions = '') => `<div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3"><div><h5 class="mb-0 text-white">${title}</h5><div class="text-secondary small">${sub}</div></div><div class="d-flex flex-wrap gap-2">${actions}</div></div>`;

function chart(id, cfg) {
  if (S.charts[id]) S.charts[id].destroy();
  const c = document.getElementById(id); if (!c) return;
  Chart.defaults.color = '#6b7280'; Chart.defaults.borderColor = '#e8eaf2'; Chart.defaults.font.family = "'Poppins', system-ui, sans-serif";
  S.charts[id] = new Chart(c, cfg);
}
