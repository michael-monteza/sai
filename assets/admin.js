'use strict';
/* Administration: User Management (RBAC), Companies, Audit Log, own-password change. Uses ui.js + grid.js. */

function changePasswordModal() {
  formModal({ title: 'Change password', icon: 'fa-key', submit: 'Change password', note: 'Minimum 12 characters with at least three of: lowercase, uppercase, digits, symbols. Your other sessions are signed out.',
    fields: [{ name: 'current_password', label: 'Current password', type: 'password', required: true }, { name: 'new_password', label: 'New password', type: 'password', required: true, maxlength: 200 }, { name: 'confirm', label: 'Repeat new password', type: 'password', required: true }],
    save: async v => { if (v.new_password !== v.confirm) { const e = new Error('The two new passwords do not match.'); e.details = { confirm: 'Does not match' }; throw e; } return api('POST', 'me/password', { current_password: v.current_password, new_password: v.new_password }); },
    done: () => toast('Password changed', 'success') });
}

/* ---------------- User management ---------------- */
async function users() {
  const [{ users: rows }, { roles }] = await Promise.all([api('GET', 'users'), api('GET', 'roles')]);
  const w = can('users.write'), dlt = can('users.delete'), sup = can('tenants.read');
  const me = S.me.user;
  const roleLabel = Object.fromEntries(roles.map(r => [r.role, r.label]));
  const assignable = roles.filter(r => r.assignable);
  const state = u => +u.locked ? 'Locked' : +u.active ? 'Active' : 'Inactive';
  const rolePill = r => `<span class="pill ${{ super_admin: 'p-vio', it_admin: 'p-info', auditor: 'p-warn', viewer: 'p-mute' }[r] || 'p-mute'}">${E(roleLabel[r] || r)}</span>`;
  $('#view').innerHTML = pageHead('<i class="fa-solid fa-users-gear text-info"></i> User Management', sup ? 'Console users across all companies. Roles decide what each person can see and change.' : 'Console users of your company. You can assign roles up to your own.', w ? addBtn('Add user', 'uAdd') : '') + `
  <div class="card mb-3 p-3 small"><b class="text-white mb-1"><i class="fa-solid fa-shield-halved me-1 text-info"></i> Roles (RBAC)</b><div class="row g-2 mt-0">${roles.map(r => `<div class="col-md-3"><div class="p-2 rounded h-100" style="background:var(--surface)"><div>${rolePill(r.role)}</div><div class="text-secondary mt-1">${r.role === 'super_admin' ? 'Everything, across all companies' : r.permissions.length + ' permissions'}</div></div></div>`).join('')}</div></div>
  <div class="card"><div id="usGrid"></div></div>`;
  const form = u => {
    const fields = [];
    if (!u) fields.push({ name: 'username', label: 'Username', required: true, maxlength: 60, col: 6, help: 'Letters, digits . _ @ - (3-60)' });
    else fields.push({ name: 'username', label: 'Username', readonly: true, col: 6 });
    fields.push({ name: 'display_name', label: 'Display name', maxlength: 100, col: 6 }, { name: 'email', label: 'Email', type: 'email', maxlength: 190, col: 6 },
      { name: 'role', label: 'Role', type: 'select', col: 6, options: (u && !assignable.some(r => r.role === u.role) ? [[u.role, roleLabel[u.role]]] : []).concat(assignable.map(r => [r.role, r.label])), readonly: u && u.id == me.id });
    if (sup) fields.push({ name: 'tenant_id', label: 'Company', type: 'select', col: 6, options: [['', '- none (platform admin) -']].concat(S.me.tenants.map(t => [t.id, t.name])), help: 'Not used by platform administrators.' });
    fields.push({ name: 'password', label: u ? 'Reset password (optional)' : 'Initial password', type: 'password', required: !u, maxlength: 200, col: 6, help: 'Min 12 characters, three of four character classes.' });
    if (u) fields.push({ name: 'active', label: 'Account active', type: 'checkbox', col: 6 }, { name: 'unlock', label: 'Clear lockout', type: 'checkbox', col: 6 }, { name: 'local_login', label: 'Allow password sign-in (turn off for Google-only)', type: 'checkbox', col: 12 }, ...(+u.google_linked ? [{ name: 'unlink_google', label: 'Unlink Google account (re-enables password sign-in)', type: 'checkbox', col: 12 }] : []));
    return formModal({ title: u ? `Edit ${u.username}` : 'Add user', icon: 'fa-user-pen', values: u ? { ...u, password: '', active: !!+u.active, local_login: !!+u.local_login } : { role: assignable[assignable.length - 1]?.role || 'viewer', tenant_id: S.me.tenant?.id }, fields,
      save: v => { const b = { ...v }; if (u) { delete b.username; if (!b.password) delete b.password; if (u.id == me.id) { delete b.role; delete b.active; delete b.local_login; } if (!b.unlink_google) delete b.unlink_google; } if (!sup || b.role === 'super_admin') b.tenant_id = b.role === 'super_admin' ? null : undefined; return api('POST', u ? 'users/' + u.id : 'users', b); },
      done: () => { toast(u ? 'User updated' : 'User created', 'success'); users(); } });
  };
  const remove = rs => deleteFlow({ path: 'users/delete', ids: rs.map(r => +r.id), title: rs.length > 1 ? `Delete ${rs.length} users` : 'Delete user', describe: () => '<p class="small mb-0">The accounts are removed and can no longer sign in. Their past actions stay in the audit log.</p>', done: 'User deleted' });
  const setActive = (rs, on) => act(async () => { for (const u of rs.filter(x => x.id != me.id)) await api('POST', 'users/' + u.id, { active: on }); toast(on ? 'Activated' : 'Deactivated', 'success'); users(); });
  new DataGrid({ el: '#usGrid', id: 'users', rows, exportName: 'users', sort: { key: 'username', dir: 'asc' }, onRowClick: u => form(u),
    columns: [
      { key: 'username', label: 'User', filter: 'text', text: u => `${u.username} ${u.display_name} ${u.email || ''}`, sort: u => u.username, render: u => `<b>${E(u.username)}</b>${u.id == me.id ? ' <span class="pill p-info">YOU</span>' : ''}<div class="small text-secondary">${E(u.display_name)}${u.email ? ' &middot; ' + E(u.email) : ''}</div>` },
      { key: 'role', label: 'Role', filter: 'select', text: u => roleLabel[u.role] || u.role, render: u => rolePill(u.role) },
      ...(sup ? [{ key: 'tenant', label: 'Company', filter: 'select', text: u => u.tenant || 'Platform', render: u => E(u.tenant || 'Platform') }] : []),
      { key: 'state', label: 'Status', filter: 'select', text: state, render: u => `<span class="pill ${+u.locked ? 'p-bad' : +u.active ? 'p-ok' : 'p-mute'}">${state(u).toUpperCase()}</span>` },
      { key: 'signin', label: 'Sign-in', filter: 'select', text: u => +u.google_linked ? (+u.local_login ? 'Google + password' : 'Google only') : 'Password', render: u => `<span class="pill ${+u.google_linked ? 'p-info' : 'p-mute'}">${+u.google_linked ? (+u.local_login ? 'GOOGLE + PASSWORD' : 'GOOGLE ONLY') : 'PASSWORD'}</span>` },
      { key: 'last_login', label: 'Last sign-in (local time)', nowrap: true, render: u => `<span class="small">${fmtDT(u.last_login)}</span><div class="small text-secondary mono">${E(u.last_login_ip || '')}</div>`, text: u => u.last_login || '' }],
    actions: u => [{ inline: true, key: 'edit', label: w ? 'Edit user' : 'View user', icon: w ? 'fa-pen' : 'fa-eye' }].concat(w ? [{ key: 'reset', label: 'Reset password', icon: 'fa-key' }] : [], dlt && u.id != me.id ? [{ inline: true, key: 'delete', label: 'Delete user', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, u) => { if (k === 'delete') { if (await remove([u])) users(); } else if (k === 'reset') form(u); else form(u); },
    bulk: w ? [{ label: 'Activate', icon: 'fa-user-check', fn: rs => setActive(rs, true) }, { label: 'Deactivate', icon: 'fa-user-slash', fn: rs => setActive(rs, false) }].concat(dlt ? [{ label: 'Delete', icon: 'fa-trash', danger: true, fn: async rs => { if (await remove(rs.filter(x => x.id != me.id))) users(); } }] : []) : null });
  if ($('#uAdd')) $('#uAdd').onclick = () => form(null);
}

/* ---------------- Companies (platform administrators) ---------------- */
async function companies() {
  const { tenants } = await api('GET', 'tenants');
  const w = can('tenants.write'), dlt = can('tenants.delete');
  const form = t => formModal({ title: t ? `Edit ${t.name}` : 'Add company', icon: 'fa-building', values: t || {},
    fields: [{ name: 'name', label: 'Company name', required: true, maxlength: 150 }].concat(t ? [{ name: 'status', label: 'Status', type: 'select', options: [['active', 'Active'], ['suspended', 'Suspended (collectors and users blocked)']] }] : [{ name: 'slug', label: 'Short name (optional)', maxlength: 60, mono: true, help: 'Used in URLs and tools; letters, digits, hyphen.' }]),
    note: t ? '' : 'A new company gets its own AI register, ISO 42001 controls, policies and enrollment key.',
    save: v => api('POST', t ? 'tenants/' + t.id : 'tenants', t ? { name: v.name, status: v.status } : v),
    done: r => { if (t) { toast('Company updated', 'success'); companies(); } else modal('Enrollment key', `<p class="small text-warning">Shown once. Give it to the installer of this company's collectors.</p><pre class="feed">${E(r.enrollment_key)}</pre>`, '', ''), document.querySelector('.modal').addEventListener('hidden.bs.modal', () => { companies(); }); } });
  const remove = async t => {
    const pv = await act(() => api('POST', 'tenants/delete', { ids: [t.id], preview: true })); if (!pv) return;
    const i = pv.preview;
    formModal({ title: `Delete ${t.name}`, icon: 'fa-triangle-exclamation', submit: 'Delete company permanently', submitIcon: 'fa-trash',
      note: `This removes <b>${fmtN(i.services)}</b> AI services, <b>${fmtN(i.events)}</b> events, <b>${fmtN(i.collectors)}</b> collectors and <b>${fmtN(i.users)}</b> users. It cannot be undone; the audit history is kept. Type <code>${E(t.slug)}</code> to confirm.`,
      fields: [{ name: 'confirm', label: 'Company short name', required: true, mono: true }], save: v => api('POST', 'tenants/delete', { ids: [t.id], confirm: v.confirm }), done: () => { toast('Company deleted', 'success'); location.reload(); } });
  };
  $('#view').innerHTML = pageHead('<i class="fa-solid fa-building text-info"></i> Companies', 'One company (tenant) per customer, each with its own register, collectors, governance data and users.', w ? addBtn('Add company', 'tAdd') : '') + '<div class="card"><div id="coGrid"></div></div>';
  new DataGrid({ el: '#coGrid', id: 'companies', rows: tenants, exportName: 'companies', sort: { key: 'name', dir: 'asc' }, onRowClick: t => { if (w) form(t); },
    columns: [{ key: 'name', label: 'Company', filter: 'text', render: t => `<b class="text-white">${E(t.name)}</b>${S.me.tenant && t.id == S.me.tenant.id ? ' <span class="pill p-info">CURRENT</span>' : ''}` }, { key: 'slug', label: 'Short name', render: t => `<span class="mono">${E(t.slug)}</span>` },
      { key: 'status', label: 'Status', filter: 'select', render: t => `<span class="pill ${t.status === 'active' ? 'p-ok' : 'p-warn'}">${E(t.status).toUpperCase()}</span>` }, { key: 'collectors', label: 'Collectors', num: true }, { key: 'events', label: 'Events', num: true, render: t => fmtN(t.events) }, { key: 'users', label: 'Users', num: true },
      { key: 'created_at', label: 'Created', nowrap: true, render: t => `<span class="small">${fmtDT(t.created_at)}</span>` }],
    actions: t => [{ inline: true, key: 'open', label: 'Open this company', icon: 'fa-right-to-bracket' }].concat(w ? [{ inline: true, key: 'edit', label: 'Edit', icon: 'fa-pen' }] : [], dlt ? [{ inline: true, key: 'delete', label: 'Delete company', icon: 'fa-trash', danger: true }] : []),
    onAction: (k, t) => { if (k === 'open') act(async () => { await api('POST', 'tenant/switch', { tenant_id: +t.id }); location.hash = '#overview'; location.reload(); }); else if (k === 'edit') form(t); else remove(t); } });
  if ($('#tAdd')) $('#tAdd').onclick = () => form(null);
}

/* ---------------- Audit log ---------------- */
async function audit() {
  const f = (S.auditFilter ||= { q: '', action: '', actor: '', from: '', to: '' });
  const qs = () => Object.entries(f).filter(([, v]) => v).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const { logs } = await api('GET', 'audit?limit=2000&' + qs());
  const actions = [...new Set(logs.map(l => l.action))].sort(), actors = [...new Set(logs.map(l => l.administrator))].sort();
  $('#view').innerHTML = pageHead('<i class="fa-solid fa-clipboard-list text-info"></i> Audit Log', 'Append-only record of sign-ins, access denials and every change, with before/after values, client IP and request id.',
    `<a class="btn btn-sm btn-outline-secondary" href="${dl('export/audit?' + qs())}"><i class="fa-solid fa-file-csv"></i> Export CSV</a>`) + `
  <div class="card p-3 mb-3"><div class="row g-2 align-items-end small">
    <div class="col-md-3"><label class="form-label mb-1">Search record / details</label><input id="afQ" class="form-control form-control-sm" value="${E(f.q)}"></div>
    <div class="col-md-2"><label class="form-label mb-1">Action</label><select id="afA" class="form-select form-select-sm"><option value="">All</option>${actions.map(a => `<option ${a === f.action ? 'selected' : ''}>${E(a)}</option>`).join('')}</select></div>
    <div class="col-md-2"><label class="form-label mb-1">Actor</label><select id="afU" class="form-select form-select-sm"><option value="">All</option>${actors.map(a => `<option ${a === f.actor ? 'selected' : ''}>${E(a)}</option>`).join('')}</select></div>
    <div class="col-md-2"><label class="form-label mb-1">From</label><input id="afF" type="date" class="form-control form-control-sm" value="${E(f.from)}"></div>
    <div class="col-md-2"><label class="form-label mb-1">To</label><input id="afT" type="date" class="form-control form-control-sm" value="${E(f.to)}"></div>
    <div class="col-md-1"><button class="btn btn-sm btn-info w-100" id="afGo" title="Apply filters" aria-label="Apply filters"><i class="fa-solid fa-filter"></i></button></div></div></div>
  <div class="card"><div id="auGrid"></div></div>`;
  $('#afGo').onclick = () => { Object.assign(f, { q: $('#afQ').value, action: $('#afA').value, actor: $('#afU').value, from: $('#afF').value, to: $('#afT').value }); audit(); };
  const diff = l => { try { const b = JSON.parse(l.before_json || 'null') || {}, a = JSON.parse(l.after_json || 'null') || {}; const keys = Object.keys({ ...b, ...a });
    return keys.length ? `<table class="table table-sm"><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>${keys.map(k => `<tr><td class="mono">${E(k)}</td><td>${E(JSON.stringify(b[k] ?? null))}</td><td><b>${E(JSON.stringify(a[k] ?? null))}</b></td></tr>`).join('')}</tbody></table>` : '<div class="text-secondary small">No field changes recorded.</div>'; } catch { return ''; } };
  const detail = l => modal(`<i class="fa-solid fa-clipboard-list me-2 text-info"></i>${E(l.action)}`, `<div class="row g-2 small mb-3"><div class="col-6"><span class="text-secondary">Time (local time)</span><br>${fmtDT(l.timestamp)}</div><div class="col-6"><span class="text-secondary">Actor</span><br>${E(l.administrator)}</div>
    <div class="col-6"><span class="text-secondary">Record</span><br>${E(l.affected_record || '-')}</div><div class="col-3"><span class="text-secondary">IP</span><br class="mono">${E(l.ip_address || '-')}</div><div class="col-3"><span class="text-secondary">Request</span><br class="mono">${E(l.request_id || '-')}</div></div>
    ${diff(l)}${l.details ? `<div class="small text-secondary">Details</div><pre class="feed small" style="color:#1f2340;white-space:pre-wrap">${E(l.details)}</pre>` : ''}`, '', 'modal-lg');
  new DataGrid({ el: '#auGrid', id: 'audit', rows: logs, exportName: 'audit-log', sort: { key: 'id', dir: 'desc' }, onRowClick: detail,
    columns: [{ key: 'id', label: 'ID', num: true, class: 'text-secondary small' }, { key: 'timestamp', label: 'Time (local time)', nowrap: true, render: l => `<span class="small">${fmtDT(l.timestamp)}</span>` }, { key: 'administrator', label: 'Actor', filter: 'select' },
      { key: 'action', label: 'Action', filter: 'select', render: l => `<span class="pill ${/denied|failed|blocked|delete/.test(l.action) ? 'p-bad' : 'p-info'}">${E(l.action)}</span>` }, { key: 'affected_record', label: 'Record', filter: 'text' },
      { key: 'ip_address', label: 'IP', render: l => `<span class="small mono">${E(l.ip_address || '')}</span>` }, { key: 'details', label: 'Details', render: l => `<span class="small mono text-secondary" style="display:inline-block;max-width:300px;overflow-wrap:anywhere">${E((l.details || '').slice(0, 160))}</span>` }],
    actions: () => [{ inline: true, key: 'view', label: 'View details', icon: 'fa-eye' }], onAction: (k, l) => detail(l) });
}
