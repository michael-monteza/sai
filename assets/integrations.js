'use strict';
/* SIEM & webhooks, Google authentication settings, Sysmon capability reference. */

const copyText = async (t, label = 'Copied') => { try { await navigator.clipboard.writeText(t); toast(label, 'success'); } catch { toast('Copy failed: select the text and copy it manually.', 'danger'); } };
const secretModal = (title, text, note) => modal(`<i class="fa-solid fa-key me-2 text-warning"></i>${E(title)}`, `<p class="small text-warning">${E(note)}</p><pre class="feed" id="secTxt">${E(text)}</pre>`, '<button class="btn btn-sm btn-outline-secondary" id="secCopy"><i class="fa-regular fa-copy"></i> Copy</button><button class="btn btn-sm btn-info" data-bs-dismiss="modal">Done</button>');

/* ---------------- SIEM & Webhooks ---------------- */
async function integrations() {
  const d = await api('GET', 'integrations');
  const w = can('integrations.write'), dlt = can('integrations.delete');
  const evLabel = { 'audit.event': 'Audit', 'shadow_ai.detected': 'Shadow AI', 'discovery.new_domain': 'New domain', 'usage.event': 'Usage stream' };
  const kindLabel = { webhook: 'Webhook', splunk_hec: 'Splunk HEC', syslog: 'Syslog' };
  const state = i => !+i.active ? 'Paused' : i.last_status === 'failed' ? 'Failing' : i.last_status === 'ok' ? 'Healthy' : 'Waiting';
  const dest = i => i.kind === 'syslog' ? `${i.protocol}://${i.host}:${i.port}` : i.url;
  $('#view').innerHTML = pageHead('<i class="fa-solid fa-plug text-info"></i> SIEM &amp; Webhooks', 'Send audit events, shadow-AI alerts, discovered domains and (optionally) the raw usage stream to your SIEM or any HTTPS endpoint. Or let your SIEM pull them with an API token.', w ? addBtn('Add integration', 'inAdd') : '') + `
  <div class="card p-3 mb-3 small"><b class="text-white"><i class="fa-solid fa-clock me-1 text-info"></i> Delivery</b> A scheduled worker delivers events every minute: <code>php tools\\dispatch-integrations.php</code>. Delivery resumes where it stopped after an outage, so no events are lost. New integrations start from now. Use <b>Deliver now</b> to push pending events immediately.</div>
  <div class="card mb-3"><div id="inGrid"></div></div>
  <div class="card mb-3"><div class="d-flex flex-wrap justify-content-between align-items-center p-3 pb-0"><h6 class="text-white mb-0"><i class="fa-solid fa-key me-2 text-info"></i>SIEM pull API tokens</h6>${w ? addBtn('Create token', 'tkAdd') : ''}</div>
    <div class="px-3 pt-2 small text-secondary">Poll with <code>Authorization: Bearer &lt;token&gt;</code>: <code>GET ${E(location.origin + BASE)}${E(d.pull.events)}?since_id=0&amp;limit=500&amp;types=audit.event,shadow_ai.detected&amp;format=json|jsonl|cef</code> and <code>${E(d.pull.usage)}</code> for the raw usage stream. Use the returned <code>next_id</code> as the next <code>since_id</code>.</div><div id="tkGrid"></div></div>`;

  const secretOnce = (r, what) => { if (!r.signing_secret) return; const m = secretModal(what, r.signing_secret, 'Shown once. Use it to verify the X-SAIP-Signature header (HMAC-SHA256 of "timestamp.body").'); $('#secCopy', m.el).onclick = () => copyText(r.signing_secret); };
  const form = i => {
    const m = formModal({ title: i ? `Edit ${i.name}` : 'Add integration', icon: 'fa-plug', size: 'modal-lg', submit: i ? 'Save' : 'Create',
      values: i ? { ...i, active: !!+i.active, secret: '', ...Object.fromEntries(Object.keys(d.event_types).map(t => ['ev:' + t, i.events.includes(t)])) } : { kind: 'webhook', format: 'json', protocol: 'udp', port: 514, active: true, ...Object.fromEntries(Object.keys(d.event_types).map(t => ['ev:' + t, t !== 'usage.event'])) },
      note: 'Webhook and Splunk URLs must be public https:// addresses. Secrets are stored encrypted and never shown again.',
      fields: [{ name: 'name', label: 'Name', required: true, maxlength: 100, col: 6 }, { name: 'kind', label: 'Type', type: 'select', col: 6, options: [['webhook', 'Webhook (HTTPS, signed JSON or CEF)'], ['splunk_hec', 'Splunk HTTP Event Collector'], ['syslog', 'Syslog (UDP/TCP, CEF or JSON)']], readonly: !!i },
        { name: 'url', label: 'Endpoint URL', col: 12, mono: true, placeholder: 'https://siem.example.com/hooks/saip', maxlength: 500 },
        { name: 'host', label: 'Syslog host', col: 5, mono: true }, { name: 'port', label: 'Port', type: 'number', col: 3 }, { name: 'protocol', label: 'Protocol', type: 'select', options: ['udp', 'tcp'], col: 4 },
        { name: 'format', label: 'Format', type: 'select', col: 4, options: [['json', 'JSON'], ['cef', 'CEF (ArcSight, QRadar, Sentinel)']] },
        { name: 'secret', label: i ? 'Replace secret / token (optional)' : 'Signing secret / HEC token', type: 'password', col: 8, help: 'Webhook: leave blank to generate a signing secret. Splunk: the HEC token (required).' },
        ...Object.entries(d.event_types).map(([t, l]) => ({ name: 'ev:' + t, label: `${evLabel[t]}: ${l}`, type: 'checkbox', col: 12 })), { name: 'active', label: 'Active', type: 'checkbox', col: 12 }],
      save: v => { const b = { name: v.name, kind: v.kind, url: v.url, host: v.host, port: v.port, protocol: v.protocol, format: v.format, secret: v.secret, active: v.active, events: Object.keys(d.event_types).filter(t => v['ev:' + t]) }; return api('POST', i ? 'integrations/' + i.id : 'integrations', b); },
      done: r => { toast(i ? 'Integration saved' : 'Integration created', 'success'); const go = () => integrations(); if (r.signing_secret) { secretOnce(r, 'Webhook signing secret'); document.querySelector('.modal').addEventListener('hidden.bs.modal', go); } else go(); } });
    const field = n => m.el.querySelector(`[name="${n}"]`)?.closest('[class*="col-md-"]');
    const sync = () => { const k = m.el.querySelector('[name=kind]').value; ['url'].forEach(n => field(n).style.display = k === 'syslog' ? 'none' : ''); ['host', 'port', 'protocol'].forEach(n => field(n).style.display = k === 'syslog' ? '' : 'none'); field('format').style.display = k === 'splunk_hec' ? 'none' : ''; };
    m.el.querySelector('[name=kind]').onchange = sync; sync();
  };
  const remove = rs => deleteFlow({ path: 'integrations/delete', ids: rs.map(r => +r.id), title: rs.length > 1 ? `Delete ${rs.length} integrations` : 'Delete integration', describe: () => '<p class="small mb-0">Delivery stops immediately. Events already delivered are not recalled.</p>', done: 'Deleted' });
  const deliveries = async i => { const { deliveries: rows } = await api('GET', `integrations/${i.id}/deliveries`); modal(`Deliveries &mdash; ${E(i.name)}`, `<div id="dvGrid"></div>`, '', 'modal-lg'); new DataGrid({ el: '#dvGrid', id: 'deliveries', rows, pageSize: 10, sort: { key: 'id', dir: 'desc' }, empty: 'No deliveries yet.', columns: [
    { key: 'created_at', label: 'Time (local time)', nowrap: true, render: r => fmtDT(r.created_at) }, { key: 'status', label: 'Result', filter: 'select', render: r => `<span class="pill ${r.status === 'ok' ? 'p-ok' : 'p-bad'}">${E(r.status).toUpperCase()}</span>` }, { key: 'event_count', label: 'Events', num: true }, { key: 'http_status', label: 'HTTP', num: true }, { key: 'duration_ms', label: 'ms', num: true }, { key: 'error', label: 'Error', render: r => `<span class="small text-danger">${E(r.error || '')}</span>` }] }); };
  new DataGrid({ el: '#inGrid', id: 'integrations', rows: d.integrations, exportName: 'integrations', sort: { key: 'name', dir: 'asc' }, empty: 'No integrations yet. Add a webhook, Splunk HEC or syslog destination.', onRowClick: i => deliveries(i),
    columns: [{ key: 'name', label: 'Name', filter: 'text', render: i => `<b class="text-white">${E(i.name)}</b>` }, { key: 'kind', label: 'Type', filter: 'select', text: i => kindLabel[i.kind], render: i => `<span class="pill p-info">${E(kindLabel[i.kind])}</span>` },
      { key: 'dest', label: 'Destination', text: dest, render: i => `<span class="mono small">${E(dest(i))}</span>` }, { key: 'format', label: 'Format', filter: 'select', render: i => E(i.format.toUpperCase()) },
      { key: 'events', label: 'Events', text: i => i.events.map(e => evLabel[e]).join(', '), render: i => i.events.map(e => `<span class="pill p-mute me-1">${E(evLabel[e])}</span>`).join('') },
      { key: 'state', label: 'Status', filter: 'select', text: state, render: i => `<span class="pill ${{ Healthy: 'p-ok', Failing: 'p-bad', Paused: 'p-mute', Waiting: 'p-warn' }[state(i)]}">${state(i).toUpperCase()}</span>${i.last_error ? `<div class="small text-danger" style="max-width:260px;overflow-wrap:anywhere">${E(i.last_error)}</div>` : ''}` },
      { key: 'last_success_at', label: 'Last delivered', nowrap: true, render: i => `<span class="small">${fmtDT(i.last_success_at)}</span>` }],
    actions: i => [{ inline: true, key: 'deliveries', label: 'Delivery log', icon: 'fa-clock-rotate-left' }].concat(w ? [{ inline: true, key: 'test', label: 'Send test event', icon: 'fa-paper-plane' }, { inline: true, key: 'edit', label: 'Edit', icon: 'fa-pen' }, { key: 'run', label: 'Deliver pending now', icon: 'fa-play' }, ...(i.kind === 'webhook' ? [{ key: 'rotate', label: 'Rotate signing secret', icon: 'fa-rotate' }] : []), { key: 'reset', label: 'Reset failures', icon: 'fa-eraser' }] : [], dlt ? [{ inline: true, key: 'delete', label: 'Delete', icon: 'fa-trash', danger: true }] : []),
    onAction: async (k, i) => {
      if (k === 'deliveries') return deliveries(i); if (k === 'edit') return form(i);
      if (k === 'delete') { if (await remove([i])) integrations(); return; }
      if (k === 'test') return act(async () => { const r = await api('POST', `integrations/${i.id}/test`, {}); toast(r.ok ? `Test delivered (${r.ms} ms)` : 'Test failed: ' + r.error, r.ok ? 'success' : 'danger'); });
      if (k === 'run') return act(async () => { const r = await api('POST', `integrations/${i.id}/run`, {}); const x = r.results[0]; toast(x ? (x.status === 'ok' ? `${x.sent} event(s) delivered` : x.status === 'idle' ? 'Nothing pending' : 'Failed: ' + x.error) : 'Nothing due', x && x.status === 'failed' ? 'danger' : 'success'); integrations(); });
      if (k === 'rotate') return act(async () => { const r = await api('POST', 'integrations/' + i.id, { name: i.name, rotate_secret: true }); secretOnce(r, 'New signing secret'); });
      if (k === 'reset') return act(async () => { await api('POST', 'integrations/' + i.id, { name: i.name, reset_failures: true }); toast('Failure counter reset', 'success'); integrations(); }); } });
  new DataGrid({ el: '#tkGrid', id: 'tokens', rows: d.tokens, exportName: 'api-tokens', pageSize: 10, empty: 'No tokens. Create one to let a SIEM pull events.',
    columns: [{ key: 'name', label: 'Token', filter: 'text', render: t => `<b>${E(t.name)}</b>` }, { key: 'scope', label: 'Scope' }, { key: 'last_used_at', label: 'Last used', render: t => t.last_used_at ? fmtDT(t.last_used_at) : '<span class="text-secondary">never</span>' }, { key: 'created_by', label: 'Created by' }, { key: 'created_at', label: 'Created', render: t => fmtDT(t.created_at) }],
    actions: () => dlt ? [{ inline: true, key: 'revoke', label: 'Revoke token', icon: 'fa-trash', danger: true }] : [],
    onAction: async (k, t) => { if (await deleteFlow({ path: 'integration-tokens/delete', ids: [+t.id], title: 'Revoke token', describe: () => '<p class="small mb-0">Any SIEM using this token stops working immediately.</p>', button: 'Revoke', done: 'Token revoked' })) integrations(); } });
  if ($('#inAdd')) $('#inAdd').onclick = () => form(null);
  if ($('#tkAdd')) $('#tkAdd').onclick = () => formModal({ title: 'Create API token', icon: 'fa-key', submit: 'Create', fields: [{ name: 'name', label: 'Name (for example the SIEM it is for)', required: true, maxlength: 100 }],
    save: v => api('POST', 'integration-tokens', v), done: r => { const m = secretModal('API token', r.token, r.note); $('#secCopy', m.el).onclick = () => copyText(r.token); m.el.addEventListener('hidden.bs.modal', integrations); } });
}

/* ---------------- Authentication (Google Sign-In) ---------------- */
async function authentication() {
  const d = await api('GET', 'settings/auth'), g = d.google;
  const roleOpts = [['viewer', 'Management viewer'], ['auditor', 'Auditor'], ['it_admin', 'IT administrator']];
  $('#view').innerHTML = pageHead('<i class="fa-brands fa-google text-info"></i> Authentication', 'Sign-in options for every company. Internal sign-in (username and password) always stays available; Google Sign-In is added on top.') + `
  <div class="row g-3"><div class="col-lg-8"><div class="card p-3"><div class="d-flex justify-content-between align-items-center mb-2"><h6 class="text-white mb-0">Google Sign-In (OpenID Connect)</h6><span class="pill ${g.enabled ? 'p-ok' : 'p-mute'}">${g.enabled ? 'ENABLED' : 'DISABLED'}</span></div>
    <form id="gForm" novalidate><div class="row g-2">
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="gEn" ${g.enabled ? 'checked' : ''}><label class="form-check-label" for="gEn">Allow "Sign in with Google" on the login page</label></div></div>
      <div class="col-md-7"><label class="form-label small">OAuth client ID</label><input id="gId" class="form-control form-control-sm mono" value="${E(g.client_id)}" placeholder="123456789-abc.apps.googleusercontent.com" maxlength="200"></div>
      <div class="col-md-5"><label class="form-label small">Client secret ${g.has_secret ? '<span class="pill p-ok ms-1">STORED</span>' : ''}</label><input id="gSec" type="password" class="form-control form-control-sm" autocomplete="new-password" placeholder="${g.has_secret ? 'unchanged (type to replace)' : 'paste the client secret'}"></div>
      <div class="col-12"><label class="form-label small">Allowed email domains <span class="text-secondary">(comma separated; empty = any verified Google account that already has a console account)</span></label><input id="gDom" class="form-control form-control-sm mono" value="${E(g.allowed_domains)}" placeholder="example.com, example.org"></div>
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="gAuto" ${g.auto_provision ? 'checked' : ''}><label class="form-check-label" for="gAuto">Create accounts automatically for allowed domains on first sign-in</label></div></div>
      <div class="col-md-6"><label class="form-label small">Default role for new accounts</label><select id="gRole" class="form-select form-select-sm">${roleOpts.map(([v, l]) => `<option value="${v}" ${g.default_role === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="col-md-6"><label class="form-label small">Default company</label><select id="gTen" class="form-select form-select-sm"><option value="0">- choose -</option>${d.tenants.map(t => `<option value="${t.id}" ${+g.default_tenant_id === +t.id ? 'selected' : ''}>${E(t.name)}</option>`).join('')}</select></div>
      <div class="col-12"><label class="form-label small">Authorized redirect URI <span class="text-secondary">(register exactly this in Google Cloud Console)</span></label><div class="input-group input-group-sm"><input class="form-control mono" id="gRed" readonly value="${E(g.redirect_uri)}"><button class="btn btn-outline-secondary" type="button" id="gCopy"><i class="fa-regular fa-copy"></i> Copy</button></div></div>
      <div class="col-12"><label class="form-label small">Redirect URI override <span class="text-secondary">(only when behind a proxy; must end with /auth/google/callback)</span></label><input id="gOv" class="form-control form-control-sm mono" value="${E(g.redirect_override)}"></div></div>
      <div class="mt-3 d-flex gap-2"><button class="btn btn-info btn-sm" id="gSave" type="button"><i class="fa-solid fa-floppy-disk"></i> Save</button><button class="btn btn-outline-secondary btn-sm" id="gTest" type="button"><i class="fa-solid fa-plug-circle-check"></i> Test connection</button></div></form><div id="gOut" class="small mt-3"></div></div></div>
    <div class="col-lg-4"><div class="card p-3 small"><h6 class="text-white">Set up in 4 steps</h6><ol class="mb-2 ps-3"><li>In Google Cloud Console: <b>APIs &amp; Services &rarr; Credentials &rarr; Create credentials &rarr; OAuth client ID</b> (Web application).</li><li>Add the redirect URI shown here.</li><li>Paste the client ID and secret, set the allowed domain(s), enable, and save.</li><li>Link people: they sign in with Google once and are matched by verified email, or enable automatic account creation.</li></ol>
      <div class="text-secondary">Accounts linked to Google: <b class="text-white">${d.google_users}</b>. In <a href="#users">User Management</a> you can turn off password sign-in for a user (Google only) or unlink Google. The secret is stored encrypted and never shown.</div></div></div></div>`;
  $('#gCopy').onclick = () => copyText(g.redirect_uri, 'Redirect URI copied');
  $('#gSave').onclick = () => act(async () => { const r = await api('POST', 'settings/auth', { google: { enabled: $('#gEn').checked, client_id: $('#gId').value, client_secret: $('#gSec').value, allowed_domains: $('#gDom').value, auto_provision: $('#gAuto').checked, default_role: $('#gRole').value, default_tenant_id: +$('#gTen').value, redirect_override: $('#gOv').value } }); toast('Authentication settings saved', 'success'); authentication(); });
  $('#gTest').onclick = () => act(async () => { const r = await api('POST', 'settings/auth/test', {}); const ok = (b, t) => `<div>${b ? '<i class="fa-solid fa-circle-check text-success"></i>' : '<i class="fa-solid fa-circle-xmark text-danger"></i>'} ${t}</div>`; $('#gOut').innerHTML = ok(r.reachable, 'Google is reachable from this server') + ok(r.client_id_set && r.client_id_format, 'Client ID is set and looks like a Google client ID') + ok(r.secret_set, 'Client secret is stored'); });
}

/* ---------------- Sysmon capabilities ---------------- */
async function sysmonModal() {
  const d = await api('GET', 'sysmon');
  const pill = s => `<span class="pill ${{ collected: 'p-ok', optional: 'p-info', not_collected: 'p-mute' }[s]}">${{ collected: 'COLLECTED', optional: d.monitoring.network_events ? 'ENABLED' : 'OPTIONAL (OFF)', not_collected: 'NOT COLLECTED' }[s]}</span>`;
  const xml = sel => `<!-- SAIP Sysmon configuration: collects only what SAIP uses. Apply with: Sysmon64.exe -c sysmon-config.xml -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- ${sel.has(22) ? 'Event ID 22: DNS queries (exclude noise)' : 'DNS disabled'} -->
    <RuleGroup name="dns" groupRelation="or">
      <DnsQuery onmatch="${sel.has(22) ? 'exclude' : 'include'}">${sel.has(22) ? `
        <QueryName condition="end with">.local</QueryName>
        <QueryName condition="end with">.arpa</QueryName>
        <QueryName condition="end with">.windowsupdate.com</QueryName>
        <QueryName condition="end with">.msftncsi.com</QueryName>
      ` : ''}</DnsQuery>
    </RuleGroup>
    ${sel.has(3) ? `<!-- Event ID 3: outbound HTTPS only, private addresses skipped -->
    <RuleGroup name="net-in" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">443</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
    <RuleGroup name="net-out" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
        <DestinationIp condition="begin with">10.</DestinationIp>
        <DestinationIp condition="begin with">192.168.</DestinationIp>
        <DestinationIp condition="begin with">169.254.</DestinationIp>
        <DestinationIp condition="is">::1</DestinationIp>
        <Initiated condition="is">false</Initiated>
      </NetworkConnect>
    </RuleGroup>` : `<RuleGroup name="net" groupRelation="or"><NetworkConnect onmatch="include"/></RuleGroup>`}
    <!-- An empty "include" logs nothing: these types are not used by SAIP. -->
    <RuleGroup name="off" groupRelation="or">
      <ProcessCreate onmatch="include"/><FileCreateTime onmatch="include"/><ProcessTerminate onmatch="include"/><ImageLoad onmatch="include"/>
      <FileCreate onmatch="include"/><RegistryEvent onmatch="include"/><FileCreateStreamHash onmatch="include"/><FileDelete onmatch="include"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
`;
  const m = modal('<i class="fa-solid fa-microchip me-2 text-info"></i>Sysmon capabilities', `
    <ul class="nav nav-tabs mb-3" role="tablist">${[['smEv', 'Events tracked', 'fa-list'], ['smJs', 'JSON data', 'fa-code'], ['smMap', 'Field mapping', 'fa-right-left'], ['smCfg', 'Config builder', 'fa-gears']].map(([id, l, ic], i) => `<li class="nav-item"><button class="nav-link ${i ? '' : 'active'}" data-bs-toggle="tab" data-bs-target="#${id}" type="button"><i class="fa-solid ${ic} me-1"></i>${l}</button></li>`).join('')}</ul>
    <div class="tab-content">
      <div class="tab-pane fade show active" id="smEv"><p class="small text-secondary">Sysmon (System Monitor) records detailed Windows activity as events. SAIP deliberately reads only what identifies AI-service use; everything else is left alone to protect privacy and keep volume low. Enable network connections under Collectors &amp; Monitoring &rarr; Monitoring options.</p><div id="smEvGrid"></div></div>
      <div class="tab-pane fade" id="smJs">${d.samples.map((s, i) => `<div class="mb-3"><div class="d-flex justify-content-between align-items-center mb-1"><b class="small text-white">${E(s.title)}</b><button class="btn btn-sm btn-outline-secondary" data-cp="${i}"><i class="fa-regular fa-copy"></i> Copy</button></div><pre class="feed small" style="color:#1f2340;white-space:pre-wrap;overflow-x:auto">${E(s.body)}</pre></div>`).join('')}</div>
      <div class="tab-pane fade" id="smMap"><p class="small text-secondary">How a Sysmon event field becomes a field in the JSON the collector sends. The computer name always comes from the authenticated collector, never from the payload.</p><div id="smMapGrid"></div></div>
      <div class="tab-pane fade" id="smCfg"><p class="small text-secondary">Pick the events to log, copy or download the Sysmon configuration, and apply it on the workstation.</p>
        <div class="mb-2"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" checked disabled id="cf22"><label class="form-check-label small" for="cf22">Event ID 22: DNS queries (required)</label></div><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="cf3" ${d.monitoring.network_events ? 'checked' : ''}><label class="form-check-label small" for="cf3">Event ID 3: network connections (optional; for browsers that bypass Windows DNS)</label></div></div>
        <pre class="feed small" id="cfOut" style="color:#1f2340;white-space:pre-wrap;max-height:320px;overflow:auto"></pre>
        <div class="d-flex gap-2"><button class="btn btn-sm btn-outline-secondary" id="cfCopy"><i class="fa-regular fa-copy"></i> Copy</button><button class="btn btn-sm btn-info" id="cfDl"><i class="fa-solid fa-download"></i> Download sysmon-config.xml</button></div></div></div>`, '', 'modal-xl');
  new DataGrid({ el: $('#smEvGrid', m.el), id: 'sysmon-events', rows: d.events, rowKey: 'id', pageSize: 25, exportName: 'sysmon-events', sort: { key: 'id', dir: 'asc' }, columns: [
    { key: 'id', label: 'Event ID', num: true, render: r => `<b class="text-white">${r.id}</b>` }, { key: 'name', label: 'Event', filter: 'text', render: r => `<b>${E(r.name)}</b><div class="small text-secondary">${E(r.what)}</div>` }, { key: 'status', label: 'SAIP', filter: 'select', text: r => ({ collected: 'Collected', optional: 'Optional', not_collected: 'Not collected' })[r.status], render: r => pill(r.status) },
    { key: 'fields', label: 'Key fields', render: r => `<span class="small mono">${E(r.fields)}</span>` }, { key: 'saip', label: 'How SAIP uses it', render: r => `<span class="small text-secondary">${E(r.saip)}</span>` }] });
  new DataGrid({ el: $('#smMapGrid', m.el), id: 'sysmon-map', rows: d.mapping.map((r, i) => ({ ...r, _i: i })), rowKey: '_i', pageSize: 25, exportName: 'sysmon-field-mapping', columns: [
    { key: 'eid', label: 'Event ID', filter: 'select' }, { key: 'sysmon', label: 'Sysmon field', render: r => `<span class="mono">${E(r.sysmon)}</span>` }, { key: 'json', label: 'SAIP JSON field', render: r => `<span class="mono text-info">${E(r.json)}</span>` }, { key: 'note', label: 'Notes', render: r => `<span class="small text-secondary">${E(r.note)}</span>` }] });
  m.el.querySelectorAll('[data-cp]').forEach(b => b.onclick = () => copyText(d.samples[+b.dataset.cp].body));
  const draw = () => { const sel = new Set([22]); if ($('#cf3', m.el).checked) sel.add(3); $('#cfOut', m.el).textContent = xml(sel); };
  $('#cf3', m.el).onchange = draw; draw();
  $('#cfCopy', m.el).onclick = () => copyText($('#cfOut', m.el).textContent);
  $('#cfDl', m.el).onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([$('#cfOut', m.el).textContent], { type: 'application/xml' })); a.download = 'sysmon-config.xml'; a.click(); };
}
