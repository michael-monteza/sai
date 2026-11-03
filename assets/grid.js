'use strict';
/**
 * DataGrid: the one table component used across the console (client-side data).
 * Search, per-column filters, click-to-sort, page size + pager, row selection with bulk actions,
 * per-row action menu, and CSV export of the filtered view. Sort and page size persist per grid id.
 *
 *   new DataGrid({ el: '#host', id: 'inventory', rows, columns: [{ key, label, render?, sort?, text?, filter?: 'select'|'text', num?, nowrap?, noexport? }],
 *     rowKey: 'id', actions: row => [{ key, label, icon?, danger?, divider? }], onAction: (key, row) => {}, bulk: [{ label, icon?, danger?, fn: rows => {} }],
 *     onRowClick: row => {}, rowClass: row => '', exportName: 'file', toolbar: '<html>', empty: 'text', pageSize: 25 })
 * Depends on E() and $() from app.js (used at call time). Every cell is escaped by default; `render` must escape itself.
 */
class DataGrid {
  constructor(o) {
    this.o = Object.assign({ rowKey: 'id', pageSize: 25, empty: 'No records match.', exportName: 'export' }, o);
    this.host = typeof o.el === 'string' ? document.querySelector(o.el) : o.el;
    this.cols = o.columns;
    this.rows = o.rows || [];
    this.remote = typeof o.server === 'function'; this.reqId = 0; this.facetKey = '';
    const saved = this.restore();
    this.q = ''; this.f = {}; this.page = 1; this.sel = new Set();
    this.sort = saved.sort && this.cols.some(c => c.key === saved.sort.key) ? saved.sort : (o.sort || null);
    this.size = [10, 25, 50, 100].includes(saved.size) ? saved.size : this.o.pageSize;
    this.build();
    this.update();
  }

  /* ---- state ---- */
  restore() { try { return JSON.parse(localStorage.getItem('saip.grid.' + this.o.id) || '{}'); } catch { return {}; } }
  persist() { try { localStorage.setItem('saip.grid.' + this.o.id, JSON.stringify({ sort: this.sort, size: this.size })); } catch { /* storage unavailable */ } }
  key(r) { return String(r[this.o.rowKey]); }
  val(c, r) { return c.sort ? c.sort(r) : r[c.key]; }
  txt(c, r) { const v = c.text ? c.text(r) : r[c.key]; return v == null ? '' : (isUtcStamp(v) ? localDT(v) : String(v)); }
  hasSelect() { return !!(this.o.bulk && this.o.bulk.length); }
  hasActions() { return typeof this.o.actions === 'function'; }

  /* ---- skeleton (built once so the search box keeps focus) ---- */
  build() {
    const o = this.o, filterable = this.cols.some(c => c.filter);
    this.host.innerHTML = `<div class="dg">
      <div class="dg-bar d-flex flex-wrap gap-2 align-items-center p-3 pb-2">
        <div class="input-group input-group-sm dg-search" style="max-width:320px"><span class="input-group-text"><i class="fa-solid fa-magnifying-glass"></i></span><input type="search" class="form-control" placeholder="Search" aria-label="Search" data-dg="q"></div>
        ${filterable ? '<button class="btn btn-sm btn-outline-secondary" data-dg="clear" title="Clear search and filters"><i class="fa-solid fa-filter-circle-xmark"></i> Clear</button>' : ''}
        <span class="small text-secondary" data-dg="count"></span>
        <div class="ms-auto d-flex flex-wrap gap-2 align-items-center">${o.toolbar || ''}
          <button class="btn btn-sm btn-outline-secondary" data-dg="export" title="Download the filtered rows as CSV"><i class="fa-solid fa-file-csv"></i> Export view</button></div></div>
      <div class="dg-bulk d-none px-3 pb-2"><div class="alert alert-info py-2 mb-0 d-flex flex-wrap gap-2 align-items-center small"><b data-dg="selcount"></b>
        ${(o.bulk || []).map((b, i) => `<button class="btn btn-sm ${b.danger ? 'btn-outline-danger' : 'btn-outline-secondary'}" data-dg-bulk="${i}">${b.icon ? `<i class="fa-solid ${b.icon}"></i> ` : ''}${E(b.label)}</button>`).join('')}
        <button class="btn btn-sm btn-link ms-auto" data-dg="unsel">Clear selection</button></div></div>
      <div class="table-responsive"><table class="table table-sm table-hover align-middle mb-0"><thead>
        <tr>${this.hasSelect() ? '<th style="width:34px"><input type="checkbox" class="form-check-input" data-dg="all" title="Select all filtered rows"></th>' : ''}
          ${this.cols.map((c, i) => `<th class="${c.num ? 'text-end ' : ''}${c.nowrap ? 'text-nowrap ' : ''}dg-th" data-dg-sort="${i}" role="button" tabindex="0">${E(c.label)} <i class="fa-solid fa-sort dg-ind text-secondary"></i></th>`).join('')}
          ${this.hasActions() ? '<th class="text-end" style="width:1%">Actions</th>' : ''}</tr>
        ${filterable ? `<tr class="dg-filters">${this.hasSelect() ? '<th></th>' : ''}${this.cols.map((c, i) => `<th>${this.filterCell(c, i)}</th>`).join('')}${this.hasActions() ? '<th></th>' : ''}</tr>` : ''}
      </thead><tbody data-dg="body"></tbody></table></div>
      <div class="d-flex flex-wrap gap-2 justify-content-between align-items-center p-3 pt-2">
        <div class="small text-secondary d-flex align-items-center gap-2">Rows <select class="form-select form-select-sm w-auto" data-dg="size">${[10, 25, 50, 100].map(n => `<option ${n === this.size ? 'selected' : ''}>${n}</option>`).join('')}</select><span data-dg="info"></span></div>
        <nav aria-label="Pages"><ul class="pagination pagination-sm mb-0" data-dg="pager"></ul></nav></div></div>`;
    const h = this.host;
    h.querySelector('[data-dg="q"]').oninput = e => { clearTimeout(this.qt); this.qt = setTimeout(() => { this.q = e.target.value.trim().toLowerCase(); this.page = 1; this.update(); }, 200); };
    h.querySelectorAll('[data-dg-f]').forEach(el => el[el.tagName === 'SELECT' ? 'onchange' : 'oninput'] = e => { this.f[el.dataset.dgF] = this.remote ? e.target.value.trim() : e.target.value.trim().toLowerCase(); this.page = 1; this.update(); });
    const clr = h.querySelector('[data-dg="clear"]'); if (clr) clr.onclick = () => { this.q = ''; this.f = {}; h.querySelector('[data-dg="q"]').value = ''; h.querySelectorAll('[data-dg-f]').forEach(el => el.value = ''); this.page = 1; this.update(); };
    h.querySelectorAll('[data-dg-sort]').forEach(th => { const go = () => this.toggleSort(this.cols[+th.dataset.dgSort].key); th.onclick = go; th.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } }; });
    h.querySelector('[data-dg="size"]').onchange = e => { this.size = +e.target.value; this.page = 1; this.persist(); this.update(); };
    h.querySelector('[data-dg="export"]').onclick = () => this.exportCsv();
    const all = h.querySelector('[data-dg="all"]'); if (all) all.onchange = e => { this.filtered.forEach(r => e.target.checked ? this.sel.add(this.key(r)) : this.sel.delete(this.key(r))); this.update(); };
    const un = h.querySelector('[data-dg="unsel"]'); if (un) un.onclick = () => { this.sel.clear(); this.update(); };
    h.querySelectorAll('[data-dg-bulk]').forEach(b => b.onclick = () => this.o.bulk[+b.dataset.dgBulk].fn(this.selected()));
    // delegated row events
    this.body = h.querySelector('[data-dg="body"]');
    this.body.onclick = e => {
      const act = e.target.closest('[data-dg-act]'); if (act) { e.preventDefault(); const r = this.byKey(act.dataset.dgRow); if (r) this.o.onAction(act.dataset.dgAct, r); return; }
      if (e.target.closest('input,button,a,.dropdown-menu,.dropdown')) return;
      const tr = e.target.closest('tr[data-dg-row]'); if (tr && this.o.onRowClick) { const r = this.byKey(tr.dataset.dgRow); if (r) this.o.onRowClick(r); }
    };
    this.body.onchange = e => { const cb = e.target.closest('[data-dg-sel]'); if (!cb) return; cb.checked ? this.sel.add(cb.dataset.dgSel) : this.sel.delete(cb.dataset.dgSel); this.updateBulk(); };
  }

  filterCell(c, i) {
    if (!c.filter) return '';
    if (c.filter === 'select') {
      const vals = [...new Set(this.rows.map(r => this.txt(c, r)).filter(Boolean))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      return `<select class="form-select form-select-sm" data-dg-f="${i}" aria-label="Filter ${E(c.label)}"><option value="">All</option>${vals.map(v => `<option value="${E(v.toLowerCase())}">${E(v)}</option>`).join('')}</select>`;
    }
    return `<input class="form-control form-control-sm" data-dg-f="${i}" placeholder="Filter" aria-label="Filter ${E(c.label)}">`;
  }

  /* ---- data ---- */
  byKey(k) { return this.rows.find(r => this.key(r) === k); }
  selected() { return this.rows.filter(r => this.sel.has(this.key(r))); }
  setRows(rows) { this.rows = rows; const keys = new Set(rows.map(r => this.key(r))); this.sel = new Set([...this.sel].filter(k => keys.has(k))); this.update(); }
  toggleSort(key) {
    this.sort = !this.sort || this.sort.key !== key ? { key, dir: 'asc' } : this.sort.dir === 'asc' ? { key, dir: 'desc' } : null;
    this.page = 1; this.persist(); this.update();
  }
  compute() {
    const sel = [...this.host.querySelectorAll('[data-dg-f]')];
    let rows = this.rows.filter(r => {
      if (this.q && !this.cols.some(c => this.txt(c, r).toLowerCase().includes(this.q))) return false;
      return sel.every(el => { const v = this.f[el.dataset.dgF]; if (!v) return true; const t = this.txt(this.cols[+el.dataset.dgF], r).toLowerCase(); return el.tagName === 'SELECT' ? t === v : t.includes(v); });
    });
    if (this.sort) {
      const c = this.cols.find(x => x.key === this.sort.key), d = this.sort.dir === 'asc' ? 1 : -1;
      rows = rows.map((r, i) => [r, i]).sort(([a, i], [b, j]) => {
        const x = this.val(c, a), y = this.val(c, b);
        if (x == null || x === '') return y == null || y === '' ? i - j : 1;
        if (y == null || y === '') return -1;
        const nx = Number(x), ny = Number(y);
        const cmp = !Number.isNaN(nx) && !Number.isNaN(ny) && (c.num || typeof x === 'number') ? nx - ny : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: 'base' });
        return cmp ? cmp * d : i - j;
      }).map(p => p[0]);
    }
    return rows;
  }

  /* ---- drawing ---- */
  update() {
    if (this.remote) return this.fetchRemote();
    this.paint(this.compute(), null);
  }

  /** Server-side mode: o.server({ page, size, q, filters:{col:value}, sort:{key,dir} }) -> { rows, total, facets?:{col:[values]} }. */
  fetchRemote() {
    clearTimeout(this.rt);
    this.rt = setTimeout(async () => {
      const id = ++this.reqId;
      this.host.classList.add('dg-loading');
      try {
        const f = Object.fromEntries(Object.entries(this.f).filter(([, v]) => v).map(([i, v]) => [this.cols[+i].key, v]));
        const r = await this.o.server({ page: this.page, size: this.size, q: this.q, filters: f, sort: this.sort });
        if (id !== this.reqId) return;
        this.rows = r.rows; this.setFacets(r.facets);
        this.paint(r.rows, r.total);
      } catch (e) { if (e.message !== 'signed out') toast(e.message, 'danger'); }
      finally { if (id === this.reqId) this.host.classList.remove('dg-loading'); }
    }, 60);
  }

  /** Fills select filters from server-provided distinct values (keeps the current selection). */
  setFacets(fc) {
    if (!fc) return;
    const key = JSON.stringify(fc); if (key === this.facetKey) return; this.facetKey = key;
    this.host.querySelectorAll('select[data-dg-f]').forEach(sel => {
      const c = this.cols[+sel.dataset.dgF], vals = fc[c.key]; if (!vals) return;
      const cur = sel.value;
      sel.innerHTML = '<option value="">All</option>' + vals.map(v => `<option value="${E(v)}" ${v === cur ? 'selected' : ''}>${E(v)}</option>`).join('');
    });
  }

  paint(list, remoteTotal) {
    const remote = remoteTotal != null;
    this.filtered = list;
    const total = remote ? remoteTotal : list.length, pages = Math.max(1, Math.ceil(total / this.size));
    if (remote && this.page > pages) { this.page = pages; return this.fetchRemote(); }
    if (!remote) this.page = Math.min(this.page, pages);
    const start = (this.page - 1) * this.size, slice = remote ? list : list.slice(start, start + this.size);
    const span = this.cols.length + (this.hasSelect() ? 1 : 0) + (this.hasActions() ? 1 : 0);
    this.body.innerHTML = slice.map(r => this.rowHtml(r)).join('') || `<tr><td colspan="${span}" class="text-center text-secondary py-4">${E(this.o.empty)}</td></tr>`;
    const $h = s => this.host.querySelector(s);
    $h('[data-dg="count"]').textContent = remote || total === this.rows.length ? `${total} record${total === 1 ? '' : 's'}` : `${total} of ${this.rows.length} records`;
    $h('[data-dg="info"]').textContent = total ? `${start + 1}-${start + slice.length} of ${total}` : '0 of 0';
    $h('[data-dg="pager"]').innerHTML = this.pagerHtml(pages);
    $h('[data-dg="pager"]').onclick = e => { const a = e.target.closest('[data-dg-page]'); if (!a) return; e.preventDefault(); this.page = +a.dataset.dgPage; this.update(); };
    this.host.querySelectorAll('[data-dg-sort]').forEach(th => {
      const c = this.cols[+th.dataset.dgSort], on = this.sort && this.sort.key === c.key;
      th.querySelector('.dg-ind').className = 'fa-solid dg-ind ' + (on ? (this.sort.dir === 'asc' ? 'fa-sort-up text-info' : 'fa-sort-down text-info') : 'fa-sort text-secondary');
      th.setAttribute('aria-sort', on ? (this.sort.dir === 'asc' ? 'ascending' : 'descending') : 'none');
    });
    this.updateBulk();
  }
  updateBulk() {
    const n = this.sel.size, bar = this.host.querySelector('.dg-bulk');
    bar.classList.toggle('d-none', !n);
    this.host.querySelector('[data-dg="selcount"]').textContent = n + ' selected';
    const all = this.host.querySelector('[data-dg="all"]');
    if (all) { const f = this.filtered || []; const c = f.filter(r => this.sel.has(this.key(r))).length; all.checked = f.length > 0 && c === f.length; all.indeterminate = c > 0 && c < f.length; }
  }
  rowHtml(r) {
    const k = E(this.key(r));
    const acts = this.hasActions() ? (this.o.actions(r) || []) : [];
    const inline = acts.filter(a => a.inline), rest = acts.filter(a => !a.inline);
    while (rest.length && (rest[0].divider)) rest.shift();
    const icons = inline.map(a => `<button class="btn btn-sm btn-icon ${a.danger ? 'btn-outline-danger' : 'btn-outline-secondary'}" data-dg-act="${E(a.key)}" data-dg-row="${k}" title="${E(a.label)}" aria-label="${E(a.label)}"><i class="fa-solid ${a.icon || 'fa-circle'}"></i></button>`).join('');
    const menu = rest.length ? `<div class="dropdown d-inline-block"><button class="btn btn-sm btn-icon btn-outline-secondary" data-bs-toggle="dropdown" data-bs-strategy="fixed" aria-label="More actions" title="More actions" aria-expanded="false"><i class="fa-solid fa-ellipsis-vertical"></i></button>
      <ul class="dropdown-menu dropdown-menu-end">${rest.map(a => a.divider ? '<li><hr class="dropdown-divider"></li>' : `<li><a class="dropdown-item ${a.danger ? 'text-danger' : ''}" href="#" data-dg-act="${E(a.key)}" data-dg-row="${k}">${a.icon ? `<i class="fa-solid ${a.icon} me-2"></i>` : ''}${E(a.label)}</a></li>`).join('')}</ul></div>` : '';
    return `<tr data-dg-row="${k}" class="${this.o.onRowClick ? 'clickable ' : ''}${this.o.rowClass ? this.o.rowClass(r) : ''}">
      ${this.hasSelect() ? `<td><input type="checkbox" class="form-check-input" data-dg-sel="${k}" ${this.sel.has(this.key(r)) ? 'checked' : ''} aria-label="Select row"></td>` : ''}
      ${this.cols.map(c => `<td class="${c.num ? 'text-end ' : ''}${c.nowrap ? 'text-nowrap ' : ''}${c.class || ''}">${c.render ? c.render(r) : E(this.txt(c, r))}</td>`).join('')}
      ${this.hasActions() ? `<td class="text-end text-nowrap">${icons} ${menu}</td>` : ''}</tr>`;
  }
  pagerHtml(pages) {
    if (pages <= 1) return '';
    const p = this.page, set = new Set([1, pages, p - 1, p, p + 1]); if (p <= 3) [2, 3, 4].forEach(x => set.add(x)); if (p >= pages - 2) [pages - 1, pages - 2, pages - 3].forEach(x => set.add(x));
    const nums = [...set].filter(x => x >= 1 && x <= pages).sort((a, b) => a - b);
    const li = (label, to, dis, act) => `<li class="page-item ${dis ? 'disabled' : ''} ${act ? 'active' : ''}"><a class="page-link" href="#" data-dg-page="${to}">${label}</a></li>`;
    let out = li('&laquo;', p - 1, p === 1), prev = 0;
    nums.forEach(n => { if (n - prev > 1) out += '<li class="page-item disabled"><span class="page-link">&hellip;</span></li>'; out += li(n, n, false, n === p); prev = n; });
    return out + li('&raquo;', p + 1, p === pages);
  }

  exportCsv() {
    if (this.remote && this.o.exportUrl) { const f = Object.fromEntries(Object.entries(this.f).filter(([, v]) => v).map(([i, v]) => [this.cols[+i].key, v])); location.href = this.o.exportUrl({ q: this.q, filters: f, sort: this.sort }); return; }
    const cols = this.cols.filter(c => !c.noexport);
    const cell = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const csv = '﻿' + [cols.map(c => cell(c.label)).join(',')].concat(this.filtered.map(r => cols.map(c => cell(this.txt(c, r))).join(','))).join('\r\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    a.download = `${this.o.exportName}-${new Date().toISOString().slice(0, 10)}.csv`; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
}

/**
 * Standard delete flow: asks the server what would be removed (preview), shows it, and only deletes on confirmation.
 * describe(impact) returns extra HTML. Resolves true when something was deleted.
 */
async function deleteFlow({ path, ids, title, intro = '', describe = () => '', extra = {}, button = 'Delete permanently', done = 'Deleted' }) {
  const pv = await act(() => api('POST', path, { ids, preview: true, ...extra }));
  if (!pv) return false;
  const i = pv.preview, names = (i.names || []).slice(0, 8).map(n => `<li>${E(n)}</li>`).join('') + ((i.names || []).length > 8 ? `<li class="text-secondary">and ${i.names.length - 8} more</li>` : '');
  return new Promise(resolve => {
    const m = modal(E(title), `${intro}<ul class="small">${names}</ul>${describe(i)}<div class="small text-danger mt-2"><i class="fa-solid fa-triangle-exclamation me-1"></i>This cannot be undone. The deletion is recorded in the audit log.</div>`,
      `<button class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-sm btn-danger" id="dfGo">${E(button)}</button>`);
    let ok = false;
    m.el.addEventListener('hidden.bs.modal', () => resolve(ok));
    $('#dfGo', m.el).onclick = async () => { const r = await act(() => api('POST', path, { ids, ...extra })); if (r) { ok = true; toast(done, 'success'); } m.close(); };
  });
}
