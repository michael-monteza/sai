'use strict';
/* Sidebar behaviour: live search over a fully visible menu, "/" shortcut, icon-rail toggle. Pure DOM. */
(() => {
  const input = document.getElementById('menu-search'), clearBtn = document.getElementById('clear-search'), noResults = document.getElementById('no-results');
  const groups = [...document.querySelectorAll('#nav-container .nav-group')];
  if (!input || !groups.length) return;
  const items = groups.flatMap(g => [...g.querySelectorAll('.nav-item')]);
  items.forEach(a => { a._label = a.querySelector('.label'); a._text = a._label.textContent; a._group = a.closest('.nav-group').querySelector('.group-title').textContent; });
  const esc = s => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const norm = s => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');

  // Matches the item name or its group name ("governance" lists both items of that group). Everything else hides; clearing shows the whole menu again.
  function filter() {
    const q = norm(input.value.trim());
    clearBtn.style.display = input.value ? 'grid' : 'none';
    let total = 0;
    groups.forEach(g => {
      let hits = 0;
      g.querySelectorAll('.nav-item').forEach(a => {
        const li = a.parentElement, i = q ? norm(a._text).indexOf(q) : -1, byGroup = q && norm(a._group).includes(q);
        const show = !q || i >= 0 || byGroup;
        li.hidden = !show;
        if (show) hits++;
        a._label.innerHTML = i >= 0 ? esc(a._text.slice(0, i)) + '<mark>' + esc(a._text.slice(i, i + q.length)) + '</mark>' + esc(a._text.slice(i + q.length)) : esc(a._text);
      });
      g.hidden = hits === 0;
      total += hits;
    });
    noResults.style.display = q && total === 0 ? 'block' : 'none';
  }
  input.addEventListener('input', filter);
  clearBtn.addEventListener('click', () => { input.value = ''; filter(); input.focus(); });
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { input.value = ''; filter(); input.blur(); }
    if (e.key === 'Enter') { const a = items.find(x => !x.parentElement.hidden); if (a) { location.hash = a.getAttribute('href'); input.value = ''; filter(); input.blur(); } }
    if (e.key === 'ArrowDown') { const a = items.find(x => !x.parentElement.hidden); if (a) { e.preventDefault(); a.focus(); } }
  });
  document.addEventListener('keydown', e => { if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) && !document.querySelector('.modal.show')) { e.preventDefault(); document.body.classList.remove('collapsed'); input.focus(); } });

  // Remember the rail/full choice.
  const KEY = 'saip.menu.rail';
  try { if (localStorage.getItem(KEY) === '1' && window.innerWidth >= 992) document.body.classList.add('collapsed'); } catch { /* storage unavailable */ }
  new MutationObserver(() => { try { localStorage.setItem(KEY, document.body.classList.contains('collapsed') ? '1' : '0'); } catch { /* ignore */ } }).observe(document.body, { attributes: true, attributeFilter: ['class'] });
})();
