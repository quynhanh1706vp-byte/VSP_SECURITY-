/* Generic table pagination — opt-in via `data-vsp-paginate="<pageSize>"` on
 * any <tbody> or list element. We don't touch the panel's render code; instead
 * a MutationObserver re-paginates whenever the loader re-renders rows.
 *
 * Page controls are appended to the closest table's parent (or right after
 * the list element). State is per-element, kept on the DOM node itself so
 * re-renders don't lose it.
 */
(function(){
  'use strict';
  if (window._vspProPaginateLoaded) return;
  window._vspProPaginateLoaded = true;

  function _ensureControlsHost(target){
    var existing = target._paginateControls;
    if (existing && existing.isConnected) return existing;
    var host = document.createElement('div');
    host.className = 'vsp-paginate-controls';
    host.style.cssText = 'display:flex;gap:6px;align-items:center;justify-content:flex-end;padding:8px 4px;font-size:11px;color:var(--t3,#888);flex-wrap:wrap';
    // Find a good insertion point: after the table or list
    var anchor = target.closest('table') || target;
    if (anchor.parentNode) anchor.parentNode.insertBefore(host, anchor.nextSibling);
    target._paginateControls = host;
    return host;
  }

  function _renderControls(target){
    var host = _ensureControlsHost(target);
    var rows = Array.from(target.children).filter(function(c){
      // Skip empty-state placeholder rows (single colspan TD with class "empty"
      // or skeleton rows from VSPUXState).
      if (c.tagName !== 'TR' && c.tagName !== 'LI' && c.tagName !== 'DIV') return true;
      var hasEmpty = c.querySelector && c.querySelector('.empty, .vsp-uxs-skel-row, .vsp-uxs-empty, .vsp-uxs-error');
      var single = c.children && c.children.length === 1 && c.children[0].hasAttribute && c.children[0].hasAttribute('colspan');
      return !(hasEmpty || single);
    });
    var pageSize = parseInt(target.getAttribute('data-vsp-paginate') || '25', 10) || 25;
    var total = rows.length;
    var pages = Math.max(1, Math.ceil(total / pageSize));
    var page = Math.min(target._paginatePage || 1, pages);
    target._paginatePage = page;

    // Show/hide
    rows.forEach(function(r, i){
      var inPage = i >= (page-1)*pageSize && i < page*pageSize;
      r.style.display = inPage ? '' : 'none';
    });

    // Build controls
    if (total <= pageSize) {
      host.innerHTML = '';
      host.style.display = 'none';
      return;
    }
    host.style.display = 'flex';
    var btn = function(label, p, disabled, active){
      return '<button class="btn btn-sm" data-page="'+p+'"'
        + (disabled ? ' disabled' : '')
        + ' style="font-size:10px;padding:3px 8px'
        + (active ? ';background:var(--cyan,#06b6d4);color:#000' : '')
        + (disabled ? ';opacity:.4;cursor:default' : '')
        + '">'+label+'</button>';
    };
    var html = '<span class="mono-sm">'
      + ((page-1)*pageSize+1) + '–' + Math.min(page*pageSize, total)
      + ' of ' + total + '</span>';
    html += btn('‹', page-1, page<=1);
    var range = 2;
    for (var p = 1; p <= pages; p++) {
      if (p === 1 || p === pages || (p >= page-range && p <= page+range)) {
        html += btn(String(p), p, false, p===page);
      } else if (p === page-range-1 || p === page+range+1) {
        html += '<span style="padding:0 2px;color:var(--t4,#666)">…</span>';
      }
    }
    html += btn('›', page+1, page>=pages);
    host.innerHTML = html;
    host.querySelectorAll('button[data-page]').forEach(function(b){
      b.addEventListener('click', function(){
        var p = parseInt(b.getAttribute('data-page'), 10);
        if (!isNaN(p) && p >= 1 && p <= pages) {
          target._paginatePage = p;
          _renderControls(target);
        }
      });
    });
  }

  function _attach(target){
    if (target._paginateAttached) return;
    target._paginateAttached = true;
    target._paginatePage = 1;
    var obs = new MutationObserver(function(){
      // Re-render controls on next tick so loader's full innerHTML batch lands.
      clearTimeout(target._paginateDebounce);
      target._paginateDebounce = setTimeout(function(){ _renderControls(target); }, 30);
    });
    obs.observe(target, { childList: true });
    _renderControls(target);
  }

  function autoAttach(){
    document.querySelectorAll('[data-vsp-paginate]').forEach(_attach);
  }

  window.vspProAutoPaginate = autoAttach;
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function(){ setTimeout(autoAttach, 200); });
  } else {
    setTimeout(autoAttach, 200);
  }
  // Re-scan in case panels render lazily
  setTimeout(autoAttach, 1500);
  setTimeout(autoAttach, 3000);
})();
