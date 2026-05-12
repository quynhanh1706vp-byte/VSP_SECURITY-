/* VSP — sidebar section collapse toggle.
   Loads on every page; finds <div class="nav-section"> blocks and makes
   their <div class="nav-section-label"> header click-to-toggle. State per
   label is persisted in localStorage so the layout sticks across reloads. */
(function(){
'use strict';
if (window.__VSP_SIDEBAR_COLLAPSE__) return;
window.__VSP_SIDEBAR_COLLAPSE__ = true;

var STORAGE_KEY = 'vsp_sidebar_collapsed_v1';

function loadState(){
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') || {}; }
  catch (_e) { return {}; }
}
function saveState(state){
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch (_e) {}
}

function injectCSS(){
  if (document.getElementById('vsp-sidebar-collapse-css')) return;
  var s = document.createElement('style');
  s.id = 'vsp-sidebar-collapse-css';
  s.textContent = [
    /* Make the label row look interactive — bigger chevron + hover bg so
       the affordance is obvious. */
    '.nav-section-label[data-vsp-toggle]{',
    '  cursor:pointer;user-select:none;display:flex !important;align-items:center;',
    '  justify-content:space-between;gap:6px;padding:4px 6px;border-radius:4px;',
    '  transition:color .12s,background .12s}',
    '.nav-section-label[data-vsp-toggle]:hover{color:#22d3ee;background:rgba(34,211,238,.06)}',
    '.nav-section-label[data-vsp-toggle] .vsp-chev{',
    '  font-size:11px;opacity:.85;color:#22d3ee;margin-left:auto;flex-shrink:0;',
    '  transition:transform .18s ease;display:inline-block;line-height:1}',
    '.nav-section.vsp-collapsed .nav-section-label[data-vsp-toggle] .vsp-chev{',
    '  transform:rotate(-90deg)}',
    /* Collapse: hide every child of nav-section except the label.
       :not() selector makes this resilient to varying child markup. */
    '.nav-section.vsp-collapsed > *:not(.nav-section-label){display:none !important}',
    /* When the sidebar collapses to icon-only (≤ 900px) the label is hidden
       — disable our toggle behaviour there so we don\'t leave sections in a
       weird state that would be unrecoverable from a 48px-wide rail. */
    '@media (max-width: 900px){',
    '  .nav-section-label[data-vsp-toggle]{cursor:default}',
    '  .nav-section.vsp-collapsed > *:not(.nav-section-label){display:revert !important}',
    '}'
  ].join('\n');
  document.head.appendChild(s);
}

function decorateSection(section, state){
  var label = section.querySelector(':scope > .nav-section-label');
  if (!label || label.hasAttribute('data-vsp-toggle')) return;

  // Use the label's plain text (first text node) as the storage key. The
  // gate-status section uses an inline-style label with badges — strip
  // those so the key is stable.
  var key = (label.textContent || '').trim().split(/\s+/).slice(0, 3).join(' ');
  if (!key) return;

  label.setAttribute('data-vsp-toggle', '1');
  label.setAttribute('title', 'Click to collapse / expand');

  // Append a chevron once. Skip if the label already contains badges that
  // ate the right edge (e.g. the "PRO" badge).
  if (!label.querySelector('.vsp-chev')){
    var chev = document.createElement('span');
    chev.className = 'vsp-chev';
    chev.textContent = '▾';
    label.appendChild(chev);
  }

  if (state[key]) section.classList.add('vsp-collapsed');

  label.addEventListener('click', function(e){
    // Allow toggle from anywhere inside the label EXCEPT real <a>/<button>
    // children (so an embedded link/badge keeps its native behaviour).
    if (e.target.closest('a, button')) return;
    section.classList.toggle('vsp-collapsed');
    var st = loadState();
    if (section.classList.contains('vsp-collapsed')) st[key] = 1;
    else delete st[key];
    saveState(st);
  });
}

function init(){
  injectCSS();
  var state = loadState();
  document.querySelectorAll('.nav-section').forEach(function(s){
    decorateSection(s, state);
  });
}

if (document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
// Also re-decorate after a short delay in case the sidebar is rendered async
// by other scripts (e.g. dynamic nav injection).
setTimeout(init, 600);
setTimeout(init, 2000);

(window.VSP_DEBUG && console.log('[VSP-SIDEBAR-COLLAPSE] active — click section labels to toggle'));
})();
