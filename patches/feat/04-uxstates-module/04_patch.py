#!/usr/bin/env python3
"""
FEAT-04: Create shared VSPUXState module + inject script tag into index.html.

Provides 4 functions for skeleton/empty/error UI states reusable across
all panels. Replaces inline _vmShowSkel / _schSetState helpers from
FEAT-02 / FEAT-03 with one unified API.

Files created:
  static/vsp_uxstates.js         (canonical, served at /vsp_uxstates.js)
  static/js/vsp_uxstates.js      (mirror — both kept in sync per repo convention)

Files modified:
  static/index.html              (one new <script> tag after line 8827)
"""
import sys, shutil, pathlib, re

ROOT = pathlib.Path(".")
JS_CONTENT = '''/* VSPUXState v1.0 — unified skeleton/empty/error UI states for all panels.
 * Created by FEAT-04. Use this instead of inline helpers.
 *
 * API:
 *   VSPUXState.skeleton(target, opts?)  - paint shimmer rows
 *   VSPUXState.empty(target, msg, retryFn?) - paint empty state with optional retry
 *   VSPUXState.error(target, msg, retryFn?) - paint error state with retry button
 *   VSPUXState.clear(target)            - remove any state classes
 *
 * `target` can be: HTMLElement, "#id" string, or ".class" string.
 * `opts` for skeleton: { rows: 5, height: 18, kind: "table"|"list"|"card" }
 *
 * Auto-injects required CSS into <head> on first call.
 */
(function (global) {
  "use strict";
  if (global.VSPUXState) return; // idempotent

  var CSS_INJECTED = false;
  var CSS = [
    ".vsp-uxs-shimmer{height:18px;border-radius:4px;",
    "background:linear-gradient(90deg,var(--surface,#1e2128) 0%,var(--border,rgba(255,255,255,.07)) 50%,var(--surface,#1e2128) 100%);",
    "background-size:200% 100%;animation:vsp-uxs-shimmer 1.2s ease-in-out infinite}",
    "@keyframes vsp-uxs-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}",
    ".vsp-uxs-empty,.vsp-uxs-error{text-align:center;padding:32px 16px;font-size:12px}",
    ".vsp-uxs-empty{color:var(--t3,#5a6278)}",
    ".vsp-uxs-error{color:var(--red,#ef4444)}",
    ".vsp-uxs-icon{font-size:28px;margin-bottom:8px;line-height:1}",
    ".vsp-uxs-msg{margin-bottom:8px}",
    ".vsp-uxs-retry{margin-top:8px;padding:4px 12px;font-size:11px;",
    "background:var(--surface,#1e2128);border:1px solid var(--border,rgba(255,255,255,.07));",
    "border-radius:4px;color:var(--t1,#e8eaf0);cursor:pointer}",
    ".vsp-uxs-retry:hover{background:var(--border,rgba(255,255,255,.1))}"
  ].join("");

  function injectCSS() {
    if (CSS_INJECTED) return;
    var s = document.createElement("style");
    s.id = "vsp-uxs-styles";
    s.textContent = CSS;
    (document.head || document.documentElement).appendChild(s);
    CSS_INJECTED = true;
  }

  function resolve(target) {
    if (!target) return null;
    if (target.nodeType === 1) return target;
    if (typeof target === "string") return document.querySelector(target);
    return null;
  }

  function detectKind(el) {
    if (!el) return "card";
    var tag = (el.tagName || "").toLowerCase();
    if (tag === "tbody" || el.closest("table")) return "table";
    if (tag === "ul" || tag === "ol") return "list";
    return "card";
  }

  function colspan(el) {
    var tbl = el && el.closest && el.closest("table");
    if (!tbl) return 1;
    var head = tbl.querySelector("thead tr");
    return head ? head.children.length : (tbl.querySelector("tr") ? tbl.querySelector("tr").children.length : 1);
  }

  function skeleton(target, opts) {
    injectCSS();
    var el = resolve(target);
    if (!el) return;
    opts = opts || {};
    var rows = opts.rows || 5;
    var h = opts.height || 18;
    var kind = opts.kind || detectKind(el);
    var bar = '<div class="vsp-uxs-shimmer" style="height:' + h + 'px"></div>';
    var html;
    if (kind === "table") {
      var cs = colspan(el);
      var row = '<tr class="vsp-uxs-skel-row"><td colspan="' + cs + '" style="padding:6px">' + bar + '</td></tr>';
      html = "";
      for (var i = 0; i < rows; i++) html += row;
    } else if (kind === "list") {
      var li = '<li class="vsp-uxs-skel-row" style="padding:6px;list-style:none">' + bar + "</li>";
      html = "";
      for (var j = 0; j < rows; j++) html += li;
    } else {
      var div = '<div class="vsp-uxs-skel-row" style="padding:6px 0">' + bar + "</div>";
      html = "";
      for (var k = 0; k < rows; k++) html += div;
    }
    el.innerHTML = html;
  }

  function _stateHTML(cls, icon, msg, retryFn, kind, cs) {
    var hasRetry = typeof retryFn === "function";
    var fnId = hasRetry ? "vspuxs_retry_" + Math.random().toString(36).slice(2, 9) : "";
    if (hasRetry) global[fnId] = retryFn;
    var inner =
      '<div class="' + cls + '">' +
      '<div class="vsp-uxs-icon">' + icon + "</div>" +
      '<div class="vsp-uxs-msg">' + (msg || "") + "</div>" +
      (hasRetry
        ? '<button class="vsp-uxs-retry" onclick="window.' + fnId + '();delete window.' + fnId + '">Retry</button>'
        : "") +
      "</div>";
    if (kind === "table") return '<tr><td colspan="' + cs + '">' + inner + "</td></tr>";
    return inner;
  }

  function empty(target, msg, retryFn) {
    injectCSS();
    var el = resolve(target);
    if (!el) return;
    var kind = detectKind(el);
    el.innerHTML = _stateHTML("vsp-uxs-empty", "∅", msg || "No data", retryFn, kind, colspan(el));
  }

  function error(target, msg, retryFn) {
    injectCSS();
    var el = resolve(target);
    if (!el) return;
    var kind = detectKind(el);
    el.innerHTML = _stateHTML("vsp-uxs-error", "⚠", msg || "Error", retryFn, kind, colspan(el));
  }

  function clear(target) {
    var el = resolve(target);
    if (el) el.innerHTML = "";
  }

  global.VSPUXState = { skeleton: skeleton, empty: empty, error: error, clear: clear, VERSION: "1.0" };
  if (typeof console !== "undefined" && console.log) {
    console.log("[VSPUXState] v1.0 loaded — VSPUXState.{skeleton,empty,error,clear}");
  }
})(typeof window !== "undefined" ? window : this);
'''

# ─── 1. Write JS to both static/ and static/js/ ────────────────
TARGETS = [
    ROOT / "static" / "vsp_uxstates.js",
    ROOT / "static" / "js" / "vsp_uxstates.js",
]
for t in TARGETS:
    if t.exists():
        BAK = t.with_suffix(".js.bak.feat04")
        if not BAK.exists():
            shutil.copy2(t, BAK)
            print(f"Backup: {BAK}")
    t.parent.mkdir(parents=True, exist_ok=True)
    t.write_text(JS_CONTENT, encoding="utf-8")
    print(f"Wrote: {t} ({len(JS_CONTENT)} bytes)")

# ─── 2. Inject <script> tag into static/index.html ─────────────
INDEX = ROOT / "static" / "index.html"
INDEX_BAK = INDEX.with_suffix(".html.bak.feat04")
src = INDEX.read_text(encoding="utf-8")

MARKER = "<!-- FEAT-04: VSPUXState shared module -->"
if MARKER in src:
    print("skip: index.html already has FEAT-04 marker")
else:
    if not INDEX_BAK.exists():
        shutil.copy2(INDEX, INDEX_BAK)
        print(f"Backup: {INDEX_BAK}")
    # Inject AFTER the line `<script src="/vsp_dast_panel.js"></script>` (line 8827)
    anchor = '<script src="/vsp_dast_panel.js"></script>'
    if anchor not in src:
        print(f"FAIL: anchor not found: {anchor}")
        sys.exit(1)
    new_block = anchor + "\n    " + MARKER + '\n    <script src="/vsp_uxstates.js"></script>'
    src = src.replace(anchor, new_block, 1)
    INDEX.write_text(src, encoding="utf-8")
    print(f"Injected <script src=/vsp_uxstates.js> into {INDEX}")

print("Done.")
