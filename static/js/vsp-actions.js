commit 7909613729cde325cee69998bdc96f7441df3684
Author: quynhanh1706vp-byte <quynhanh1706vp@gmail.com>
Date:   Thu Apr 23 02:28:57 2026 +0700

    feat(ui): add vsp-actions.js

diff --git a/static/js/vsp-actions.js b/static/js/vsp-actions.js
new file mode 100644
index 0000000..078c193
--- /dev/null
+++ b/static/js/vsp-actions.js
@@ -0,0 +1,149 @@
+/*!
+ * VSP Actions — event delegation layer
+ * 
+ * Replaces inline event handlers (onclick=, onchange=, etc.) with CSP-safe
+ * data-vsp-* attributes. Preserves the semantics of inline handlers:
+ *   - `this` is bound to the element
+ *   - `event` is available in scope
+ *   - Expression syntax (not just function names) is supported
+ *
+ * Migration:
+ *   onclick="foo(1)"                  →  data-vsp-click="foo(1)"
+ *   onchange="this.value = ''"        →  data-vsp-change="this.value = ''"
+ *   onclick="if(event.target===this)closeQS()"
+ *                                     →  data-vsp-click="if(event.target===this)closeQS()"
+ *
+ * CSP requirement: script-src must allow 'unsafe-eval' because expressions
+ * are executed via new Function(). This is a pragmatic compromise — it
+ * removes 'unsafe-inline' (the primary XSS vector) while allowing legacy
+ * inline-style expressions to keep working during migration.
+ */
+(function () {
+  'use strict';
+
+  // Cache compiled expressions — same expression appears many times in the DOM
+  // (e.g. "closeModal()" on every close button). Compiling once gives a measurable
+  // boost on the larger panels.
+  var fnCache = Object.create(null);
+
+  function compile(expr) {
+    if (fnCache[expr]) return fnCache[expr];
+    try {
+      // Wrap in try/catch so a single bad expression doesn't kill the handler
+      var fn = new Function('event', expr);
+      fnCache[expr] = fn;
+      return fn;
+    } catch (e) {
+      console.error('[vsp-actions] compile error:', expr, e);
+      fnCache[expr] = null;
+      return null;
+    }
+  }
+
+  function exec(el, expr, ev) {
+    var fn = compile(expr);
+    if (!fn) return;
+    try {
+      fn.call(el, ev);
+    } catch (e) {
+      console.error('[vsp-actions] runtime error:', expr, e);
+    }
+  }
+
+  // ─── Bubbling events: 1 listener at document ────────────────────────────
+  var BUBBLE_EVENTS = {
+    click:    'vspClick',
+    change:   'vspChange',
+    input:    'vspInput',
+    keydown:  'vspKeydown',
+    submit:   'vspSubmit',
+    paste:    'vspPaste',
+    mouseover: 'vspMouseover',
+    mouseout:  'vspMouseout'
+  };
+
+  Object.keys(BUBBLE_EVENTS).forEach(function (evType) {
+    var dsKey = BUBBLE_EVENTS[evType];
+    document.addEventListener(evType, function (ev) {
+      // Walk up from target to document; fire handler on first matching ancestor.
+      // Matches native bubbling semantics: inner-first.
+      var node = ev.target;
+      while (node && node !== document && node.nodeType === 1) {
+        var expr = node.dataset && node.dataset[dsKey];
+        if (expr) {
+          exec(node, expr, ev);
+          // Don't break — allow multiple levels to handle same event if both
+          // have data-vsp-* set. Matches how inline onclick bubbles via the
+          // DOM event system even when intermediate nodes also have onclick.
+          // If you need stopPropagation, the handler code can call it itself.
+        }
+        node = node.parentNode;
+      }
+    }, true); // capture=true so we see events before stopPropagation inside
+  });
+
+  // ─── Non-bubbling events: direct listeners via walker ───────────────────
+  // mouseenter/mouseleave do not bubble. onload on <img> fires once, early.
+  var DIRECT_EVENTS = {
+    mouseenter: 'vspMouseenter',
+    mouseleave: 'vspMouseleave',
+    load:       'vspLoad'
+  };
+
+  function attachDirect(root) {
+    Object.keys(DIRECT_EVENTS).forEach(function (evType) {
+      var dsKey = DIRECT_EVENTS[evType];
+      // Build attribute selector: data-vsp-mouseenter etc.
+      var attrName = 'data-vsp-' + evType;
+      var elements = root.querySelectorAll('[' + attrName + ']');
+      for (var i = 0; i < elements.length; i++) {
+        var el = elements[i];
+        // Idempotency: skip if we've already attached for this event type
+        var attachedKey = '_vspAttached_' + evType;
+        if (el[attachedKey]) continue;
+        el[attachedKey] = true;
+
+        (function (node, key) {
+          node.addEventListener(evType, function (ev) {
+            exec(node, node.dataset[key], ev);
+          });
+        })(el, dsKey);
+      }
+    });
+  }
+
+  // Attach on DOM ready; re-scan when mutations add new nodes.
+  function scanNow() {
+    attachDirect(document);
+  }
+
+  if (document.readyState === 'loading') {
+    document.addEventListener('DOMContentLoaded', scanNow);
+  } else {
+    scanNow();
+  }
+
+  // Rescan on DOM mutations so dynamically-added elements get listeners.
+  // Scoped to subtree additions; ignores attribute changes.
+  if (typeof MutationObserver !== 'undefined') {
+    var mo = new MutationObserver(function (mutations) {
+      for (var i = 0; i < mutations.length; i++) {
+        var m = mutations[i];
+        if (m.addedNodes && m.addedNodes.length) {
+          for (var j = 0; j < m.addedNodes.length; j++) {
+            var node = m.addedNodes[j];
+            if (node.nodeType === 1) attachDirect(node);
+          }
+        }
+      }
+    });
+    mo.observe(document.documentElement, { childList: true, subtree: true });
+  }
+
+  // Expose for debugging
+  window.__vspActions = {
+    exec: exec,
+    rescan: scanNow,
+    cacheSize: function () { return Object.keys(fnCache).length; }
+  };
+})();
