/* VSP dom-safe helpers v1 (2026-04-21) — SEC-006 fix
 *
 * Replaces the 53 HIGH-risk template-literal innerHTML sites identified in
 * docs/sprint4/innerhtml-high-classified.csv with safer alternatives.
 *
 * API:
 *   safeText(el, text)          — 68% of HIGH sites (TEXT bucket)
 *   safeCreate(tag, opts)       — 23% of HIGH sites (STRUCTURED bucket)
 *   safeSetHTML(el, html)       —  9% of HIGH sites (DYNAMIC bucket, async)
 *
 * Include in <head> of panels that need it:
 *   <script src="/static/js/dom-safe.js"></script>
 *
 * Ref: docs/sprint4/SPRINT4-TRACKER.md
 * TODO(SEC-006 cleanup): once all 53 sites migrated, add gitleaks-style CI
 * check to fail any new PR that uses template-literal innerHTML.
 */
(function () {
  'use strict';
  if (window.__vspDomSafe) return;
  window.__vspDomSafe = true;

  var DOMPURIFY_CDN = 'https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js';
  var DOMPURIFY_SRI = 'sha384-2Ul6oiBTTTU83Giz/u6Tz+3zvKz3p2KqjwmQOT/+Bfpx2Tq5nXiPHC/QODZZhSnX';

  // Lazy-load DOMPurify only when DYNAMIC sites actually run.
  var _purify = null;
  var _purifyPromise = null;

  function loadPurify() {
    if (_purify) return Promise.resolve(_purify);
    if (window.DOMPurify) {
      _purify = window.DOMPurify;
      return Promise.resolve(_purify);
    }
    if (_purifyPromise) return _purifyPromise;

    _purifyPromise = new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = DOMPURIFY_CDN;
      s.integrity = DOMPURIFY_SRI;
      s.crossOrigin = 'anonymous';
      s.onload = function () {
        _purify = window.DOMPurify;
        if (!_purify) reject(new Error('DOMPurify failed to load'));
        else resolve(_purify);
      };
      s.onerror = function () {
        reject(new Error('DOMPurify CDN unreachable'));
      };
      document.head.appendChild(s);
    });
    return _purifyPromise;
  }

  /**
   * TEXT bucket — use when innerHTML was setting plain text or simple text
   * with variable interpolation. Sets textContent which cannot execute scripts.
   *
   * Example migration:
   *   el.innerHTML = `Score: ${score}`;
   *   →
   *   safeText(el, 'Score: ' + score);
   */
  window.safeText = function (el, text) {
    if (!el) return;
    el.textContent = (text === null || text === undefined) ? '' : String(text);
  };

  /**
   * STRUCTURED bucket — build DOM via createElement, safe from XSS by design.
   *
   * Example migration:
   *   el.innerHTML = `<div class="card"><span>Hello</span></div>`;
   *   →
   *   el.replaceChildren(safeCreate('div', {
   *     cls: 'card',
   *     children: [safeCreate('span', { text: 'Hello' })]
   *   }));
   */
  window.safeCreate = function (tag, opts) {
    opts = opts || {};
    var el = document.createElement(tag);

    if (opts.text != null) el.textContent = String(opts.text);
    if (opts.cls) el.className = String(opts.cls);

    if (opts.attrs) {
      Object.keys(opts.attrs).forEach(function (k) {
        var v = opts.attrs[k];
        // Block event handlers and javascript: URLs
        if (/^on/i.test(k)) {
          console.warn('[dom-safe] blocked event-handler attr:', k);
          return;
        }
        if (typeof v === 'string' && /^\s*javascript:/i.test(v)) {
          console.warn('[dom-safe] blocked javascript: URL for attr:', k);
          return;
        }
        el.setAttribute(k, String(v));
      });
    }

    if (opts.style) {
      // Style object — set individual properties, safer than cssText
      Object.keys(opts.style).forEach(function (k) {
        el.style[k] = String(opts.style[k]);
      });
    }

    if (opts.children && opts.children.length) {
      opts.children.forEach(function (c) {
        if (c == null) return;
        if (c instanceof Node) el.appendChild(c);
        else el.appendChild(document.createTextNode(String(c)));
      });
    }

    return el;
  };

  /**
   * DYNAMIC bucket — data from API/user may contain HTML that must render.
   * Uses DOMPurify to strip script/event/unsafe tags.
   *
   * Example migration:
   *   el.innerHTML = `<span>${apiResult.description}</span>`;
   *   →
   *   await safeSetHTML(el, '<span>' + apiResult.description + '</span>');
   */
  window.safeSetHTML = function (el, html) {
    if (!el) return Promise.resolve();
    return loadPurify().then(function (purify) {
      el.innerHTML = purify.sanitize(String(html == null ? '' : html), {
        ALLOWED_TAGS: [
          'b', 'i', 'em', 'strong', 'a', 'br', 'p', 'span', 'div',
          'ul', 'ol', 'li', 'code', 'pre',
          'table', 'tr', 'td', 'th', 'thead', 'tbody',
          'hr', 'small', 'sub', 'sup', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
        ],
        ALLOWED_ATTR: ['href', 'title', 'class', 'target', 'rel', 'style'],
        ALLOW_DATA_ATTR: false,
        FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'link'],
        FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover']
      });
    }).catch(function (err) {
      console.error('[dom-safe] safeSetHTML fallback to textContent:', err);
      el.textContent = String(html == null ? '' : html);
    });
  };
})();
