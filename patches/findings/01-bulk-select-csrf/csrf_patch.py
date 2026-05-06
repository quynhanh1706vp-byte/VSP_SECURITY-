#!/usr/bin/env python3
"""
F1.1 CSRF Patcher — adds X-CSRF-Token header + credentials:'include' to
the two POST calls in vsp_bulk_f1.js.

Why: The gateway's CSRFProtect middleware uses double-submit cookie pattern.
It expects:
  Cookie:        vsp_csrf=<token>
  Request hdr:   X-CSRF-Token: <same token>
The /api/v1/vulns/bulk[/undo] routes are NOT in csrfExemptPaths, so they
require the header. Without it: HTTP 403 "CSRF cookie missing".

Strategy:
  1. Inject helper `vspCsrfHeaders(base)` near `authFetch` definition.
  2. Replace `headers: { 'Content-Type': 'application/json' }` in the
     two bulk POST calls with `headers: vspCsrfHeaders({ 'Content-Type': 'application/json' })`.
  3. Add `credentials: 'include'` so the cookie is actually sent.

Idempotent: marker `VSP_F1_CSRF_PATCHED` checked.

Usage: python3 csrf_patch.py path/to/vsp_bulk_f1.js
"""
import sys
import os
import re

MARKER = "// VSP_F1_CSRF_PATCHED"

# Helper to inject right after authFetch function definition
HELPER_BLOCK = """  // VSP_F1_CSRF_PATCHED — read vsp_csrf cookie + add to headers (double-submit pattern)
  function vspCsrfHeaders(base) {
    base = base || {};
    try {
      var m = document.cookie.match(/(?:^|;\\s*)vsp_csrf=([^;]+)/);
      if (m && m[1]) base['X-CSRF-Token'] = decodeURIComponent(m[1]);
    } catch (e) { /* malformed cookie — let request fail naturally */ }
    return base;
  }
"""

# Anchor: end of authFetch function
AUTHFETCH_ANCHOR = """  function authFetch(url, opts) {
    return (window.vspAuthFetch || window.fetch)(url, opts || {});
  }
"""

AUTHFETCH_REPLACE = AUTHFETCH_ANCHOR + HELPER_BLOCK

# Patterns for the two POST calls — we add credentials and wrap headers
# Match pattern carefully (not regex, exact strings to be safe)
POST_BULK_OLD = """      authFetch('/api/v1/vulns/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: action, cve_ids: ids, metadata: metadata })
      })"""
POST_BULK_NEW = """      authFetch('/api/v1/vulns/bulk', {
        method: 'POST',
        credentials: 'include',
        headers: vspCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ action: action, cve_ids: ids, metadata: metadata })
      })"""

POST_UNDO_OLD = """      authFetch('/api/v1/vulns/bulk/undo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ undo_token: last.undoToken })
      })"""
POST_UNDO_NEW = """      authFetch('/api/v1/vulns/bulk/undo', {
        method: 'POST',
        credentials: 'include',
        headers: vspCsrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ undo_token: last.undoToken })
      })"""


def patch(path):
    if not os.path.exists(path):
        sys.stderr.write(f"ERROR: {path} not found\n")
        return 2

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    original = src

    if MARKER in src:
        print(f"[F1.1] Already CSRF-patched (marker present). Skipping.")
        return 0

    # Step 1: insert helper after authFetch
    if AUTHFETCH_ANCHOR not in src:
        sys.stderr.write("ERROR: authFetch anchor not found — file may differ from expected\n")
        return 3
    src = src.replace(AUTHFETCH_ANCHOR, AUTHFETCH_REPLACE, 1)

    # Step 2: patch bulk POST
    if POST_BULK_OLD not in src:
        sys.stderr.write("ERROR: bulk POST anchor not found\n")
        return 3
    src = src.replace(POST_BULK_OLD, POST_BULK_NEW, 1)

    # Step 3: patch undo POST
    if POST_UNDO_OLD not in src:
        sys.stderr.write("ERROR: undo POST anchor not found\n")
        return 3
    src = src.replace(POST_UNDO_OLD, POST_UNDO_NEW, 1)

    if src == original:
        sys.stderr.write("ERROR: no changes made\n")
        return 4

    # Atomic write
    tmp = path + ".tmp.f1csrf"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(src)
    os.replace(tmp, path)

    added = src.count("\n") - original.count("\n")
    print(f"[F1.1] Patched {path} (+{added} lines, CSRF header + credentials added to 2 POSTs)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: csrf_patch.py path/to/vsp_bulk_f1.js\n")
        sys.exit(1)
    sys.exit(patch(sys.argv[1]))
