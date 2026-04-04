#!/usr/bin/env python3
"""
VSP Fix: restore ensureToken definition that was cut by login patch.
Simply injects the function right after TOKEN initialization.
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_tokenfix2_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# The login patch replaced the auto-login block which contained ensureToken.
# We inject ensureToken right after TOKEN init line, before govLoginSubmit.
ANCHOR = "window.TOKEN = localStorage.getItem('vsp_token') || '';"

ENSURE_TOKEN_FN = """
// ── ensureToken: returns true if TOKEN available, else tries localStorage ──
async function ensureToken() {
  if (window.TOKEN) return true;
  var stored = localStorage.getItem('vsp_token');
  if (stored) {
    // Validate JWT expiry
    try {
      var parts = stored.split('.');
      if (parts.length === 3) {
        var payload = JSON.parse(atob(parts[1]));
        if (payload.exp && payload.exp * 1000 > Date.now()) {
          window.TOKEN = stored;
          return true;
        } else {
          localStorage.removeItem('vsp_token');
          return false;
        }
      }
    } catch(e) {}
    window.TOKEN = stored;
    return true;
  }
  return false;
}
"""

if ANCHOR in html:
    # Only inject if ensureToken is not already defined before this point
    anchor_pos = html.find(ANCHOR)
    before = html[:anchor_pos]
    if "async function ensureToken" not in before:
        html = html.replace(ANCHOR, ANCHOR + "\n" + ENSURE_TOKEN_FN, 1)
        print("[+] ensureToken restored after TOKEN init")
    else:
        print("[=] ensureToken already defined before anchor — no change needed")
else:
    print("[!] Anchor not found, trying fallback...")
    # fallback: inject before govLoginSubmit
    FALLBACK = "async function govLoginSubmit()"
    if FALLBACK in html:
        html = html.replace(FALLBACK, ENSURE_TOKEN_FN + "\n" + FALLBACK, 1)
        print("[+] ensureToken injected before govLoginSubmit (fallback)")
    else:
        print("[!] Could not find injection point")
        sys.exit(1)

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Fix applied → {TARGET}")
print(f"   Backup → {bak}")
print("""
What changed:
  - ensureToken() restored: checks window.TOKEN → localStorage → JWT expiry
  - No auto-login to hardcoded credentials (kept intentionally removed)
  - All patch scripts (v2.2+) calling ensureToken() will now work correctly
""")
