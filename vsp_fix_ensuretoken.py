#!/usr/bin/env python3
"""
VSP Fix: ensureToken hoisting
Injects an early stub so patch scripts v2.2+ can call ensureToken()
before the real definition loads at line ~7666.
"""
import sys, shutil, datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_ensurefix_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# Inject early stub right after <head> opens (before any other scripts)
STUB = """<script>
// ── GOV FIX: ensureToken early stub ──────────────────────────────────────
// Real implementation loads later (~line 7666). This stub queues calls
// until the real function is available, preventing ReferenceError in
// intermediate patch scripts (v2.2+).
window._ensureTokenQueue = [];
window._ensureTokenReady = false;
window.ensureToken = async function() {
  if (window._ensureTokenReady && window._realEnsureToken) {
    return window._realEnsureToken();
  }
  // Queue and wait
  return new Promise(function(resolve) {
    window._ensureTokenQueue.push(resolve);
  });
};
// Called by the real ensureToken when it loads
window._flushEnsureTokenQueue = function() {
  window._ensureTokenReady = true;
  var q = window._ensureTokenQueue || [];
  window._ensureTokenQueue = [];
  q.forEach(function(resolve) {
    window._realEnsureToken().then(resolve).catch(resolve);
  });
};
// ── END GOV FIX ──────────────────────────────────────────────────────────
</script>"""

# Also patch the real ensureToken definition to register itself
OLD_REAL = "window.ensureToken = async function() {"
NEW_REAL = """window._realEnsureToken = async function() {"""

FLUSH_INJECT = """
// GOV FIX: register real implementation + flush queue
window._realEnsureToken = window._realEnsureToken || window.ensureToken;
if (window._flushEnsureTokenQueue) window._flushEnsureTokenQueue();
"""

# Step 1: inject stub after <head>
if "<head>" in html:
    html = html.replace("<head>", "<head>\n" + STUB, 1)
    print("[+] Early ensureToken stub injected after <head>")
elif "<!DOCTYPE html>" in html:
    html = html.replace("<!DOCTYPE html>", "<!DOCTYPE html>\n" + STUB, 1)
    print("[+] Early ensureToken stub injected after DOCTYPE")

# Step 2: find the LAST definition of window.ensureToken (the real one ~line 7666)
# and add flush call after it
last_idx = html.rfind("window.ensureToken = async function()")
if last_idx != -1:
    # Find the closing }; of this function
    brace_start = html.find("{", last_idx)
    depth = 0
    i = brace_start
    while i < len(html):
        if html[i] == '{': depth += 1
        elif html[i] == '}':
            depth -= 1
            if depth == 0:
                # inject flush after closing };
                close_pos = i + 1
                # skip optional semicolon
                if close_pos < len(html) and html[close_pos] == ';':
                    close_pos += 1
                html = html[:close_pos] + "\n" + FLUSH_INJECT + html[close_pos:]
                print("[+] Flush call injected after real ensureToken definition")
                break
        i += 1
else:
    print("[!] Could not find window.ensureToken definition — appending flush to end")
    html = html.replace("</body>", f"<script>{FLUSH_INJECT}</script>\n</body>", 1)

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ ensureToken fix applied → {TARGET}")
print(f"   Backup → {bak}")
