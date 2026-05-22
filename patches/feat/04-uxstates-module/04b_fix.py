#!/usr/bin/env python3
"""
FEAT-04b: Wire vsp_uxstates.js into Go gateway routes + whitelist in .gitignore.

Root cause: cmd/gateway/main.go has explicit `r.Get("/vsp_X.js", ...)` routes
for each static JS file. Without this, gateway returns 404 + text/plain MIME.
"""
import sys, shutil, pathlib, re

ROOT = pathlib.Path(".")

# ─── 1. Patch cmd/gateway/main.go — add route after vsp_dast_panel.js ───
GO = ROOT / "cmd/gateway/main.go"
GO_BAK = GO.with_suffix(".go.bak.feat04b")
src = GO.read_text(encoding="utf-8")

MARKER_GO = "// FEAT-04: vsp_uxstates.js"
if MARKER_GO in src:
    print("skip: gateway main.go already has FEAT-04 route")
else:
    if not GO_BAK.exists():
        shutil.copy2(GO, GO_BAK)
        print(f"Backup: {GO_BAK}")

    anchor = '''	r.Get("/vsp_dast_panel.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_dast_panel.js")
	})'''
    new_route = anchor + '''

	// FEAT-04: vsp_uxstates.js — shared skeleton/empty/error UI module
	r.Get("/vsp_uxstates.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/vsp_uxstates.js")
	})'''

    if anchor not in src:
        print(f"FAIL: anchor not found in {GO}")
        sys.exit(1)

    src = src.replace(anchor, new_route, 1)
    GO.write_text(src, encoding="utf-8")
    print(f"Added route in {GO}")

# ─── 2. Whitelist in .gitignore ───────────────────────────────────────
GI = ROOT / ".gitignore"
gi = GI.read_text(encoding="utf-8")

WL_LINES = [
    "!static/vsp_uxstates.js",
    "!static/js/vsp_uxstates.js",
]

# Check if both already present
need = [w for w in WL_LINES if w not in gi]
if not need:
    print("skip: .gitignore already whitelists vsp_uxstates.js")
else:
    GI_BAK = GI.with_suffix(".bak.feat04b")
    if not GI_BAK.exists():
        shutil.copy2(GI, GI_BAK)
        print(f"Backup: {GI_BAK}")

    # Append after the last !static/js/vsp_*.js whitelist line
    # Anchor: find last line matching "!static/" pattern, append after
    lines = gi.split("\n")
    # find the highest-index line that starts with !static/
    last_wl = -1
    for i, ln in enumerate(lines):
        if ln.startswith("!static/") and ln.endswith(".js"):
            last_wl = i
    if last_wl < 0:
        # fallback: append to end
        lines.append("# FEAT-04 whitelists")
        lines.extend(need)
    else:
        # insert right after last_wl
        for j, w in enumerate(need):
            lines.insert(last_wl + 1 + j, w)
    GI.write_text("\n".join(lines), encoding="utf-8")
    print(f"Whitelisted in .gitignore: {need}")

print("Done.")
