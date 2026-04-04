#!/usr/bin/env python3
"""
VSP Gov Patch v1.2 — Sidebar SVG Icons
Replaces Unicode symbols (◈ ▦ ▷ ◎ ◐ ◫ ◷ ◉ ◧ ◆ ◌ ★ ↓ 📊) 
with clean SVG icons matching DoD/enterprise tool aesthetic.
"""
import sys, shutil, datetime, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/home/test/Data/GOLANG_VSP/static/index.html"

ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
bak = TARGET + f".bak_iconpatch_{ts}"
shutil.copy2(TARGET, bak)
print(f"[+] Backup → {bak}")

with open(TARGET, "r", encoding="utf-8") as f:
    html = f.read()

# ── SVG icon definitions (16x16 viewBox, stroke-based, clean) ───────────────
# Each icon is a self-contained SVG snippet to use inline
ICONS = {
    "dashboard": '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>',
    "scanlog":   '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 4h12M2 8h8M2 12h10"/><circle cx="13" cy="12" r="2.5"/><path d="M15 14l1.5 1.5"/></svg>',
    "runs":      '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="3,2 13,8 3,14" fill="none"/></svg>',
    "findings":  '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3.5"/><circle cx="8" cy="11.5" r="0.5" fill="currentColor"/></svg>',
    "remediation":'<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2.5A6.5 6.5 0 1 0 14.5 8"/><polyline points="10,1 13,2.5 11.5,5.5"/></svg>',
    "policy":    '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1L2 3.5v4C2 11 5 13.5 8 15c3-1.5 6-4 6-7.5v-4L8 1z"/></svg>',
    "audit":     '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="1" width="10" height="14" rx="1.5"/><path d="M6 5h4M6 8h4M6 11h2"/></svg>',
    "soc":       '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="6.5"/><circle cx="8" cy="8" r="2.5"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2"/></svg>',
    "governance":'<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1l7 4v1H1V5L8 1z"/><rect x="2" y="6" width="2" height="7"/><rect x="7" y="6" width="2" height="7"/><rect x="12" y="6" width="2" height="7"/><path d="M1 13h14"/></svg>',
    "fedramp":   '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1L2 3.5v4C2 11 5 13.5 8 15c3-1.5 6-4 6-7.5v-4L8 1z"/><path d="M5.5 8l2 2 3.5-3.5"/></svg>',
    "sbom":      '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="3" width="14" height="10" rx="1.5"/><path d="M5 3V2M8 3V2M11 3V2M4 7h2M4 10h2M8 7h4M8 10h3"/></svg>',
    "sla":       '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="6.5"/><polyline points="8,4 8,8 11,10"/></svg>',
    "analytics": '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1,12 5,7 8,9 12,4 15,6"/><path d="M1 14h14"/></svg>',
    "executive": '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1l1.8 3.6L14 5.3l-3 2.9.7 4.1L8 10.4l-3.7 1.9.7-4.1-3-2.9 4.2-.7z"/></svg>',
    "export":    '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1v9M4.5 6.5L8 10l3.5-3.5"/><path d="M3 11v2.5a.5.5 0 00.5.5h9a.5.5 0 00.5-.5V11"/></svg>',
    "users":     '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="5" r="3"/><path d="M1 14c0-3 2-5 5-5s5 2 5 5"/><path d="M11 3a3 3 0 010 4M15 14c0-2.5-1.5-4-3.5-4.5"/></svg>',
}

# ── CSS tweak for nav-icon to render SVG correctly ───────────────────────────
ICON_CSS = """
/* GOV PATCH v1.2 — SVG nav icons */
.nav-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  flex-shrink: 0;
  opacity: 0.7;
  transition: opacity 0.15s;
}
.nav-item:hover .nav-icon,
.nav-item.active .nav-icon { opacity: 1; }
.nav-icon svg { display: block; }
"""

html = html.replace("</style>", ICON_CSS + "\n</style>", 1)
print("[+] Icon CSS injected")

# ── Replace each nav-item icon span ──────────────────────────────────────────
replacements = [
    # (showPanel name, old icon text, icon key)
    ("'dashboard'",  "◈",  "dashboard"),
    ("'scanlog'",    "▦",  "scanlog"),
    ("'runs'",       "▷",  "runs"),
    ("'findings'",   "◎",  "findings"),
    ("'remediation'","◐",  "remediation"),
    ("'policy'",     "◫",  "policy"),
    ("'audit'",      "◷",  "audit"),
    ("'soc'",        "◉",  "soc"),
    ("'governance'", "◧",  "governance"),
    ("'compliance'", "◆",  "fedramp"),
    ("'sbom'",       "◌",  "sbom"),
    ("'sla'",        "◷",  "sla"),
    ("'analytics'",  "📊", "analytics"),
    ("'executive'",  "★",  "executive"),
    ("'export'",     "↓",  "export"),
    ("'users'",      "◈",  "users"),
]

count = 0
for panel, old_sym, icon_key in replacements:
    svg = ICONS[icon_key]
    old_span = f'<span class="nav-icon">{old_sym}</span>'
    new_span = f'<span class="nav-icon">{svg}</span>'

    # Find the nav-item line that references this panel
    pattern = re.compile(
        r"(onclick=\"showPanel\(" + re.escape(panel) + r"[^\"]*\)[^>]*>)"
        + re.escape(old_span),
        re.DOTALL
    )
    new_html, n = pattern.subn(r'\1' + new_span, html)
    if n > 0:
        html = new_html
        print(f"  [+] {panel:<20} {old_sym} → SVG ({icon_key})")
        count += 1
    else:
        # fallback: replace by symbol alone in nav-icon span near panel name
        old = f'<span class="nav-icon">{old_sym}</span>'
        # Only replace if it's on a line containing this panel
        lines = html.split('\n')
        for i, line in enumerate(lines):
            if f"showPanel({panel}" in line and old in line:
                lines[i] = line.replace(old, new_span, 1)
                count += 1
                print(f"  [+] {panel:<20} {old_sym} → SVG ({icon_key}) [line match]")
                break
        html = '\n'.join(lines)

print(f"\n[+] {count}/{len(replacements)} icons replaced")

# ── Also fix logo-icon to look sharper ───────────────────────────────────────
# Already looks fine, skip

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Icon patch complete → {TARGET}")
print(f"   Backup → {bak}")
print(f"""
What changed:
  - {count} nav icons replaced with clean 14px SVG stroke icons
  - Icons: stroke-based, currentColor, consistent 16x16 grid
  - .nav-icon CSS updated for proper SVG flex alignment
  - No logic changes
""")
