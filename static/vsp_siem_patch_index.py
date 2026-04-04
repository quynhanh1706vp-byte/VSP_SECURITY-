#!/usr/bin/env python3
"""
vsp_siem_patch_index.py
Tự động patch index.html của VSP để thêm 4 SIEM panels.
Usage: python3 vsp_siem_patch_index.py [path/to/index.html]
"""
import sys, os, shutil, re
from datetime import datetime

# ── Config ───────────────────────────────────────────────────────
INDEX = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
    "~/Data/GOLANG_VSP/static/index.html"
)

# ── Kiểm tra file tồn tại ─────────────────────────────────────
if not os.path.exists(INDEX):
    print(f"❌  Không tìm thấy: {INDEX}")
    print(f"    Dùng: python3 {sys.argv[0]} /đường/dẫn/tới/index.html")
    sys.exit(1)

# ── Backup ────────────────────────────────────────────────────
ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
bak = INDEX + f".bak_{ts}"
shutil.copy2(INDEX, bak)
print(f"✓  Backup: {bak}")

html = open(INDEX, encoding="utf-8").read()
original = html

# ════════════════════════════════════════════════════════════════
# PATCH 1: Sidebar nav — thêm section SIEM
# Tìm vị trí sau nav-section "Reports" hoặc cuối </nav>
# ════════════════════════════════════════════════════════════════
SIEM_NAV = """
    <div class="nav-section">
      <div class="nav-section-label">SIEM</div>
      <button class="nav-item" onclick="showPanel('correlation',this)">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="4" r="2"/><circle cx="3" cy="12" r="2"/><circle cx="13" cy="12" r="2"/><path d="M8 6v2M8 8L3 10M8 8l5 2"/></svg></span>
        Correlation
        <span class="nav-badge" id="badge-incidents">0</span>
      </button>
      <button class="nav-item" onclick="showPanel('soar',this)">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="3,2 13,8 3,14"/></svg></span>
        SOAR
      </button>
      <button class="nav-item" onclick="showPanel('logsources',this)">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 4h12M2 8h8M2 12h10"/></svg></span>
        Log ingestion
      </button>
      <button class="nav-item" onclick="showPanel('threatintel',this)">
        <span class="nav-icon"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1L2 3.5v4C2 11 5 13.5 8 15c3-1.5 6-4 6-7.5v-4L8 1z"/><path d="M5.5 7l2 2L11 5.5"/></svg></span>
        Threat intel
      </button>
    </div>"""

# Guard: jangan double-patch
if "showPanel('correlation'" in html:
    print("⚠️   SIEM nav đã tồn tại — bỏ qua patch nav")
    p1_done = False
else:
    # Chèn trước </nav> đầu tiên bên trong .sidebar
    # Tìm pattern: kết thúc nav-section Reports (Export/Users button)
    patterns = [
        # Sau nav-section Reports
        r'(showPanel\(\'export\',this\)[^<]*</button>\s*</div>\s*</nav>)',
        r'(showPanel\(\'users\',this\)[^<]*</button>\s*</div>\s*</nav>)',
        # Fallback: trước </nav> đầu tiên trong sidebar
        r'(</div>\s*</nav>)',
    ]
    inserted = False
    for pat in patterns:
        m = re.search(pat, html, re.DOTALL)
        if m:
            old = m.group(0)
            # Chèn nav section trước </nav>
            new = old.replace("</div>\n</nav>", f"</div>{SIEM_NAV}\n    </div>\n</nav>")
            if new == old:
                # Thử pattern đơn giản hơn
                new = re.sub(r'(</div>\s*</nav>)', SIEM_NAV + r'\n    </div>\n</nav>', old, count=1)
            if new != old:
                html = html.replace(old, new, 1)
                inserted = True
                break

    if not inserted:
        # Fallback: tìm </nav> trong sidebar và chèn trước
        # Tìm sidebar nav block
        m = re.search(r'(<nav class="nav">.*?)(</nav>)', html, re.DOTALL)
        if m:
            html = html[:m.start(2)] + SIEM_NAV + "\n  " + html[m.start(2):]
            inserted = True

    if inserted:
        print("✓  Patch 1: SIEM nav section thêm vào sidebar")
        p1_done = True
    else:
        print("⚠️   Patch 1: Không tìm thấy điểm chèn nav — thêm thủ công")
        p1_done = False

# ════════════════════════════════════════════════════════════════
# PATCH 2: Panel HTML — thêm 4 panel divs vào #content
# ════════════════════════════════════════════════════════════════
SIEM_PANELS = """
    <!-- ════════════════════════════════════
         SIEM — CORRELATION PANEL
    ════════════════════════════════════ -->
    <div id="panel-correlation" class="panel">
      <iframe src="/panels/correlation.html"
        style="width:100%;height:calc(100vh - 52px);border:none;background:transparent"
        allowtransparency="true">
      </iframe>
    </div>

    <!-- ════════════════════════════════════
         SIEM — SOAR PANEL
    ════════════════════════════════════ -->
    <div id="panel-soar" class="panel">
      <iframe src="/panels/soar.html"
        style="width:100%;height:calc(100vh - 52px);border:none;background:transparent"
        allowtransparency="true">
      </iframe>
    </div>

    <!-- ════════════════════════════════════
         SIEM — LOG INGESTION PANEL
    ════════════════════════════════════ -->
    <div id="panel-logsources" class="panel">
      <iframe src="/panels/log_pipeline.html"
        style="width:100%;height:calc(100vh - 52px);border:none;background:transparent"
        allowtransparency="true">
      </iframe>
    </div>

    <!-- ════════════════════════════════════
         SIEM — THREAT INTEL PANEL
    ════════════════════════════════════ -->
    <div id="panel-threatintel" class="panel">
      <iframe src="/panels/threat_intel.html"
        style="width:100%;height:calc(100vh - 52px);border:none;background:transparent"
        allowtransparency="true">
      </iframe>
    </div>"""

if "panel-correlation" in html:
    print("⚠️   SIEM panels đã tồn tại — bỏ qua patch panels")
    p2_done = False
else:
    # Chèn trước </div><!-- /content --> hoặc trước thẻ đóng content
    patterns2 = [
        r'(</div><!-- /content -->)',
        r'(</div><!-- end content -->)',
        r'(\s*</div><!-- content -->)',
        r'(</div>\s*</div><!-- /main -->)',
    ]
    inserted2 = False
    for pat in patterns2:
        if re.search(pat, html):
            html = re.sub(pat, SIEM_PANELS + r'\n  \1', html, count=1)
            inserted2 = True
            break

    if not inserted2:
        # Tìm panel cuối cùng (panel-export hoặc panel-users) và chèn sau
        last_panel = re.search(
            r'(<div id="panel-(?:export|users)"[^>]*>.*?</div>)\s*\n(\s*</div>)',
            html, re.DOTALL
        )
        if last_panel:
            html = html[:last_panel.end(1)] + "\n" + SIEM_PANELS + "\n" + html[last_panel.end(1):]
            inserted2 = True

    if inserted2:
        print("✓  Patch 2: SIEM panel divs thêm vào #content")
        p2_done = True
    else:
        print("⚠️   Patch 2: Không tìm thấy điểm chèn panels — thêm thủ công")
        p2_done = False

# ════════════════════════════════════════════════════════════════
# PATCH 3: PANEL_META — thêm 4 entry
# ════════════════════════════════════════════════════════════════
META_PATCH = """  // ── SIEM panels (auto-patched) ──
  correlation: { title:'Correlation engine', sub:'VSP / SIEM / Event correlation · incidents' },
  soar:        { title:'SOAR playbooks',     sub:'VSP / SIEM / Orchestration & automation'   },
  logsources:  { title:'Log ingestion',      sub:'VSP / SIEM / Sources · parsers · live stream'},
  threatintel: { title:'Threat intelligence',sub:'VSP / SIEM / IOC · CVE enrichment · MITRE' },"""

if "correlation:" in html and "soar:" in html:
    print("⚠️   PANEL_META patch đã tồn tại — bỏ qua")
    p3_done = False
else:
    # Tìm cuối object PANEL_META
    m = re.search(r'(const\s+PANEL_META\s*=\s*\{[^}]*)(export\s*:)', html, re.DOTALL)
    if m:
        insert_at = m.start(2)
        html = html[:insert_at] + META_PATCH + "\n  " + html[insert_at:]
        print("✓  Patch 3: PANEL_META entries thêm vào")
        p3_done = True
    else:
        # Tìm users: entry (thường là cuối)
        m2 = re.search(r"(users\s*:\s*\{[^}]+\},?\s*\n)", html)
        if m2:
            html = html[:m2.end()] + META_PATCH + "\n" + html[m2.end():]
            print("✓  Patch 3: PANEL_META entries thêm sau 'users'")
            p3_done = True
        else:
            print("⚠️   Patch 3: Không tìm thấy PANEL_META — thêm thủ công")
            p3_done = False

# ════════════════════════════════════════════════════════════════
# PATCH 4: <script src> cho vsp_siem_patch.js trước </body>
# ════════════════════════════════════════════════════════════════
SCRIPT_TAG = '\n<script src="/panels/vsp_siem_patch.js"></script>'

if "vsp_siem_patch.js" in html:
    print("⚠️   Script tag đã tồn tại — bỏ qua")
    p4_done = False
else:
    if "</body>" in html:
        html = html.replace("</body>", SCRIPT_TAG + "\n</body>", 1)
        print("✓  Patch 4: <script src> thêm trước </body>")
        p4_done = True
    else:
        html = html + SCRIPT_TAG
        print("✓  Patch 4: <script src> thêm cuối file")
        p4_done = True

# ════════════════════════════════════════════════════════════════
# PATCH 5: SSE handler — thêm _siemAutoTrigger call
# ════════════════════════════════════════════════════════════════
SSE_TRIGGER = """
        // ── SIEM auto-trigger (auto-patched) ──
        if (typeof window._siemAutoTrigger === 'function') {
          window._siemAutoTrigger(msg);
        }"""

if "_siemAutoTrigger" in html:
    print("⚠️   SSE trigger đã tồn tại — bỏ qua")
    p5_done = False
else:
    # Tìm scan_complete handler
    patterns5 = [
        r"(if\s*\(\s*msg\.type\s*===\s*['\"]scan_complete['\"]\s*\)\s*\{)",
        r"(msg\.type\s*===\s*['\"]scan_complete['\"]\s*&&\s*msg\.gate)",
        r"(showToast\s*\(\s*['\"]Scan[^'\"]*['\"]\s*,)",
    ]
    inserted5 = False
    for pat in patterns5:
        m = re.search(pat, html)
        if m:
            # Chèn trước closing brace của block
            pos = m.end()
            html = html[:pos] + SSE_TRIGGER + html[pos:]
            inserted5 = True
            break

    if inserted5:
        print("✓  Patch 5: SSE auto-trigger thêm vào scan_complete handler")
        p5_done = True
    else:
        print("⚠️   Patch 5: Không tìm thấy SSE scan_complete handler")
        p5_done = False

# ════════════════════════════════════════════════════════════════
# Ghi file
# ════════════════════════════════════════════════════════════════
if html != original:
    with open(INDEX, "w", encoding="utf-8") as f:
        f.write(html)
    size_orig = os.path.getsize(bak)
    size_new  = len(html.encode("utf-8"))
    print(f"\n✓  index.html đã ghi ({size_orig:,} → {size_new:,} bytes, +{size_new-size_orig:,})")
else:
    print("\n⚠️   Không có thay đổi nào được ghi")

# ════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════
done  = sum([p1_done, p2_done, p3_done, p4_done, p5_done])
total = 5
print(f"""
════════════════════════════════════════════════════
  Kết quả: {done}/{total} patches thành công
  Backup:  {bak}
════════════════════════════════════════════════════""")

if done < total:
    print("""
  Các patch chưa tự động được — thêm thủ công:

  [NAV]  Thêm vào sidebar nav (trước </nav>):
         cat ~/Data/GOLANG_VSP/static/panels/vsp_siem_patch.js | grep -A5 "nav-section"

  [PANELS] Thêm vào #content (trước </div><!-- /content -->):
         4 thẻ <div id="panel-*" class="panel"> với iframe

  [META]  Thêm vào PANEL_META object:
         correlation, soar, logsources, threatintel

  [SCRIPT] Thêm trước </body>:
         <script src="/panels/vsp_siem_patch.js"></script>

  [SSE]  Trong SSE onmessage sau scan_complete:
         if (typeof window._siemAutoTrigger === 'function') window._siemAutoTrigger(msg);
""")

print("  Restart VSP để áp dụng:")
print("  cd ~/Data/GOLANG_VSP && go build ./cmd/... && ./start.sh")
print("  hoặc: make run")
