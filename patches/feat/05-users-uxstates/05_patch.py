#!/usr/bin/env python3
"""
FEAT-05: Apply VSPUXState to Users panel.
- Strip hardcoded USERS + ROLES arrays (have backend endpoints)
- Keep AUDIT + API_KEYS arrays (no backend yet, leave for future sprint)
- Wire loadUsers() with VSPUXState skeleton/empty/error states
- Add loadRoles() (currently no real fetch, was rendering hardcoded ROLES)
- Remove initial mock render at line 425
"""
import re, sys, shutil, pathlib

TARGET = pathlib.Path("static/panels/users.html")
BACKUP = pathlib.Path("static/panels/users.html.bak.feat05")
MARKER = "/* FEAT-05 PATCH APPLIED */"

src = TARGET.read_text(encoding="utf-8")

if MARKER in src:
    print("skip: FEAT-05 already applied"); sys.exit(0)

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"Backup: {BACKUP}")

# ─── 1. USERS literal → empty ────────────────────────────────────
m = re.search(r"^var USERS=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: USERS literal not found"); sys.exit(1)
src = src[:m.start()] + "var USERS=[];" + src[m.end():]
print("Stripped USERS literal")

# ─── 2. ROLES literal → empty ────────────────────────────────────
m = re.search(r"^var ROLES=\[\s*\n(?:.*\n)*?\];", src, flags=re.MULTILINE)
if not m:
    print("FAIL: ROLES literal not found"); sys.exit(1)
src = src[:m.start()] + "var ROLES=[];" + src[m.end():]
print("Stripped ROLES literal")

# ─── 3. Rewrite loadUsers() — entire async function with proper states ────
# Match from `async function loadUsers(){` to closing `}` (greedy multi-line)
# Use sentinel pattern: catch existing logic to inner-most try/catch
old_load_re = re.compile(
    r"async function loadUsers\(\)\s*\{[\s\S]*?\n\}\s*\n",
    re.MULTILINE
)
m = old_load_re.search(src)
if not m:
    print("FAIL: loadUsers() not found"); sys.exit(1)

new_load = '''async function loadUsers(){
  var hasUX = typeof VSPUXState !== 'undefined';
  if(hasUX) VSPUXState.skeleton('#users-tbody', {rows: 6});
  if(!TOKEN){
    if(hasUX) VSPUXState.empty('#users-tbody', 'Authentication required', loadUsers);
    return;
  }
  var h={Authorization:'Bearer '+TOKEN};
  try{
    var r=await fetch(API+'/api/v1/admin/users',{headers:h});
    if(!r.ok){
      if(hasUX) VSPUXState.error('#users-tbody', 'HTTP '+r.status, loadUsers);
      return;
    }
    var d=await r.json();
    if(!d.users||!d.users.length){
      USERS=[];
      if(hasUX) VSPUXState.empty('#users-tbody', 'No users found', loadUsers);
      else { updateKPIs(); renderUsers(); }
      return;
    }
    // Map API users to UI shape; derive name from email local-part if missing
    USERS=d.users.map(function(u){
      var fallbackName=(u.email||'unknown@unknown').split('@')[0]
        .replace(/[._-]+/g,' ')
        .replace(/\\b\\w/g, function(c){return c.toUpperCase();});
      return Object.assign({
        name:fallbackName, last_login:'—', status:'active', mfa:false, clearance:'UNCLASS'
      }, u, {
        name:(u.name && u.name.trim())||fallbackName
      });
    });
    updateKPIs(); renderUsers();
  }catch(e){
    if(hasUX) VSPUXState.error('#users-tbody', 'Network error', loadUsers);
  }
}
'''
src = src[:m.start()] + new_load + src[m.end():]
print("Rewrote loadUsers()")

# ─── 4. Add loadRoles() — fetch from backend (or fallback to default 4) ────
# Insert immediately after loadUsers
LOAD_ROLES = '''
async function loadRoles(){
  // FEAT-05: Roles are typically static config. Try API first, fall back to defaults.
  var DEFAULT_ROLES=[
    {id:'admin',name:'Administrator',color:'var(--red)',desc:'Full access to all features, user management, system config',perms:['scans.*','findings.*','users.*','admin.*','reports.*','policy.*']},
    {id:'analyst',name:'SOC Analyst',color:'var(--amber)',desc:'Create scans, manage findings, view all data, no user admin',perms:['scans.*','findings.*','reports.read','policy.read']},
    {id:'viewer',name:'Read-only Viewer',color:'var(--blue)',desc:'View findings and reports, no modifications',perms:['scans.read','findings.read','reports.read']},
    {id:'api',name:'API Service Account',color:'var(--purple)',desc:'Programmatic access for CI/CD and integrations',perms:['scans.create','findings.read','reports.read']},
  ];
  if(!TOKEN){ ROLES=DEFAULT_ROLES; if(typeof renderRoles==='function')renderRoles(); return; }
  try{
    var r=await fetch(API+'/api/v1/admin/roles',{headers:{Authorization:'Bearer '+TOKEN}});
    if(r.ok){
      var d=await r.json();
      if(d.roles && d.roles.length){ ROLES=d.roles; }
      else { ROLES=DEFAULT_ROLES; }
    } else { ROLES=DEFAULT_ROLES; }
  }catch(e){ ROLES=DEFAULT_ROLES; }
  if(typeof renderRoles==='function')renderRoles();
}
'''
# Insert after the new loadUsers (find marker we just added)
anchor = '''  }catch(e){
    if(hasUX) VSPUXState.error('#users-tbody', 'Network error', loadUsers);
  }
}
'''
if anchor not in src:
    print("FAIL: loadUsers anchor not found for loadRoles insertion"); sys.exit(1)
src = src.replace(anchor, anchor + LOAD_ROLES, 1)
print("Added loadRoles()")

# ─── 5. Remove initial mock render at end of script ────────────────
# Pattern: line 425 "updateKPIs();renderUsers();" — appears multiple times, target the LAST one
# Strategy: find the standalone occurrence (not inside a function body)
# In context: this is at top-level near </script> — single line pattern
old_init = "updateKPIs();renderUsers();\n</script>"
new_init = "/* FEAT-05: no mock initial render — loadUsers() will populate */\nif(typeof VSPUXState!=='undefined'){VSPUXState.skeleton('#users-tbody',{rows:6});}\n</script>"
if old_init not in src:
    # try alternate (with extra whitespace before </script>)
    old_init2 = "updateKPIs();renderUsers();\n\n</script>"
    if old_init2 in src:
        src = src.replace(old_init2, new_init.replace("</script>", "\n</script>"), 1)
        print("Removed initial mock render (alt match)")
    else:
        print("FAIL: initial mock render not found at end of script")
        sys.exit(1)
else:
    src = src.replace(old_init, new_init, 1)
    print("Removed initial mock render")

# ─── 6. Hook loadRoles into tab switch (line 286: if(idx===1)renderRoles()) ──
old_tab = "if(idx===1)renderRoles();"
new_tab = "if(idx===1){if(!ROLES.length)loadRoles();else renderRoles();}"
if old_tab in src:
    src = src.replace(old_tab, new_tab, 1)
    print("Hooked loadRoles() into tab switch")
else:
    print("WARN: tab switch hook not found (skipping, non-critical)")

# ─── 7. Marker ───────────────────────────────────────────────────
src = MARKER + "\n" + src
TARGET.write_text(src, encoding="utf-8")
print(f"Wrote {TARGET}")
print("Done.")
