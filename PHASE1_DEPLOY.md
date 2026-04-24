# VSP 19-Tools Phase 1 — Deployment Guide

## 🎯 Mục tiêu
Wire 4 tool BE đã có (`gosec`, `nikto`, `nmap`, `sslscan`) vào FE
→ Dashboard hiển thị **14 tool thật sự**, không còn gap giữa BE và UI.

## 📦 Files

- `vsp_19tools_phase1.js` — runtime patch (đặt vào `static/` cùng `vsp_features_patch.js`)

## 🚀 Deploy steps

### 1. Copy file vào repo
```bash
cd ~/Data/GOLANG_VSP
cp /path/to/vsp_19tools_phase1.js static/
```

### 2. Inject vào index.html
Mở `static/index.html`, tìm dòng cuối trước `</body>`:
```html
<script src="/static/vsp_features_patch.js"></script>
<script src="/static/vsp_siem_patch.js"></script>
<!-- ADD THIS LINE ↓ -->
<script src="/static/vsp_19tools_phase1.js"></script>
</body>
```

### 3. Verify BE scanner đã register tools
```bash
cd ~/Data/GOLANG_VSP
grep -rE 'case "(gosec|nikto|nmap|sslscan)"' internal/scanner/
# Expect: 4 matches minimum (one per tool in registry switch)

# Check tool binary available
which gosec nikto nmap sslscan
# If missing: apt install nmap sslscan nikto && go install github.com/securego/gosec/v2/cmd/gosec@latest
```

### 4. Restart backend
```bash
# Dev mode
go run cmd/server/main.go

# Or rebuild
go build -o bin/vsp cmd/server/main.go && ./bin/vsp
```

### 5. Smoke test
- Open http://localhost:8080/
- Navigate to **Scan log** panel → expect 12 tool cells (was 8)
- Check browser console → look for:
  ```
  [VSP-19T] Registry extended: {...}
  [VSP-19T] log-tool-cells injected
  [VSP-19T] dropdowns extended
  [VSP 19-Tools Phase 1] ✓ 4 tools wired: gosec, nikto, nmap, sslscan
  ```

### 6. Trigger FULL scan → verify findings
```bash
curl -X POST http://localhost:8080/api/v1/scan/all-modes \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"repo_path":"/path/to/target"}'

# Query findings by tool
for t in gosec nikto nmap sslscan; do
  curl -s "http://localhost:8080/api/v1/vsp/findings?tool=$t" \
    -H "Authorization: Bearer $TOKEN" | jq '.total'
done
```

## ✅ Success criteria

- [ ] `TOOLS_BY_MODE_V2.SAST` includes `gosec`
- [ ] `TOOLS_BY_MODE_V2.DAST` includes `nikto`
- [ ] `TOOLS_BY_MODE_V2.NETWORK` = `['nmap','sslscan','nikto']`
- [ ] `TOOLS_BY_MODE_V2.FULL` has 14 tools (was 9)
- [ ] Scan log panel shows 12 tool cells
- [ ] Tool filter dropdowns include 4 new tools
- [ ] BE `/api/v1/scan/all-modes` accepts NETWORK mode
- [ ] Findings API returns results tagged with new tool names

## 🔄 Rollback

Remove one line from `index.html`:
```html
<script src="/static/vsp_19tools_phase1.js"></script>
```

No database migration, no BE changes required — safe rollback.

## 🐛 Known issues & fixes

**Issue 1**: Tool cells don't appear
→ Check browser console for "ltc-kics anchor not found" — upstream patch order wrong. Move `vsp_19tools_phase1.js` to load AFTER `vsp_features_patch.js`.

**Issue 2**: BE returns `unknown tool: nmap`
→ Scanner dispatch missing. Add to `internal/scanner/dispatcher.go`:
```go
case "nmap":
    return runNmap(ctx, target)
case "sslscan":
    return runSSLScan(ctx, target)
```

**Issue 3**: NETWORK mode button doesn't appear
→ UI may not have `.scan-mode-tabs` selector. The button injection is best-effort; core registry works regardless.

## 📊 Next phases

After Phase 1 success:
- **Phase 2**: SBOM family (`syft`, `cyclonedx`, `govulncheck`) — requires BE work
- **Phase 3**: Supply chain (`cosign`, `tfsec`) — requires BE work
- **Phase 4**: Marketing stack (landing polish, datasheet, pitch, proposal)
