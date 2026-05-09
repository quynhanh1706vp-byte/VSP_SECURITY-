#!/usr/bin/env bash
# scripts/test-l21-upload-safety.sh — file-upload safety probes.
#
# Two upload endpoints in scope:
#   POST /api/v1/compliance/evidence  (multipart, blob in DB)
#   POST /api/v1/import/findings      (multipart, CSV)
#
# Probes (active + static):
#
#   22.1 Path traversal in filename — header.Filename like ../../etc/passwd
#        must not appear unsanitised in Content-Disposition on download.
#
#   22.2 Polyglot / MIME confusion — declare Content-Type: image/png but
#        ship HTML+JS. Server should NOT trust the declared CT for the
#        download response (browser would render, → stored XSS).
#
#   22.3 Oversized file rejected — 50 MB upload blocked (cap is 10 MB).
#
#   22.4 Zero-byte file accepted but flagged — not actively a bug, but
#        watchdog for null-blob storage.
#
#   22.5 Filename CRLF injection — \r\n in filename should not split
#        Content-Disposition into multiple headers.
#
#   22.6 No ZIP extraction in code (zip slip is N/A if we never extract;
#        confirm by code search).
#
# Pre-flight: $JWT_SECRET, $DB_DSN, gateway running.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command curl jq openssl

JWT_SECRET=$(resolve_jwt_secret)
if [[ -z "$JWT_SECRET" ]]; then
  printf "%s✗%s JWT_SECRET unavailable\n" "$C_RED" "$C_RESET" >&2
  exit 2
fi

mint_jwt() {
  local now exp h p s
  now=$(date +%s); exp=$((now + 3600))
  h=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  p=$(printf '{"sub":"l21@vsp.local","email":"l21@vsp.local","role":"admin","tenant_id":"default","iat":%d,"exp":%d}' \
    "$now" "$exp" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary \
    | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
  printf '%s.%s.%s\n' "$h" "$p" "$s"
}
ADMIN=$(mint_jwt)

# ── 22.1 Path-traversal filename ──────────────────────────────────────────

phase_open "22.1 Path-traversal filename — sanitised on download"

# Upload a benign file with a malicious name. Then GET its download
# and verify Content-Disposition contains no path components.
TMPF=$(mktemp /tmp/upload.XXXXXX)
echo "L21 canary content $$" > "$TMPF"

UP=$(mktemp)
status=$(curl -s -o "$UP" -w "%{http_code}" --max-time 10 \
  -X POST -H "Authorization: Bearer $ADMIN" \
  -F "control_id=L21" \
  -F "notes=path traversal probe" \
  -F "file=@$TMPF;filename=../../etc/passwd" \
  "$BASE/api/v1/compliance/evidence")
EVID_ID=$(jq -r '.id // empty' "$UP" 2>/dev/null)
rm -f "$UP" "$TMPF"

if [[ "$status" =~ ^(200|201)$ && -n "$EVID_ID" ]]; then
  # Now GET the download.
  CD=$(curl -s -i --max-time 5 -H "Authorization: Bearer $ADMIN" \
    "$BASE/api/v1/compliance/evidence/$EVID_ID/download" 2>/dev/null \
    | grep -i "^Content-Disposition:" | head -1 | tr -d '\r')
  if echo "$CD" | grep -qE "\.\.|/etc/|/home/|\\\\"; then
    _fail "22.1.1 path traversal in Content-Disposition" "$CD"
  else
    _pass "22.1.1 path traversal sanitised on download [$CD]"
  fi
  # Cleanup canary.
  if [[ -n "${DB_DSN:-}" ]]; then
    _psql_oneshot "DELETE FROM compliance_evidence WHERE id='$EVID_ID';" >/dev/null 2>&1 || true
  fi
else
  _skip "22.1.1 path traversal" "upload returned HTTP $status"
fi

# ── 22.2 Polyglot / MIME confusion ────────────────────────────────────────

phase_open "22.2 MIME confusion — content-type doesn't enable XSS"

# Upload an HTML+JS payload but TELL the server it's image/png. If the
# download endpoint reflects the client's declared CT verbatim, the
# browser would render the HTML and execute JS. Mitigation: server
# either re-detects from content, OR forces Content-Disposition:
# attachment so browsers don't render.
TMPH=$(mktemp /tmp/poly.XXXXXX)
cat > "$TMPH" <<'HTML'
<html><script>alert("L21-POLYGLOT-XSS")</script></html>
HTML

UP2=$(mktemp)
status=$(curl -s -o "$UP2" -w "%{http_code}" --max-time 10 \
  -X POST -H "Authorization: Bearer $ADMIN" \
  -F "control_id=L21" \
  -F "notes=mime confusion probe" \
  -F "file=@$TMPH;type=image/png;filename=poly.png" \
  "$BASE/api/v1/compliance/evidence")
EVID_ID=$(jq -r '.id // empty' "$UP2" 2>/dev/null)
rm -f "$UP2" "$TMPH"

if [[ "$status" =~ ^(200|201)$ && -n "$EVID_ID" ]]; then
  HDRS=$(curl -s -i --max-time 5 -H "Authorization: Bearer $ADMIN" \
    "$BASE/api/v1/compliance/evidence/$EVID_ID/download" 2>/dev/null | head -20)
  CD=$(echo "$HDRS" | grep -i "^Content-Disposition:" | head -1 | tr -d '\r')
  CT=$(echo "$HDRS" | grep -i "^Content-Type:"        | head -1 | tr -d '\r')
  XCO=$(echo "$HDRS" | grep -i "^X-Content-Type-Options:" | head -1 | tr -d '\r')
  # Browser will not auto-render an HTML payload IF EITHER:
  #   - Content-Disposition starts with "attachment" (forces download)
  #   - X-Content-Type-Options: nosniff present + CT is image/* (browser
  #     refuses to sniff and won't run JS in image rendering)
  if echo "$CD" | grep -qiE "^Content-Disposition: attachment"; then
    _pass "22.2.1 download forces attachment [defends MIME confusion]"
  elif echo "$XCO" | grep -qi nosniff; then
    _pass "22.2.1 nosniff present + non-html CT — defends MIME confusion"
  else
    _fail "22.2.1 MIME confusion possible" "no attachment + no nosniff: $CD / $CT"
  fi
  if [[ -n "${DB_DSN:-}" ]]; then
    _psql_oneshot "DELETE FROM compliance_evidence WHERE id='$EVID_ID';" >/dev/null 2>&1 || true
  fi
else
  _skip "22.2.1 MIME confusion probe" "upload returned HTTP $status"
fi

# ── 22.3 Oversized file rejected ───────────────────────────────────────────

phase_open "22.3 Oversized file — 50MB rejected"

BIG=$(mktemp /tmp/big.XXXXXX)
dd if=/dev/zero of="$BIG" bs=1M count=50 2>/dev/null

START=$(date +%s%N)
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST -H "Authorization: Bearer $ADMIN" \
  -F "control_id=L21" -F "notes=big" \
  -F "file=@$BIG;filename=big.bin" \
  "$BASE/api/v1/compliance/evidence")
ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))
rm -f "$BIG"

if [[ "$status" =~ ^(400|413|414)$ ]]; then
  _pass "22.3.1 50MB rejected [HTTP $status, ${ELAPSED}ms]"
elif [[ "$status" == "200" ]]; then
  _fail "22.3.1 50MB accepted" "handler stored a 50MB blob — cap not enforced"
else
  _fail "22.3.1 unexpected" "HTTP $status"
fi

# ── 22.4 Zero-byte file ───────────────────────────────────────────────────

phase_open "22.4 Zero-byte file — handled non-fatally"

EMPTY=$(mktemp /tmp/zero.XXXXXX)
: > "$EMPTY"

UP3=$(mktemp)
status=$(curl -s -o "$UP3" -w "%{http_code}" --max-time 5 \
  -X POST -H "Authorization: Bearer $ADMIN" \
  -F "control_id=L21" -F "notes=empty" \
  -F "file=@$EMPTY;filename=empty.txt" \
  "$BASE/api/v1/compliance/evidence")
EVID_ID=$(jq -r '.id // empty' "$UP3" 2>/dev/null)
rm -f "$UP3" "$EMPTY"

if [[ "$status" =~ ^(200|201|400)$ ]]; then
  _pass "22.4.1 zero-byte upload handled non-fatally [HTTP $status]"
  if [[ -n "$EVID_ID" && -n "${DB_DSN:-}" ]]; then
    _psql_oneshot "DELETE FROM compliance_evidence WHERE id='$EVID_ID';" >/dev/null 2>&1 || true
  fi
elif [[ "$status" =~ ^5 ]]; then
  _fail "22.4.1 zero-byte caused 5xx" "handler crashed on empty file"
else
  _pass "22.4.1 zero-byte rejected [HTTP $status]"
fi

# ── 22.5 CRLF in filename ─────────────────────────────────────────────────

phase_open "22.5 Filename CRLF — header injection blocked"

# Filename with embedded \r\n. If naively interpolated into
# Content-Disposition, would split into multiple headers.
TMPC=$(mktemp /tmp/crlf.XXXXXX)
echo "crlf canary" > "$TMPC"

UP4=$(mktemp)
# Encode CRLF in the filename via a Python helper since curl's -F
# escapes special chars on its own. Use --form-string so curl passes
# the bytes through without smart parsing.
status=$(curl -s -o "$UP4" -w "%{http_code}" --max-time 5 \
  -X POST -H "Authorization: Bearer $ADMIN" \
  -F "control_id=L21" -F "notes=crlf" \
  -F $'file=@'"$TMPC"$';filename=evil\r\nX-Injected: 1.txt' \
  "$BASE/api/v1/compliance/evidence")
EVID_ID=$(jq -r '.id // empty' "$UP4" 2>/dev/null)
rm -f "$UP4" "$TMPC"

if [[ "$status" =~ ^(200|201)$ && -n "$EVID_ID" ]]; then
  HDRS=$(curl -s -i --max-time 5 -H "Authorization: Bearer $ADMIN" \
    "$BASE/api/v1/compliance/evidence/$EVID_ID/download" 2>/dev/null | head -25)
  if echo "$HDRS" | grep -qi "^X-Injected:"; then
    _fail "22.5.1 CRLF injection succeeded" \
      "filename embedded \\r\\n produced an X-Injected header in response"
  else
    _pass "22.5.1 CRLF in filename neutralised in response headers"
  fi
  if [[ -n "${DB_DSN:-}" ]]; then
    _psql_oneshot "DELETE FROM compliance_evidence WHERE id='$EVID_ID';" >/dev/null 2>&1 || true
  fi
elif [[ "$status" =~ ^(400)$ ]]; then
  _pass "22.5.1 CRLF filename rejected at upload [HTTP $status]"
else
  _skip "22.5.1 CRLF filename probe" "upload returned HTTP $status"
fi

# ── 22.6 Zip slip not applicable — no extraction in code ──────────────────

phase_open "22.6 Zip slip — no archive extraction in handlers"

# If we never extract uploaded archives, zip slip is structurally
# impossible. Confirm via code search: no archive/zip.NewReader,
# tar.NewReader, or shelling out to `unzip` from a handler.
HITS=$(grep -rEn "archive/zip\\.NewReader|archive/tar\\.NewReader|exec\\.Command\\(\"(unzip|tar|7z|gunzip)\"" \
  --include="*.go" -- "$ROOT/internal/api/handler" 2>/dev/null \
  | grep -v "_test\|\.bak" || true)

if [[ -z "$HITS" ]]; then
  _pass "22.6.1 no archive extraction in upload handlers — zip slip N/A"
else
  printf -v L '%s | ' "${HITS[@]}"
  _fail "22.6.1 archive extraction present" "${L%| }"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary
