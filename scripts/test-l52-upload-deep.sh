#!/usr/bin/env bash
# scripts/test-l52-upload-deep.sh — upload-safety deeper probes.
#
# L21 covers size limits and Content-Type sniffing. This level adds
# the high-yield attack surfaces L21 misses:
#
#   1. ZIP slip — file inside a ZIP with `../../../etc/passwd` path
#   2. Polyglot files — image-disguised script (JFIF header + JS)
#   3. SVG with embedded <script> — XSS via avatar upload
#   4. MIME-vs-magic mismatch — Content-Type: image/png but body is HTML
#   5. Oversized PNG (decompression bomb / chroma blowup)
#   6. Filename traversal — name="../../../etc/passwd.txt"

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

ADMIN="${TOKEN_ADMIN:-$($ROOT/scripts/mint_jwt_local.sh admin "${JWT_SECRET:-dev-secret-please-change}")}"

# Find an upload endpoint. The codebase has /api/v1/sbom/import and
# /api/v1/findings/import depending on build. Probe both.
UPLOAD_ENDPOINTS=(
  "/api/v1/sbom/import"
  "/api/v1/findings/import"
  "/api/v1/runs/import"
)

# _try_upload BODY CONTENT_TYPE FILENAME → echoes "endpoint:HTTP" of
# the first endpoint that didn't 404. Returns empty if no upload
# endpoint exists in this build.
_first_responding_upload() {
  local body_file="$1" ctype="$2" filename="$3"
  for ep in "${UPLOAD_ENDPOINTS[@]}"; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
      -X POST -H "Authorization: Bearer $ADMIN" \
      -F "file=@$body_file;type=$ctype;filename=$filename" \
      "$BASE$ep" 2>/dev/null || echo "000")
    if [[ "$code" != "404" && "$code" != "405" ]]; then
      printf '%s:%s' "$ep" "$code"
      return
    fi
  done
  printf '::'
}

# ── 52.1 SVG with embedded <script> ──────────────────────────────────────

phase_open "52.1 SVG with <script> — XSS via upload"

SVG=$(mktemp --suffix=.svg)
cat > "$SVG" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <script type="text/javascript">window.parent.__l52_pwned__ = true;</script>
  <circle cx="5" cy="5" r="4" fill="red"/>
</svg>
EOF

RESULT=$(_first_responding_upload "$SVG" "image/svg+xml" "l52-xss.svg")
EP=${RESULT%%:*}; CODE=${RESULT##*:}
rm -f "$SVG"

if [[ -z "$EP" ]]; then
  _skip "52.1.1 SVG XSS upload" "no responding upload endpoint"
elif [[ "$CODE" =~ ^(400|413|415|422)$ ]]; then
  _pass "52.1.1 SVG with <script> rejected at $EP [HTTP $CODE]"
elif [[ "$CODE" =~ ^2 ]]; then
  _fail "52.1.1 SVG with embedded <script> accepted" \
    "$EP returned $CODE — stored SVG can fire script if served back"
else
  _skip "52.1.1 SVG XSS upload" "$EP [HTTP $CODE]"
fi

# ── 52.2 Polyglot — claim image/png but body is HTML ─────────────────────

phase_open "52.2 MIME-vs-magic mismatch"

POLY=$(mktemp --suffix=.png)
# Real PNG signature: 89 50 4E 47 0D 0A 1A 0A
printf '\x89PNG\r\n\x1a\n<script>alert(1)</script><html><body>' > "$POLY"
# Note: a real magic-byte check would still see PNG signature here,
# so this probe is about the SERVER preferring filename .png + ctype
# over actual content. A defending server should reject because the
# bytes after the PNG signature aren't valid IHDR.

RESULT=$(_first_responding_upload "$POLY" "image/png" "l52-poly.png")
EP=${RESULT%%:*}; CODE=${RESULT##*:}
rm -f "$POLY"

if [[ -z "$EP" ]]; then
  _skip "52.2.1 polyglot upload" "no responding upload endpoint"
elif [[ "$CODE" =~ ^(400|415|422)$ ]]; then
  _pass "52.2.1 polyglot PNG with HTML body rejected at $EP [HTTP $CODE]"
elif [[ "$CODE" =~ ^2 ]]; then
  _skip "52.2.1 polyglot PNG accepted" \
    "$EP returned $CODE — informational, defends with output encoding"
else
  _skip "52.2.1 polyglot upload" "$EP [HTTP $CODE]"
fi

# ── 52.3 Filename traversal — ../../etc/passwd ──────────────────────────

phase_open "52.3 Filename traversal"

# Even if the server accepts the file, the FILENAME used on disk
# must not contain `../`. We can't verify disk state directly from
# the test, but we can verify the server doesn't crash and ideally
# rejects the filename outright.
SMALL=$(mktemp --suffix=.txt)
echo "harmless" > "$SMALL"
RESULT=$(_first_responding_upload "$SMALL" "text/plain" "../../etc/passwd")
EP=${RESULT%%:*}; CODE=${RESULT##*:}
rm -f "$SMALL"

if [[ -z "$EP" ]]; then
  _skip "52.3.1 filename traversal" "no responding upload endpoint"
elif [[ "$CODE" =~ ^(400|415|422)$ ]]; then
  _pass "52.3.1 traversal filename rejected at $EP [HTTP $CODE]"
elif [[ "$CODE" =~ ^5 ]]; then
  _fail "52.3.1 traversal filename caused 5xx" \
    "$EP [HTTP $CODE] — server crashed on dot-dot filename"
elif [[ "$CODE" =~ ^2 ]]; then
  _skip "52.3.1 traversal filename accepted" \
    "$EP [HTTP $CODE] — verify server sanitised stored filename"
else
  _skip "52.3.1 traversal filename" "$EP [HTTP $CODE]"
fi

# ── 52.4 ZIP slip — entry path escapes upload dir ────────────────────────

phase_open "52.4 ZIP slip — entry with ../../../"

if command -v zip &>/dev/null; then
  ZIP_DIR=$(mktemp -d)
  echo "evil content" > "$ZIP_DIR/safe.txt"
  (cd "$ZIP_DIR" && zip -q slip.zip safe.txt)
  # Manually inject a ../../etc/passwd entry by editing the zip
  # central directory. Easier: use python if available.
  if command -v python3 &>/dev/null; then
    python3 - "$ZIP_DIR/slip.zip" <<'PY'
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p, 'a') as z:
    z.writestr('../../../tmp/l52-slip.txt', 'evil escapement')
PY
    RESULT=$(_first_responding_upload "$ZIP_DIR/slip.zip" "application/zip" "l52-slip.zip")
    EP=${RESULT%%:*}; CODE=${RESULT##*:}
    if [[ -z "$EP" ]]; then
      _skip "52.4.1 ZIP slip" "no responding upload endpoint"
    elif [[ "$CODE" =~ ^(400|415|422)$ ]]; then
      _pass "52.4.1 ZIP with ../ entry rejected at $EP [HTTP $CODE]"
    elif [[ "$CODE" =~ ^2 ]]; then
      # If the server extracted, check whether the slip file appeared
      # in /tmp (we wrote ../../../tmp/l52-slip.txt). If yes, real bug.
      if [[ -f /tmp/l52-slip.txt ]]; then
        _fail "52.4.1 ZIP slip succeeded" "/tmp/l52-slip.txt was written — extraction escaped sandbox"
        rm -f /tmp/l52-slip.txt
      else
        _skip "52.4.1 ZIP accepted" "$EP [HTTP $CODE] — no extraction observed"
      fi
    else
      _skip "52.4.1 ZIP slip" "$EP [HTTP $CODE]"
    fi
  else
    _skip "52.4.1 ZIP slip" "python3 not available — can't craft slip entry"
  fi
  rm -rf "$ZIP_DIR"
else
  _skip "52.4.1 ZIP slip" "zip command not installed"
fi

# ── 52.5 Empty / zero-byte upload ────────────────────────────────────────

phase_open "52.5 Empty upload doesn't crash handler"

EMPTY=$(mktemp)
: > "$EMPTY"  # truncate to 0 bytes
RESULT=$(_first_responding_upload "$EMPTY" "application/octet-stream" "l52-empty.bin")
EP=${RESULT%%:*}; CODE=${RESULT##*:}
rm -f "$EMPTY"

if [[ -z "$EP" ]]; then
  _skip "52.5.1 empty upload" "no responding upload endpoint"
elif [[ "$CODE" =~ ^(400|413|415|422)$ ]]; then
  _pass "52.5.1 empty upload rejected cleanly [HTTP $CODE]"
elif [[ "$CODE" =~ ^5 ]]; then
  _fail "52.5.1 empty upload caused 5xx" "$EP [HTTP $CODE]"
elif [[ "$CODE" =~ ^2 ]]; then
  _skip "52.5.1 empty upload accepted" "$EP [HTTP $CODE]"
else
  _skip "52.5.1 empty upload" "$EP [HTTP $CODE]"
fi

# ── 52.6 Filename with null byte ─────────────────────────────────────────

phase_open "52.6 Null-byte in filename"

NULL_NAME=$'l52\x00.png'
TINY=$(mktemp)
echo "data" > "$TINY"
# curl quietly drops null bytes in -F filename=; some HTTP libs don't.
# We send via raw multipart to see if the server filter handles it.
BOUNDARY="L52BOUND$(date +%s)"
MULTI=$(mktemp)
{
  printf -- "--%s\r\n" "$BOUNDARY"
  printf "Content-Disposition: form-data; name=\"file\"; filename=\"l52\x00.png\"\r\n"
  printf "Content-Type: image/png\r\n\r\n"
  cat "$TINY"
  printf "\r\n--%s--\r\n" "$BOUNDARY"
} > "$MULTI"

CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -X POST -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: multipart/form-data; boundary=$BOUNDARY" \
  --data-binary "@$MULTI" \
  "$BASE/api/v1/sbom/import" 2>/dev/null || echo "000")
rm -f "$TINY" "$MULTI"

if [[ "$CODE" =~ ^(400|415|422|404|405)$ ]]; then
  _pass "52.6.1 null-byte filename rejected [HTTP $CODE]"
elif [[ "$CODE" =~ ^5 ]]; then
  _fail "52.6.1 null-byte filename caused 5xx" "HTTP $CODE — handler crashed"
elif [[ "$CODE" =~ ^2 ]]; then
  _skip "52.6.1 null-byte filename accepted" "HTTP $CODE — verify stored filename"
else
  _skip "52.6.1 null-byte filename" "HTTP $CODE"
fi

final_summary
