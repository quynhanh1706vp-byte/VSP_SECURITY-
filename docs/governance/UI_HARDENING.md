# VSP UI Security Hardening

**Targets** (Sprint 4 SEC-005, SEC-006):
- SEC-005: Migrate JWT storage from `localStorage` → HttpOnly cookie
- SEC-006: Eliminate XSS via `innerHTML`

## Budget schedule

Giảm dần qua 5 sprint:

| Sprint | localStorage | innerHTML | Gate |
|---|---|---|---|
| 5 (hiện tại) | ≤ 130 | ≤ 470 | FAIL if exceeded |
| 6 | ≤ 80 | ≤ 300 | FAIL if exceeded |
| 7 | ≤ 30 | ≤ 150 | FAIL if exceeded |
| 8 | ≤ 10 | ≤ 50 | FAIL if exceeded |
| 9 (target) | 0 | 0 (DOMPurify only) | FAIL if > 0 |

Set via env trong `.github/workflows/ui-security-gate.yml` hoặc call:
```bash
MAX_LOCAL_STORAGE=80 MAX_INNER_HTML=300 bash scripts/ui-hygiene-budget.sh
```

## SEC-005: JWT migration

### Backend (Go)

```go
// internal/auth/handler.go

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
    // ... validate credentials, generate JWT ...

    http.SetCookie(w, &http.Cookie{
        Name:     "vsp_token",
        Value:    signedJWT,
        HttpOnly: true,                       // JS cannot read
        Secure:   true,                       // HTTPS only
        SameSite: http.SameSiteStrictMode,    // CSRF mitigation
        Path:     "/",
        MaxAge:   3600,
    })

    // CSRF double-submit token (readable by JS, sent as header)
    http.SetCookie(w, &http.Cookie{
        Name:     "vsp_csrf",
        Value:    generateCSRFToken(userID),
        HttpOnly: false,                      // JS reads this
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
        Path:     "/",
        MaxAge:   3600,
    })

    json.NewEncoder(w).Encode(map[string]any{
        "ok": true, "user_id": userID,
    })
}
```

### Frontend (JS)

```javascript
// Thay cho: localStorage.getItem('vsp_token')
function getCsrfToken() {
  return document.cookie
    .split('; ')
    .find(r => r.startsWith('vsp_csrf='))
    ?.split('=')[1] || '';
}

// Fetch tự động gửi cookie — không cần Authorization header
async function apiCall(path, opts = {}) {
  return fetch(path, {
    credentials: 'same-origin',               // gửi cookie
    headers: {
      'X-CSRF-Token': getCsrfToken(),         // double-submit
      'Content-Type': 'application/json',
      ...opts.headers,
    },
    ...opts,
  });
}
```

## SEC-006: innerHTML elimination

### Option A — codemod tự động

```bash
# Dry run first
node codemod/innerHTML-to-safe.js panels/ --dry-run

# Review diff, then apply
node codemod/innerHTML-to-safe.js panels/ --write
```

### Option B — manual migration

```javascript
// BEFORE (unsafe)
el.innerHTML = user.name + ' says hello';

// AFTER - nếu chỉ text
el.textContent = user.name + ' says hello';

// AFTER - nếu cần HTML (bảng, icon)
el.innerHTML = DOMPurify.sanitize(
  `<span class="name">${user.name}</span>`,
  { ALLOWED_TAGS: ['span', 'b', 'i'], ALLOWED_ATTR: ['class'] }
);

// AFTER - nếu build element tree
el.replaceChildren(
  Object.assign(document.createElement('span'), {
    className: 'name',
    textContent: user.name
  }),
  document.createTextNode(' says hello')
);
```

## CSP header (add to reverse proxy)

```nginx
add_header Content-Security-Policy "
  default-src 'self';
  script-src 'self' https://cdnjs.cloudflare.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self';
  frame-ancestors 'none';
" always;

add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```
