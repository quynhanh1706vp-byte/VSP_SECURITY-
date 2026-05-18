# VSP Security — VS Code Extension

Live VSP scan integration in your editor:

- Status-bar gate badge (PASS / WARN / FAIL + finding count)
- Scan-on-save → findings flow into Problems panel
- Click finding to jump to file:line
- One-click "Open latest run in browser"
- Token stored in VS Code SecretStorage (never settings.json)

## Build & install (developer)

```bash
cd ide/vscode-vsp
npm install
npm run compile
npm run package           # produces vsp-security-0.1.0.vsix
code --install-extension vsp-security-0.1.0.vsix
```

## Configure

After install, set:

- `vsp.gatewayUrl` (default `http://localhost:8921`)
- Run command **VSP: Sign in** to store your token

## Publish to Marketplace

```bash
npm install -g @vscode/vsce
vsce publish
```

Requires a Personal Access Token from
<https://dev.azure.com/vsp-platform/_usersSettings/tokens> with the
`Marketplace (Publish)` scope.

## What it touches

| API | Direction | Purpose |
|-----|-----------|---------|
| `POST /api/v1/vsp/run` | Out | Trigger scan |
| `GET /api/v1/vsp/run/{rid}` | Out | Poll status |
| `GET /api/v1/vsp/run/latest` | Out | Status-bar badge |
| `GET /api/v1/findings?rid=X` | Out | Populate Problems panel |
| `vscode.SecretStorage` | Local | Store JWT |
| `vscode.DiagnosticCollection` | Local | Render findings inline |

## Roadmap

- v0.2: real SSE live-tail (drop polling)
- v0.3: AutoFix one-click action (calls `POST /api/v1/autofix/run`)
- v0.4: PRO-tier features behind setting (DORA badge, cATO posture)

## License

Apache 2.0 — same as the rest of VSP.
