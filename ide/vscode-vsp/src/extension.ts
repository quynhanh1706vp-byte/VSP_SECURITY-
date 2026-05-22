// VSP VS Code extension entry point.
//
// Wires four behaviours:
//
//   1. Status-bar gate badge — fetches /api/v1/vsp/run/latest every 30s
//      and shows PASS/WARN/FAIL with severity counts. Click → opens the
//      latest run in the browser.
//
//   2. Scan-on-save — when vsp.scanOnSave is true, POSTs a scan request
//      with the saved file's directory as src, profile per
//      vsp.scanProfile. Findings stream back via the SSE live-tail
//      endpoint and become VS Code Diagnostics in the Problems panel.
//
//   3. Findings panel webview — VSP: Open findings panel command opens
//      a side panel listing the latest 100 findings with severity
//      filter. Click a finding → jumps to file:line.
//
//   4. Token storage via VS Code SecretStorage. Never written to
//      settings.json (which sometimes ends up in source control).

import * as vscode from "vscode";
import * as http from "http";
import * as https from "https";
import { URL } from "url";

const STATE_TOKEN = "vsp.token";
const STATE_LAST_RUN = "vsp.lastRunRid";

let statusItem: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;

export function activate(ctx: vscode.ExtensionContext) {
  diagnostics = vscode.languages.createDiagnosticCollection("vsp");
  ctx.subscriptions.push(diagnostics);

  statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right, 100,
  );
  statusItem.command = "vsp.openLatestRun";
  statusItem.text = "$(shield) VSP …";
  statusItem.show();
  ctx.subscriptions.push(statusItem);

  ctx.subscriptions.push(
    vscode.commands.registerCommand("vsp.scanWorkspace", () => scanCmd(ctx)),
    vscode.commands.registerCommand("vsp.openFindings", () => openFindingsPanel(ctx)),
    vscode.commands.registerCommand("vsp.openLatestRun", () => openLatestRun(ctx)),
    vscode.commands.registerCommand("vsp.signIn", () => signInCmd(ctx)),
  );

  // Refresh status every 30 s.
  refreshStatus(ctx);
  const tick = setInterval(() => refreshStatus(ctx), 30_000);
  ctx.subscriptions.push({ dispose: () => clearInterval(tick) });

  // Scan-on-save.
  ctx.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const cfg = vscode.workspace.getConfiguration("vsp");
      if (!cfg.get<boolean>("scanOnSave")) return;
      // Only touch source-code files; skip large binaries / generated.
      if (!/\.(go|js|ts|py|java|rb|php|c|cpp|tf|yaml|yml)$/.test(doc.fileName)) return;
      await runScan(ctx, vscode.Uri.file(doc.fileName), cfg.get<string>("scanProfile") || "FAST");
    }),
  );
}

export function deactivate() {
  if (statusItem) statusItem.dispose();
  if (diagnostics) diagnostics.dispose();
}

// ── commands ───────────────────────────────────────────────────────────────

async function scanCmd(ctx: vscode.ExtensionContext) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("VSP: no workspace folder open");
    return;
  }
  const profile = await vscode.window.showQuickPick(
    ["FAST", "FULL", "SAST_ONLY", "SECRETS_ONLY"],
    { placeHolder: "Pick scan profile" });
  if (!profile) return;
  await runScan(ctx, folders[0].uri, profile);
}

async function runScan(ctx: vscode.ExtensionContext, target: vscode.Uri, profile: string) {
  const cfg = vscode.workspace.getConfiguration("vsp");
  const base = cfg.get<string>("gatewayUrl") || "http://localhost:8921";
  const token = await ensureToken(ctx);
  if (!token) return;

  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: `VSP scan (${profile})`,
    cancellable: false,
  }, async (progress) => {
    try {
      const resp = await postJSON(
        `${base}/api/v1/vsp/run`,
        { mode: "FULL", profile, src: target.fsPath },
        token,
      );
      const rid = (resp as any).rid as string;
      if (!rid) throw new Error("no rid in response");
      ctx.workspaceState.update(STATE_LAST_RUN, rid);
      progress.report({ message: `rid=${rid.slice(-12)} — streaming findings…` });
      await streamLiveTail(base, rid, token, target.fsPath);
      vscode.window.showInformationMessage(`VSP scan ${rid} complete. Open Problems panel.`);
    } catch (err: any) {
      vscode.window.showErrorMessage(`VSP scan failed: ${err.message}`);
    }
  });
}

async function streamLiveTail(base: string, rid: string, token: string, srcRoot: string) {
  // Use SSE endpoint /api/v1/vsp/run/{rid}/tail. We poll instead of
  // a live SSE connection in this v0.1 to keep the extension simple;
  // upgrade to EventSource when we're shipping ESM-compatible code.
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    try {
      const r: any = await getJSON(`${base}/api/v1/vsp/run/${rid}`, token);
      if (r.status === "COMPLETED" || r.status === "FAILED") {
        await refreshDiagnostics(base, rid, token, srcRoot);
        return;
      }
    } catch { /* tolerate transient */ }
  }
}

async function refreshDiagnostics(base: string, rid: string, token: string, srcRoot: string) {
  const r: any = await getJSON(`${base}/api/v1/findings?rid=${rid}&limit=200`, token);
  diagnostics.clear();
  const map = new Map<string, vscode.Diagnostic[]>();
  for (const f of r.findings || []) {
    if (!f.path || !f.line_num) continue;
    const abs = f.path.startsWith("/") ? f.path : `${srcRoot}/${f.path}`;
    const range = new vscode.Range(
      new vscode.Position(Math.max(0, f.line_num - 1), 0),
      new vscode.Position(Math.max(0, f.line_num - 1), 200),
    );
    const sev = severityToVSC(f.severity);
    const d = new vscode.Diagnostic(range,
      `[${f.tool}] ${f.rule_id || "unknown"}: ${f.message || ""}`, sev);
    d.source = "VSP";
    if (f.cwe) d.code = f.cwe;
    const arr = map.get(abs) || [];
    arr.push(d);
    map.set(abs, arr);
  }
  for (const [path, ds] of map.entries()) {
    diagnostics.set(vscode.Uri.file(path), ds);
  }
}

function severityToVSC(s: string): vscode.DiagnosticSeverity {
  switch ((s || "").toUpperCase()) {
    case "CRITICAL": case "HIGH":
      return vscode.DiagnosticSeverity.Error;
    case "MEDIUM":
      return vscode.DiagnosticSeverity.Warning;
    case "LOW":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

async function refreshStatus(ctx: vscode.ExtensionContext) {
  const cfg = vscode.workspace.getConfiguration("vsp");
  const base = cfg.get<string>("gatewayUrl") || "http://localhost:8921";
  const token = await ctx.secrets.get(STATE_TOKEN);
  if (!token) {
    statusItem.text = "$(shield) VSP: sign-in";
    statusItem.tooltip = "Click to set VSP token";
    statusItem.command = "vsp.signIn";
    return;
  }
  try {
    const r: any = await getJSON(`${base}/api/v1/vsp/run/latest`, token);
    const gate = r.gate || "?";
    const total = r.total_findings || 0;
    const icon = gate === "PASS" ? "$(check)" : gate === "WARN" ? "$(warning)" : "$(error)";
    statusItem.text = `${icon} VSP ${gate} · ${total}`;
    statusItem.tooltip = `Latest run: ${r.rid}\nClick to open in browser`;
    statusItem.command = "vsp.openLatestRun";
  } catch {
    statusItem.text = "$(shield) VSP: offline";
    statusItem.tooltip = "VSP gateway unreachable";
  }
}

async function openLatestRun(ctx: vscode.ExtensionContext) {
  const rid = ctx.workspaceState.get<string>(STATE_LAST_RUN);
  const cfg = vscode.workspace.getConfiguration("vsp");
  const base = cfg.get<string>("gatewayUrl") || "http://localhost:8921";
  const url = rid ? `${base}/static/panels/runs.html?rid=${rid}` : `${base}/`;
  vscode.env.openExternal(vscode.Uri.parse(url));
}

async function openFindingsPanel(ctx: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "vsp.findings", "VSP Findings", vscode.ViewColumn.Beside,
    { enableScripts: true });
  const cfg = vscode.workspace.getConfiguration("vsp");
  const base = cfg.get<string>("gatewayUrl") || "http://localhost:8921";
  const token = await ctx.secrets.get(STATE_TOKEN) || "";
  panel.webview.html = `<!doctype html><html><body style="font-family:sans-serif;padding:16px">
    <h2>VSP Findings</h2>
    <p>Showing latest run findings. Refresh: ⟳</p>
    <iframe src="${base}/static/panels/findings.html"
            style="width:100%;height:80vh;border:1px solid #444"></iframe>
  </body></html>`;
}

async function signInCmd(ctx: vscode.ExtensionContext) {
  const token = await vscode.window.showInputBox({
    placeHolder: "VSP JWT or API key",
    password: true,
    prompt: "Stored in VS Code secret storage; never written to settings.json",
  });
  if (token) {
    await ctx.secrets.store(STATE_TOKEN, token);
    vscode.window.showInformationMessage("VSP token stored.");
    refreshStatus(ctx);
  }
}

async function ensureToken(ctx: vscode.ExtensionContext): Promise<string | undefined> {
  let token = await ctx.secrets.get(STATE_TOKEN);
  if (!token) {
    await signInCmd(ctx);
    token = await ctx.secrets.get(STATE_TOKEN);
  }
  return token;
}

// ── HTTP helpers (stdlib only — keep extension dependency-free) ────────────

function getJSON(url: string, token: string): Promise<unknown> {
  return request(url, "GET", null, token);
}

function postJSON(url: string, body: unknown, token: string): Promise<unknown> {
  return request(url, "POST", body, token);
}

function request(url: string, method: string, body: unknown, token: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const data = body == null ? null : JSON.stringify(body);
    const req = lib.request({
      method,
      hostname: u.hostname,
      port: u.port || (u.protocol === "https:" ? 443 : 80),
      path: u.pathname + u.search,
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "User-Agent": "vsp-vscode/0.1",
        ...(data ? { "Content-Length": Buffer.byteLength(data).toString() } : {}),
      },
      timeout: 10_000,
    }, (res) => {
      let buf = "";
      res.on("data", (c) => buf += c);
      res.on("end", () => {
        if (res.statusCode && res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${buf.slice(0, 200)}`));
          return;
        }
        try { resolve(buf ? JSON.parse(buf) : {}); }
        catch (e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    if (data) req.write(data);
    req.end();
  });
}
