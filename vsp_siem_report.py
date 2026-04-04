#!/usr/bin/env python3
"""
vsp_siem_report.py — Generate SIEM PDF report từ VSP API
Usage: python3 vsp_siem_report.py --token TOKEN [--output report.pdf]
"""
import argparse, json, sys, os
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError

# ReportLab
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.platypus import KeepTogether
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Config ────────────────────────────────────────────────────
API = "http://127.0.0.1:8921"
W, H = A4

# ── Colors ────────────────────────────────────────────────────
C_BG      = colors.HexColor("#0a0c10")
C_SURFACE = colors.HexColor("#1e2128")
C_RED     = colors.HexColor("#ef4444")
C_AMBER   = colors.HexColor("#f59e0b")
C_GREEN   = colors.HexColor("#22c55e")
C_BLUE    = colors.HexColor("#3b82f6")
C_CYAN    = colors.HexColor("#06b6d4")
C_PURPLE  = colors.HexColor("#8b5cf6")
C_GRAY    = colors.HexColor("#5a6278")
C_T1      = colors.HexColor("#e8eaf0")
C_T2      = colors.HexColor("#9aa3b8")
C_DARK    = colors.HexColor("#111318")
WHITE     = colors.white

def fetch(path, token):
    try:
        req = Request(f"{API}{path}", headers={"Authorization": f"Bearer {token}"})
        with urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"⚠ fetch {path}: {e}", file=sys.stderr)
        return {}

def sev_color(sev):
    return {
        "CRITICAL": C_RED, "HIGH": C_AMBER,
        "MEDIUM": C_BLUE,  "LOW":  C_GREEN,
    }.get((sev or "").upper(), C_GRAY)

def gate_color(gate):
    return {"PASS": C_GREEN, "WARN": C_AMBER, "FAIL": C_RED}.get(gate, C_GRAY)

# ── Styles ────────────────────────────────────────────────────
def make_styles():
    styles = getSampleStyleSheet()
    base = dict(fontName="Helvetica", textColor=C_T1)

    return {
        "cover_title": ParagraphStyle("ct", fontSize=32, fontName="Helvetica-Bold",
                        textColor=WHITE, alignment=TA_CENTER, spaceAfter=6),
        "cover_sub":   ParagraphStyle("cs", fontSize=14, fontName="Helvetica",
                        textColor=C_T2, alignment=TA_CENTER, spaceAfter=4),
        "cover_date":  ParagraphStyle("cd", fontSize=11, fontName="Helvetica",
                        textColor=C_GRAY, alignment=TA_CENTER),
        "section":     ParagraphStyle("sec", fontSize=16, fontName="Helvetica-Bold",
                        textColor=WHITE, spaceBefore=16, spaceAfter=8,
                        borderPad=4),
        "subsection":  ParagraphStyle("sub", fontSize=12, fontName="Helvetica-Bold",
                        textColor=C_T1, spaceBefore=10, spaceAfter=4),
        "body":        ParagraphStyle("body", fontSize=9, fontName="Helvetica",
                        textColor=C_T2, spaceAfter=4, leading=14),
        "mono":        ParagraphStyle("mono", fontSize=8, fontName="Courier",
                        textColor=C_CYAN, spaceAfter=2),
        "label":       ParagraphStyle("lbl", fontSize=8, fontName="Helvetica-Bold",
                        textColor=C_GRAY, spaceAfter=2),
        "kpi_val":     ParagraphStyle("kv", fontSize=24, fontName="Helvetica-Bold",
                        textColor=WHITE, alignment=TA_CENTER),
        "kpi_lbl":     ParagraphStyle("kl", fontSize=8, fontName="Helvetica",
                        textColor=C_T2, alignment=TA_CENTER),
        "footer":      ParagraphStyle("ft", fontSize=7, fontName="Helvetica",
                        textColor=C_GRAY, alignment=TA_CENTER),
        "tag":         ParagraphStyle("tag", fontSize=8, fontName="Helvetica-Bold",
                        textColor=WHITE, alignment=TA_CENTER),
    }

def header_footer(canvas, doc):
    canvas.saveState()
    # Header bar
    canvas.setFillColor(C_DARK)
    canvas.rect(0, H - 28*mm, W, 28*mm, fill=1, stroke=0)
    canvas.setFillColor(C_RED)
    canvas.rect(0, H - 30*mm, W, 2*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(WHITE)
    canvas.drawString(15*mm, H - 18*mm, "VSP Security Platform — SIEM Report")
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(C_GRAY)
    canvas.drawRightString(W - 15*mm, H - 18*mm,
        datetime.now().strftime("%Y-%m-%d %H:%M UTC") + f"  ·  Page {doc.page}")
    # Footer
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, W, 12*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_GRAY)
    canvas.drawString(15*mm, 5*mm,
        "UNCLASSIFIED // FOR OFFICIAL USE ONLY · VSP Security Platform v0.10.0 · ITAR/EAR Controlled")
    canvas.setFillColor(C_RED)
    canvas.drawRightString(W - 15*mm, 5*mm, "● GATE FAIL")
    canvas.restoreState()

def kpi_table(data, styles):
    """4-column KPI row."""
    cells = []
    for val, lbl, color in data:
        cells.append([
            Paragraph(str(val), ParagraphStyle("kv", fontSize=22,
                fontName="Helvetica-Bold", textColor=color, alignment=TA_CENTER)),
            Paragraph(lbl, styles["kpi_lbl"]),
        ])
    t = Table([[c[0] for c in cells], [c[1] for c in cells]],
              colWidths=[W/len(data) - 12*mm] * len(data))
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
        ("ROUNDEDCORNERS", [5]),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LINEABOVE", (0,0), (-1,0), 0.5, C_GRAY),
    ]))
    return t

def build_report(token, output):
    S = make_styles()
    story = []

    # ── Fetch data ────────────────────────────────────────────
    print("Fetching data...")
    incidents  = fetch("/api/v1/correlation/incidents?limit=50", token)
    rules      = fetch("/api/v1/correlation/rules", token)
    playbooks  = fetch("/api/v1/soar/playbooks", token)
    runs       = fetch("/api/v1/soar/runs?limit=20", token)
    sources    = fetch("/api/v1/logs/sources", token)
    stats      = fetch("/api/v1/logs/stats", token)
    iocs       = fetch("/api/v1/ti/iocs?limit=20", token)
    feeds      = fetch("/api/v1/ti/feeds", token)
    baseline   = fetch("/api/v1/ueba/baseline", token)
    assets     = fetch("/api/v1/assets", token)
    asset_sum  = fetch("/api/v1/assets/summary", token)

    inc_list  = incidents.get("incidents", [])
    rule_list = rules.get("rules", [])
    pb_list   = playbooks.get("playbooks", [])
    run_list  = runs.get("runs", [])
    src_list  = sources.get("sources", [])
    ioc_list  = iocs.get("iocs", [])
    feed_list = feeds.get("feeds", [])
    asset_list= assets.get("assets", [])

    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    # ── Cover page ────────────────────────────────────────────
    story.append(Spacer(1, 40*mm))
    story.append(Paragraph("VSP SECURITY PLATFORM", S["cover_title"]))
    story.append(Paragraph("SIEM Integration Report", S["cover_sub"]))
    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width="80%", thickness=1, color=C_RED, hAlign="CENTER"))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f"Generated: {now}", S["cover_date"]))
    story.append(Paragraph("UNCLASSIFIED // FOR OFFICIAL USE ONLY", S["cover_date"]))
    story.append(Spacer(1, 20*mm))

    # Cover KPIs
    crit_inc = sum(1 for i in inc_list if (i.get("severity","")).upper()=="CRITICAL")
    story.append(kpi_table([
        (len(inc_list),         "Active Incidents", C_RED),
        (len(rule_list),        "Correlation Rules", C_BLUE),
        (len(pb_list),          "SOAR Playbooks", C_PURPLE),
        (stats.get("online",0), "Log Sources Online", C_GREEN),
    ], S))
    story.append(PageBreak())

    # ── 1. Executive Summary ──────────────────────────────────
    story.append(Paragraph("1. Executive Summary", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 4*mm))

    crit_count = sum(1 for i in inc_list if (i.get("severity","")).upper()=="CRITICAL")
    high_count = sum(1 for i in inc_list if (i.get("severity","")).upper()=="HIGH")
    enabled_rules = sum(1 for r in rule_list if r.get("enabled", False))
    enabled_pbs   = sum(1 for p in pb_list   if p.get("enabled", False))
    success_runs  = sum(1 for r in run_list   if r.get("status")=="success")

    summary_text = f"""
    The VSP SIEM integration is fully operational with <b>{len(rule_list)} correlation rules</b>
    ({enabled_rules} enabled), <b>{len(pb_list)} SOAR playbooks</b> ({enabled_pbs} active),
    and <b>{len(src_list)} log sources</b> ingesting events continuously.
    <br/><br/>
    During the reporting period, the system detected <b>{len(inc_list)} security incidents</b>
    ({crit_count} critical, {high_count} high severity). The SOAR engine executed
    <b>{len(run_list)} playbook runs</b> with a {int(success_runs/max(len(run_list),1)*100)}% success rate.
    <br/><br/>
    The threat intelligence database contains <b>{len(ioc_list)} active IOCs</b> across
    {len(feed_list)} feed sources. UEBA behavioral baseline shows an average security score
    of <b>{round(baseline.get('avg_score',0))}/100</b> with a
    {round(baseline.get('gate_pass_rate',0)*100)}% gate pass rate over 30 days.
    """
    story.append(Paragraph(summary_text, S["body"]))
    story.append(Spacer(1, 6*mm))

    # ── 2. Incidents ──────────────────────────────────────────
    story.append(Paragraph("2. Active Incidents", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 3*mm))

    if inc_list:
        tdata = [["ID", "Title", "Severity", "Status", "Created"]]
        for inc in inc_list[:20]:
            sev = (inc.get("severity") or "—").upper()
            tdata.append([
                Paragraph(str(inc.get("id",""))[:8], S["mono"]),
                Paragraph(str(inc.get("title","—"))[:60], S["body"]),
                Paragraph(sev, ParagraphStyle("sv", fontSize=8, fontName="Helvetica-Bold",
                    textColor=sev_color(sev), alignment=TA_CENTER)),
                Paragraph(str(inc.get("status","open")), S["body"]),
                Paragraph(str(inc.get("created_at",""))[:10], S["mono"]),
            ])
        t = Table(tdata, colWidths=[18*mm, 75*mm, 22*mm, 20*mm, 25*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), C_T2),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.25, C_GRAY),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No active incidents.", S["body"]))
    story.append(Spacer(1, 6*mm))

    # ── 3. Correlation Rules ──────────────────────────────────
    story.append(Paragraph("3. Correlation Rules", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 3*mm))

    if rule_list:
        tdata = [["Rule Name", "Severity", "Window", "Sources", "Enabled", "Hits"]]
        for r in rule_list:
            sev = (r.get("severity") or "—").upper()
            tdata.append([
                Paragraph(str(r.get("name","—"))[:50], S["body"]),
                Paragraph(sev, ParagraphStyle("sv2", fontSize=8, fontName="Helvetica-Bold",
                    textColor=sev_color(sev), alignment=TA_CENTER)),
                Paragraph(f"{r.get('window_min',0)}m", S["mono"]),
                Paragraph(", ".join(r.get("sources",[]))[:30], S["body"]),
                Paragraph("✓" if r.get("enabled") else "✗", ParagraphStyle("en",
                    fontSize=9, textColor=C_GREEN if r.get("enabled") else C_GRAY,
                    alignment=TA_CENTER)),
                Paragraph(str(r.get("hits",0)), S["mono"]),
            ])
        t = Table(tdata, colWidths=[60*mm, 22*mm, 16*mm, 35*mm, 16*mm, 11*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), C_T2),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.25, C_GRAY),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        story.append(t)
    story.append(PageBreak())

    # ── 4. SOAR Playbooks ─────────────────────────────────────
    story.append(Paragraph("4. SOAR Playbooks", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 3*mm))

    if pb_list:
        tdata = [["Playbook", "Trigger", "Severity", "Runs", "Success", "Rate"]]
        for p in pb_list:
            runs_n   = p.get("runs", 0)
            success_n= p.get("success", 0)
            rate     = f"{int(success_n/max(runs_n,1)*100)}%" if runs_n > 0 else "—"
            tdata.append([
                Paragraph(str(p.get("name","—"))[:45], S["body"]),
                Paragraph(str(p.get("trigger","—")), S["mono"]),
                Paragraph(str(p.get("sev","any")), S["body"]),
                Paragraph(str(runs_n), S["mono"]),
                Paragraph(str(success_n), S["mono"]),
                Paragraph(rate, ParagraphStyle("rt", fontSize=8, fontName="Helvetica-Bold",
                    textColor=C_GREEN if runs_n>0 and success_n==runs_n else C_AMBER,
                    alignment=TA_CENTER)),
            ])
        t = Table(tdata, colWidths=[60*mm, 30*mm, 20*mm, 16*mm, 16*mm, 18*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), C_T2),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.25, C_GRAY),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        story.append(t)
    story.append(Spacer(1, 6*mm))

    # ── 5. Log Sources ────────────────────────────────────────
    story.append(Paragraph("5. Log Ingestion Sources", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 3*mm))

    story.append(kpi_table([
        (stats.get("total",  len(src_list)), "Total Sources", C_CYAN),
        (stats.get("online", "—"),           "Online",        C_GREEN),
        (stats.get("errors", "—"),           "Errors",        C_RED),
        (stats.get("eps",    "—"),           "Events/min",    C_AMBER),
    ], S))
    story.append(Spacer(1, 4*mm))

    if src_list:
        tdata = [["Source", "Protocol", "Format", "EPS", "Parse Rate", "Status"]]
        for s in src_list[:15]:
            status = s.get("status","—")
            tdata.append([
                Paragraph(str(s.get("name","—"))[:35], S["body"]),
                Paragraph(str(s.get("proto","—")), S["mono"]),
                Paragraph(str(s.get("format","—")), S["mono"]),
                Paragraph(str(s.get("eps",0)), S["mono"]),
                Paragraph(f"{s.get('parse_rate',0)}%", S["mono"]),
                Paragraph(status, ParagraphStyle("st", fontSize=8,
                    fontName="Helvetica-Bold", alignment=TA_CENTER,
                    textColor=C_GREEN if status=="ok" else C_RED)),
            ])
        t = Table(tdata, colWidths=[50*mm, 25*mm, 30*mm, 18*mm, 22*mm, 15*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), C_T2),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.25, C_GRAY),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        story.append(t)
    story.append(PageBreak())

    # ── 6. Threat Intelligence ────────────────────────────────
    story.append(Paragraph("6. Threat Intelligence", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 3*mm))

    matched = [i for i in ioc_list if i.get("matched")]
    story.append(kpi_table([
        (len(ioc_list), "Total IOCs",    C_CYAN),
        (len(matched),  "Matched",       C_RED),
        (len(feed_list),"Active Feeds",  C_GREEN),
        (sum(1 for f in feed_list if f.get("status")=="ok"), "Feeds Online", C_BLUE),
    ], S))
    story.append(Spacer(1, 4*mm))

    if ioc_list:
        tdata = [["Type", "Value", "Severity", "Feed", "Matched"]]
        for ioc in ioc_list[:15]:
            sev = (ioc.get("sev","—")).upper()
            tdata.append([
                Paragraph(str(ioc.get("type","—")).upper(), S["mono"]),
                Paragraph(str(ioc.get("val","—"))[:40], S["mono"]),
                Paragraph(sev, ParagraphStyle("sv3", fontSize=8,
                    fontName="Helvetica-Bold", textColor=sev_color(sev))),
                Paragraph(str(ioc.get("feed","—")), S["body"]),
                Paragraph("✓" if ioc.get("matched") else "—",
                    ParagraphStyle("m", fontSize=9, alignment=TA_CENTER,
                    textColor=C_GREEN if ioc.get("matched") else C_GRAY)),
            ])
        t = Table(tdata, colWidths=[18*mm, 65*mm, 22*mm, 30*mm, 15*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), C_T2),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.25, C_GRAY),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        story.append(t)
    story.append(Spacer(1, 6*mm))

    # ── 7. UEBA Baseline ─────────────────────────────────────
    story.append(Paragraph("7. UEBA Behavioral Baseline", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 3*mm))

    story.append(kpi_table([
        (round(baseline.get("avg_score",0)),          "Avg Security Score", C_CYAN),
        (round(baseline.get("avg_findings",0)),        "Avg Findings/Scan",  C_AMBER),
        (f"{round(baseline.get('gate_pass_rate',0)*100)}%","Gate Pass Rate", C_GREEN),
        (round(baseline.get("avg_scans_per_day",0),1), "Avg Scans/Day",     C_BLUE),
    ], S))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"Baseline period: {baseline.get('period','30d')} · "
        f"Score std deviation: {round(baseline.get('std_score',0),1)} pts",
        S["body"]))
    story.append(PageBreak())

    # ── 8. Asset Inventory ────────────────────────────────────
    story.append(Paragraph("8. Asset Inventory", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY))
    story.append(Spacer(1, 3*mm))

    story.append(kpi_table([
        (asset_sum.get("total",   len(asset_list)), "Total Assets",  C_CYAN),
        (asset_sum.get("critical","—"),             "Critical Risk", C_RED),
        (asset_sum.get("high",    "—"),             "High Risk",     C_AMBER),
        (asset_sum.get("clean",   "—"),             "Clean Assets",  C_GREEN),
    ], S))
    story.append(Spacer(1, 4*mm))

    if asset_list:
        tdata = [["Asset", "Type", "Environment", "Critical", "High", "Risk Score"]]
        for a in asset_list[:15]:
            risk = a.get("risk_score", 0)
            tdata.append([
                Paragraph(str(a.get("name","—"))[:35], S["body"]),
                Paragraph(str(a.get("type","—")), S["mono"]),
                Paragraph(str(a.get("env","prod")), S["body"]),
                Paragraph(str(a.get("critical",0)),
                    ParagraphStyle("cr", fontSize=8, fontName="Helvetica-Bold",
                    textColor=C_RED if a.get("critical",0)>0 else C_GRAY,
                    alignment=TA_CENTER)),
                Paragraph(str(a.get("high",0)),
                    ParagraphStyle("hi", fontSize=8, fontName="Helvetica-Bold",
                    textColor=C_AMBER if a.get("high",0)>0 else C_GRAY,
                    alignment=TA_CENTER)),
                Paragraph(str(risk), ParagraphStyle("rs", fontSize=8,
                    fontName="Helvetica-Bold", alignment=TA_CENTER,
                    textColor=C_RED if risk>=70 else C_AMBER if risk>=40 else C_GREEN)),
            ])
        t = Table(tdata, colWidths=[55*mm, 20*mm, 25*mm, 18*mm, 14*mm, 22*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), C_DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), C_T2),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,0), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
            ("GRID", (0,0), (-1,-1), 0.25, C_GRAY),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        story.append(t)

    # ── Build PDF ─────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        topMargin=35*mm,
        bottomMargin=18*mm,
        leftMargin=15*mm,
        rightMargin=15*mm,
    )
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"✓ Report saved: {output} ({os.path.getsize(output):,} bytes)")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--token",  required=True, help="JWT token")
    p.add_argument("--output", default="vsp_siem_report.pdf")
    args = p.parse_args()
    build_report(args.token, args.output)
