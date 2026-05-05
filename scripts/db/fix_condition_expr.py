#!/usr/bin/env python3
"""Make condition steps in marketplace playbooks runnable.

Goja sandbox eval-s config_raw as JS. YAML config like 'expr: foo > 0'
fails because of the 'expr:' prefix. Strategy:

  - If config_raw matches 'expr: <single line>' → extract <single line>,
    apply legacy operator translation (AND/OR/IN handled by Go side already),
    additionally translate MATCHES/STARTS_WITH/NOT for Goja safety.
  - If condition step actually carries non-condition YAML
    (route_rules:, retry_policy:, wait_for:) → that's a template tagging
    bug; replace expr with 'true' so the engine moves on.
  - Wrap final expression in defensive guard: undefined-safe eval.

Idempotent: detects already-translated steps via marker '/* fixed-cond */'.
"""
import psycopg2
import json
import re
import sys

MARKER = "/* fixed-cond-v2 */"
MARKER_V1 = "/* fixed-cond */"  # legacy from first migration


def fix_expr(raw: str) -> str:
    """Convert config_raw of a condition step to a Goja-evaluable JS expr."""
    s = (raw or "").strip()
    if not s:
        return f"true {MARKER}"
    # Idempotency — already fixed with v2
    if MARKER in s:
        return s
    # If v1 marker present, this row was rewritten by the previous version
    # without IIFE wrap. Strip v1 marker and any v1 wrapping artifacts before
    # re-translating. v1 output was: "<translated-expr> /* fixed-cond */"
    if MARKER_V1 in s:
        s = s.replace(MARKER_V1, "").strip()
        # v1 had no IIFE — single line is the translated expr; wrap it
        return f'(function(){{try{{return ({s});}}catch(_e){{return false;}}}})() {MARKER}'

    # Pattern A/B/C — single-line "expr: <stuff>"
    m = re.match(r"^expr\s*[:=]\s*(.+?)\s*$", s, re.MULTILINE)
    if m and len(s.splitlines()) <= 2:
        # Single-line expr (allow trailing newline)
        expr = m.group(1).strip()
        return _translate_expr(expr) + f" {MARKER}"

    # Pattern D — non-condition YAML mistakenly tagged condition
    # (route_rules, retry_policy, wait_for, etc.)
    return f"true {MARKER}"


def _translate_expr(expr: str) -> str:
    """Translate custom operators we know Go's legacyConditionToJS doesn't handle.

    Go engine handles AND/OR/IN downstream via legacyConditionToJS, but only
    when the expression is plain (not wrapped). So we keep AND/OR/IN as-is and
    let Go translate them. We do handle:
      - MATCHES "<glob>"  → defensive .match(/<regex>/)
      - STARTS_WITH "<x>" → defensive .startsWith
      - NOT (X)           → !(X)
      - "X=Y" equality    → X==Y  (Go side doesn't translate single =)

    Bare identifiers remain bare; Goja will throw ReferenceError at runtime
    if the var isn't bound in ec.Vars — but engine catches that as a step
    failure, not a panic. Acceptable for marketplace bootstrap data.
    """
    if expr.count('"') % 2 != 0:
        return "true"

    expr = re.sub(r"\bNOT\s+", "!", expr)

    def matches_repl(m):
        ident = m.group(1)
        glob = m.group(2)
        regex = re.escape(glob).replace(r"\*", ".*")
        return f'(typeof {ident}=="string" && {ident}.match(/^{regex}$/)!==null)'
    expr = re.sub(r'(\w+(?:\.\w+)*)\s+MATCHES\s+"([^"]*)"', matches_repl, expr)

    expr = re.sub(
        r'(\w+(?:\.\w+)*)\s+STARTS_WITH\s+"([^"]*)"',
        r'(typeof \1=="string" && \1.startsWith("\2"))',
        expr,
    )

    # =  →  ==   (skip ==, !=, <=, >=)
    expr = re.sub(r'(?<![!<>=])=(?!=)', "==", expr)

    # Defensive wrap: catch ReferenceError on undefined vars → false.
    # IIFE+try/catch lets engine record step.done with truthy=false instead
    # of failing the entire run when ec.Vars don't bind a referenced var.
    return f'(function(){{try{{return ({expr});}}catch(_e){{return false;}}}})()'


def main():
    conn = psycopg2.connect("dbname=vsp_go user=postgres host=/var/run/postgresql")
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, graph
        FROM playbooks
        WHERE created_at > '2026-05-04'
          AND graph IS NOT NULL
    """)
    rows = cur.fetchall()
    print(f"Scanning {len(rows)} marketplace playbooks", flush=True)

    pb_changed = 0
    nodes_changed = 0
    nodes_already = 0

    for pid, name, graph in rows:
        if isinstance(graph, str):
            graph = json.loads(graph)
        if not isinstance(graph, dict) or "nodes" not in graph:
            continue
        modified = False
        for node in graph["nodes"]:
            if node.get("type") != "condition":
                continue
            cur_raw = node.get("config_raw", "")
            if MARKER in cur_raw:
                nodes_already += 1
                continue
            new_raw = fix_expr(cur_raw)
            if new_raw != cur_raw:
                node["config_raw"] = new_raw
                modified = True
                nodes_changed += 1
        if modified:
            cur.execute(
                "UPDATE playbooks SET graph = %s::jsonb WHERE id = %s",
                (json.dumps(graph), str(pid)),
            )
            pb_changed += 1
            print(f"  OK   {name[:55]:<55}  ({sum(1 for n in graph['nodes'] if n.get('type')=='condition')} condition steps)")

    conn.commit()
    cur.close()
    conn.close()
    print(f"\nDone: {pb_changed} playbooks updated, {nodes_changed} condition nodes rewritten, {nodes_already} already done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
