#!/usr/bin/env python3
"""Set next_true / next_false on condition nodes for linear marketplace playbooks.

The Go SOAR engine routes condition steps using node.next_true (when expr is
truthy) or node.next_false (when falsy). Marketplace playbooks were generated
with linear edges (n0 → n1 → n2 → ...) but no explicit branching set on
condition nodes, so the engine doesn't know where to go after evaluating.

For linear playbooks we set both next_true and next_false to the same target:
the unique outgoing edge. The condition still gates execution (the engine
records the truthy/falsy decision and outputs it), but execution flow is
the same regardless — appropriate for proof-of-concept marketplace data.

Idempotent: marker '/* routed */' on a condition's config_raw flags it done.
"""
import psycopg2
import json
import sys

ROUTE_MARKER = "/* routed */"


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
    nodes_routed = 0
    nodes_already = 0
    nodes_no_edge = 0

    for pid, name, graph in rows:
        if isinstance(graph, str):
            graph = json.loads(graph)
        if not isinstance(graph, dict) or "nodes" not in graph:
            continue
        edges = graph.get("edges", [])
        # Build adjacency: node_id → list of out-neighbors
        adj = {}
        for e in edges:
            if isinstance(e, list) and len(e) == 2:
                adj.setdefault(e[0], []).append(e[1])

        modified = False
        for node in graph["nodes"]:
            if node.get("type") != "condition":
                continue

            # Idempotency
            if ROUTE_MARKER in (node.get("config_raw") or ""):
                nodes_already += 1
                continue

            nid = node.get("id")
            outs = adj.get(nid, [])
            if not outs:
                nodes_no_edge += 1
                continue
            target = outs[0]  # linear chain: only one outgoing edge

            node["next_true"] = target
            node["next_false"] = target  # linear: continue regardless

            # Append marker to config_raw for idempotency
            cfg = node.get("config_raw", "")
            if ROUTE_MARKER not in cfg:
                node["config_raw"] = cfg.rstrip() + " " + ROUTE_MARKER

            nodes_routed += 1
            modified = True

        if modified:
            cur.execute(
                "UPDATE playbooks SET graph = %s::jsonb WHERE id = %s",
                (json.dumps(graph), str(pid)),
            )
            pb_changed += 1
            print(f"  OK   {name[:55]:<55}  routed condition steps")

    conn.commit()
    cur.close()
    conn.close()
    print(f"\nDone:")
    print(f"  {pb_changed} playbooks updated")
    print(f"  {nodes_routed} condition nodes given next_true/next_false")
    print(f"  {nodes_already} already routed (skipped)")
    print(f"  {nodes_no_edge} condition nodes had no outgoing edge (terminal)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
