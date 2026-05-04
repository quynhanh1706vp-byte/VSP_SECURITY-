package soar

import (
	"errors"
	"fmt"
)

// Validation errors.
var (
	ErrEmptyGraph      = errors.New("soar: graph has no nodes")
	ErrTooManyNodes    = errors.New("soar: graph exceeds max node count")
	ErrDuplicateNodeID = errors.New("soar: duplicate node ID")
	ErrUnknownStepType = errors.New("soar: unknown step type")
	ErrEdgeUnknownNode = errors.New("soar: edge references unknown node")
	ErrCycle           = errors.New("soar: graph contains a cycle")
	ErrUnreachable     = errors.New("soar: node not reachable from entry")
	ErrEntryMissing    = errors.New("soar: entry node not found")
	ErrMultipleEntries = errors.New("soar: multiple entry candidates (in-degree 0)")
	ErrForkWithoutJoin = errors.New("soar: fork node missing matching join")
	ErrInvalidNodeID   = errors.New("soar: invalid node ID format")
)

// Validate checks that g is a well-formed DAG suitable for execution.
//
// Order matters:
//  1. Size limits + ID uniqueness + type validity (cheap, fail fast)
//  2. Edge endpoint resolution + adjacency build
//  3. Cycle detection FIRST (before entry detection — a cycle has no in-degree-0 node,
//     which would otherwise be misreported as ErrEntryMissing)
//  4. Entry node determination (explicit g.Entry OR unique in-degree-0 node)
//  5. Reachability check from entry
//  6. Fork ↔ Join consistency
func Validate(g *Graph) error {
	if len(g.Nodes) == 0 {
		return ErrEmptyGraph
	}
	if len(g.Nodes) > MaxNodesPerGraph {
		return fmt.Errorf("%w: have %d, max %d", ErrTooManyNodes, len(g.Nodes), MaxNodesPerGraph)
	}

	// 1. Unique IDs + valid step types
	idSet := make(map[string]*Node, len(g.Nodes))
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.ID == "" {
			return fmt.Errorf("%w: node[%d] has empty ID", ErrInvalidNodeID, i)
		}
		if _, dup := idSet[n.ID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateNodeID, n.ID)
		}
		idSet[n.ID] = n

		if !n.Type.IsValid() {
			return fmt.Errorf("%w: %q (node %s)", ErrUnknownStepType, n.Type, n.ID)
		}
	}

	// 2. Build adjacency from edges + branch fields
	adj := make(map[string][]string, len(g.Nodes))
	inDegree := make(map[string]int, len(g.Nodes))
	for _, n := range g.Nodes {
		adj[n.ID] = nil
		inDegree[n.ID] = 0
	}

	addEdge := func(from, to string) {
		if !contains(adj[from], to) {
			adj[from] = append(adj[from], to)
			inDegree[to]++
		}
	}

	for i, e := range g.Edges {
		from, to := e[0], e[1]
		if _, ok := idSet[from]; !ok {
			return fmt.Errorf("%w: edge[%d] from=%q", ErrEdgeUnknownNode, i, from)
		}
		if _, ok := idSet[to]; !ok {
			return fmt.Errorf("%w: edge[%d] to=%q", ErrEdgeUnknownNode, i, to)
		}
		addEdge(from, to)
	}

	// Branch fields (NextTrue/NextFalse/Branches/OnFailureNext) also count as edges
	for _, n := range g.Nodes {
		for _, target := range branchTargets(&n) {
			if target == "" {
				continue
			}
			if _, ok := idSet[target]; !ok {
				return fmt.Errorf("%w: node %s references %q", ErrEdgeUnknownNode, n.ID, target)
			}
			addEdge(n.ID, target)
		}
	}

	// 3. Cycle detection (DFS 3-color) — MUST run before entry detection.
	//    Reason: a fully-cyclic graph has no in-degree-0 node, which would
	//    otherwise be misreported as ErrEntryMissing.
	const (
		white = 0 // unvisited
		gray  = 1 // in current DFS stack
		black = 2 // finished
	)
	color := make(map[string]int, len(g.Nodes))
	var stack []string
	var dfs func(string) error
	dfs = func(u string) error {
		color[u] = gray
		stack = append(stack, u)
		defer func() {
			color[u] = black
			stack = stack[:len(stack)-1]
		}()
		for _, v := range adj[u] {
			switch color[v] {
			case gray:
				path := append(append([]string{}, stack...), v)
				return fmt.Errorf("%w: %s → %s (path: %v)", ErrCycle, u, v, path)
			case white:
				if err := dfs(v); err != nil {
					return err
				}
			}
		}
		return nil
	}
	// Walk in stable order so error messages are deterministic
	for i := range g.Nodes {
		id := g.Nodes[i].ID
		if color[id] == white {
			if err := dfs(id); err != nil {
				return err
			}
		}
	}

	// 4. Determine entry node
	entry := g.Entry
	if entry == "" {
		var candidates []string
		for i := range g.Nodes {
			id := g.Nodes[i].ID
			if inDegree[id] == 0 {
				candidates = append(candidates, id)
			}
		}
		switch len(candidates) {
		case 0:
			// Should not happen if cycle check passed, but defensively:
			return fmt.Errorf("%w: graph has no source node", ErrEntryMissing)
		case 1:
			entry = candidates[0]
		default:
			return fmt.Errorf("%w: candidates=%v", ErrMultipleEntries, candidates)
		}
	}
	if _, ok := idSet[entry]; !ok {
		return fmt.Errorf("%w: %q", ErrEntryMissing, entry)
	}

	// 5. Reachability from entry (iterative BFS to avoid stack overflow on big graphs)
	reachable := make(map[string]bool, len(g.Nodes))
	queue := []string{entry}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		if reachable[u] {
			continue
		}
		reachable[u] = true
		queue = append(queue, adj[u]...)
	}
	for id := range idSet {
		if !reachable[id] {
			return fmt.Errorf("%w: %s", ErrUnreachable, id)
		}
	}

	// 6. Fork ↔ Join consistency
	for _, n := range g.Nodes {
		if n.Type == StepFork {
			if n.JoinNode == "" {
				return fmt.Errorf("%w: %s has no join_node", ErrForkWithoutJoin, n.ID)
			}
			if join, ok := idSet[n.JoinNode]; !ok || join.Type != StepJoin {
				return fmt.Errorf("%w: %s join_node=%q is not a join step", ErrForkWithoutJoin, n.ID, n.JoinNode)
			}
		}
	}

	return nil
}

// branchTargets returns all node IDs referenced by special fields.
func branchTargets(n *Node) []string {
	out := []string{n.NextTrue, n.NextFalse, n.JoinNode, n.OnFailureNext}
	out = append(out, n.Branches...)
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
