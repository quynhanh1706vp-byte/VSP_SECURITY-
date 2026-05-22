package soar

import (
	"errors"
	"testing"
)

func mkNode(id string, t StepType) Node {
	return Node{ID: id, Type: t, Name: id}
}

func TestValidate_SimpleLinearChain(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			mkNode("n0", StepSetVar),
			mkNode("n1", StepNotify),
			mkNode("n2", StepEnd),
		},
		Edges: [][2]string{{"n0", "n1"}, {"n1", "n2"}},
	}
	if err := Validate(g); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_EmptyGraph(t *testing.T) {
	err := Validate(&Graph{})
	if !errors.Is(err, ErrEmptyGraph) {
		t.Fatalf("expected ErrEmptyGraph, got %v", err)
	}
}

func TestValidate_DuplicateID(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			mkNode("n0", StepSetVar),
			mkNode("n0", StepNotify),
		},
	}
	if err := Validate(g); !errors.Is(err, ErrDuplicateNodeID) {
		t.Fatalf("expected ErrDuplicateNodeID, got %v", err)
	}
}

func TestValidate_UnknownStep(t *testing.T) {
	g := &Graph{
		Nodes: []Node{{ID: "n0", Type: StepType("bogus"), Name: "x"}},
	}
	if err := Validate(g); !errors.Is(err, ErrUnknownStepType) {
		t.Fatalf("expected ErrUnknownStepType, got %v", err)
	}
}

func TestValidate_EdgeToUnknownNode(t *testing.T) {
	g := &Graph{
		Nodes: []Node{mkNode("n0", StepSetVar)},
		Edges: [][2]string{{"n0", "ghost"}},
	}
	if err := Validate(g); !errors.Is(err, ErrEdgeUnknownNode) {
		t.Fatalf("expected ErrEdgeUnknownNode, got %v", err)
	}
}

func TestValidate_CycleDetected(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			mkNode("n0", StepSetVar),
			mkNode("n1", StepNotify),
			mkNode("n2", StepNotify),
		},
		Edges: [][2]string{{"n0", "n1"}, {"n1", "n2"}, {"n2", "n0"}},
	}
	if err := Validate(g); !errors.Is(err, ErrCycle) {
		t.Fatalf("expected ErrCycle, got %v", err)
	}
}

func TestValidate_Unreachable(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			mkNode("n0", StepSetVar),
			mkNode("n1", StepNotify),
			mkNode("orphan", StepNotify), // no edges in/out
		},
		Edges: [][2]string{{"n0", "n1"}},
		Entry: "n0",
	}
	if err := Validate(g); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("expected ErrUnreachable, got %v", err)
	}
}

func TestValidate_MultipleEntries(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			mkNode("a", StepSetVar),
			mkNode("b", StepSetVar),
			mkNode("c", StepNotify),
		},
		Edges: [][2]string{{"a", "c"}, {"b", "c"}},
		// no Entry set → both a and b have in-degree 0
	}
	if err := Validate(g); !errors.Is(err, ErrMultipleEntries) {
		t.Fatalf("expected ErrMultipleEntries, got %v", err)
	}
}

func TestValidate_TooManyNodes(t *testing.T) {
	nodes := make([]Node, MaxNodesPerGraph+1)
	for i := range nodes {
		nodes[i] = mkNode("n"+string(rune('a'+i%26))+string(rune('0'+i%10))+string(rune('A'+i%26))+"_"+itoa(i), StepSetVar)
	}
	// link them so reachability passes
	edges := make([][2]string, len(nodes)-1)
	for i := range edges {
		edges[i] = [2]string{nodes[i].ID, nodes[i+1].ID}
	}
	g := &Graph{Nodes: nodes, Edges: edges}
	if err := Validate(g); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("expected ErrTooManyNodes, got %v", err)
	}
}

func TestValidate_BranchFieldsCountAsEdges(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			{ID: "n0", Type: StepCondition, Name: "c", NextTrue: "n1", NextFalse: "n2"},
			mkNode("n1", StepNotify),
			mkNode("n2", StepNotify),
		},
		// no explicit edges; branch fields should suffice
	}
	if err := Validate(g); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_ForkWithoutJoinFails(t *testing.T) {
	g := &Graph{
		Nodes: []Node{
			{ID: "n0", Type: StepFork, Branches: []string{"n1"}, JoinNode: ""},
			mkNode("n1", StepNotify),
		},
	}
	err := Validate(g)
	if !errors.Is(err, ErrForkWithoutJoin) {
		t.Fatalf("expected ErrForkWithoutJoin, got %v", err)
	}
}

// itoa — itoa avoid strconv import in test
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
