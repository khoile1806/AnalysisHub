package osint

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestGenerateGraphML(t *testing.T) {
	nodes := []GraphNode{
		{ID: "a", Label: "acme.com", Type: "domain", Status: "done", Findings: 12, Root: true, Exposure: 40, Grade: "elevated"},
		{ID: "b", Label: "1.2.3.4", Type: "ip", Status: "done", Depth: 1, Findings: 3},
	}
	edges := []GraphEdge{
		{From: "a", To: "b", Label: "1.2.3.4", Rel: "pivot"},
		{From: "a", To: "b", Label: "admin@acme.com", Rel: "correlation"},
	}
	out, err := GenerateGraphML(nodes, edges)
	if err != nil {
		t.Fatalf("GenerateGraphML: %v", err)
	}
	// Must be well-formed XML.
	var doc graphmlDoc
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}
	if len(doc.Graph.Nodes) != 2 || len(doc.Graph.Edges) != 2 {
		t.Fatalf("expected 2 nodes / 2 edges, got %d / %d", len(doc.Graph.Nodes), len(doc.Graph.Edges))
	}
	s := string(out)
	for _, want := range []string{"graphml", "acme.com", `edgedefault="directed"`, "correlation"} {
		if !strings.Contains(s, want) {
			t.Errorf("GraphML output missing %q", want)
		}
	}
}
