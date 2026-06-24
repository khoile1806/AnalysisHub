package osint

import (
	"encoding/xml"
)

// GraphNode is one entity in the investigation graph (a scanned identifier).
type GraphNode struct {
	ID       string
	Label    string // the entity value (domain/ip/email…)
	Type     string // ip|domain|email|…
	Status   string
	Depth    int
	Findings int
	Root     bool
	Exposure int
	Grade    string
}

// GraphEdge connects two entities. Rel is "pivot" (auto-pivot parent→child) or
// "correlation" (a shared indicator links two otherwise-separate entities).
type GraphEdge struct {
	From  string
	To    string
	Label string
	Rel   string
}

// -- GraphML serialisation (Maltego / Gephi / yEd / Cytoscape import) ----------

type graphmlKey struct {
	ID       string `xml:"id,attr"`
	For      string `xml:"for,attr"`
	AttrName string `xml:"attr.name,attr"`
	AttrType string `xml:"attr.type,attr"`
}

type graphmlData struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type graphmlNode struct {
	ID   string        `xml:"id,attr"`
	Data []graphmlData `xml:"data"`
}

type graphmlEdge struct {
	Source string        `xml:"source,attr"`
	Target string        `xml:"target,attr"`
	Data   []graphmlData `xml:"data"`
}

type graphmlGraph struct {
	ID          string        `xml:"id,attr"`
	EdgeDefault string        `xml:"edgedefault,attr"`
	Nodes       []graphmlNode `xml:"node"`
	Edges       []graphmlEdge `xml:"edge"`
}

type graphmlDoc struct {
	XMLName xml.Name     `xml:"graphml"`
	Xmlns   string       `xml:"xmlns,attr"`
	Keys    []graphmlKey `xml:"key"`
	Graph   graphmlGraph `xml:"graph"`
}

// GenerateGraphML renders the investigation graph as GraphML so an analyst can
// import the whole entity/relationship graph into Maltego, Gephi, yEd or
// Cytoscape for deeper link analysis. GraphML is a documented open standard
// every major graph tool imports, which is why it is preferred over the
// proprietary native Maltego graph format.
func GenerateGraphML(nodes []GraphNode, edges []GraphEdge) ([]byte, error) {
	doc := graphmlDoc{
		Xmlns: "http://graphml.graphdrawing.org/xmlns",
		Keys: []graphmlKey{
			{ID: "label", For: "node", AttrName: "label", AttrType: "string"},
			{ID: "type", For: "node", AttrName: "type", AttrType: "string"},
			{ID: "status", For: "node", AttrName: "status", AttrType: "string"},
			{ID: "depth", For: "node", AttrName: "depth", AttrType: "int"},
			{ID: "findings", For: "node", AttrName: "findings", AttrType: "int"},
			{ID: "root", For: "node", AttrName: "root", AttrType: "boolean"},
			{ID: "exposure", For: "node", AttrName: "exposure", AttrType: "int"},
			{ID: "grade", For: "node", AttrName: "grade", AttrType: "string"},
			{ID: "rel", For: "edge", AttrName: "rel", AttrType: "string"},
			{ID: "elabel", For: "edge", AttrName: "label", AttrType: "string"},
		},
		Graph: graphmlGraph{ID: "investigation", EdgeDefault: "directed"},
	}

	for _, n := range nodes {
		gn := graphmlNode{ID: n.ID, Data: []graphmlData{
			{Key: "label", Value: n.Label},
			{Key: "type", Value: n.Type},
			{Key: "status", Value: n.Status},
			{Key: "depth", Value: itoa(n.Depth)},
			{Key: "findings", Value: itoa(n.Findings)},
			{Key: "root", Value: boolStr(n.Root)},
		}}
		if n.Root {
			gn.Data = append(gn.Data,
				graphmlData{Key: "exposure", Value: itoa(n.Exposure)},
				graphmlData{Key: "grade", Value: n.Grade})
		}
		doc.Graph.Nodes = append(doc.Graph.Nodes, gn)
	}

	for _, e := range edges {
		rel := e.Rel
		if rel == "" {
			rel = "pivot"
		}
		doc.Graph.Edges = append(doc.Graph.Edges, graphmlEdge{
			Source: e.From, Target: e.To,
			Data: []graphmlData{{Key: "rel", Value: rel}, {Key: "elabel", Value: e.Label}},
		})
	}

	body, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

func itoa(n int) string {
	// small, allocation-light int->string for graph attrs
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
