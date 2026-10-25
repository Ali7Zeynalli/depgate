package airules

import (
	"strings"
	"testing"
)

func TestBuildPicksVersionedRules(t *testing.T) {
	r := Build(map[string]string{"next": "16.2.1", "react": "19.2.0", "tailwindcss": "3.4.17", "moment": "2.30.1", "node-fetch": "2.7.0", "left-pad": "1.3.0"}, "22.20.0")
	if r == nil {
		t.Fatal("nil")
	}
	got := map[string]bool{}
	for _, x := range r.Rules {
		got[x.Topic] = true
		if x.Text == "" || !strings.HasPrefix(x.Docs, "https://") {
			t.Fatalf("incomplete rule %+v", x)
		}
	}
	for _, want := range []string{"Next.js 16", "Next.js docs for agents", "Next.js routing", "React 19", "Tailwind CSS 3", "Node.js runtime 22.20.0"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for _, not := range []string{"Next.js 15", "React 18", "Tailwind CSS 4"} {
		if got[not] {
			t.Errorf("wrong-version rule %q included", not)
		}
	}
	rep := map[string]bool{}
	for _, x := range r.Replace {
		rep[x.Pkg] = true
	}
	if !rep["moment"] || !rep["node-fetch"] || !rep["left-pad"] {
		t.Fatalf("replacements %+v", r.Replace)
	}
	if len(r.Stack) != 3 || r.Stack[0].Pkg != "next" || r.Stack[0].Version != "16.2.1" {
		t.Fatalf("stack %+v", r.Stack)
	}
}

func TestReplacementNeedsNode(t *testing.T) {
	r := Build(map[string]string{"node-fetch": "2.7.0", "dotenv": "16.4.5"}, "16.20.0")
	if r != nil && len(r.Replace) != 0 {
		t.Fatalf("Node 16 must keep node-fetch/dotenv: %+v", r.Replace)
	}
	r = Build(map[string]string{"node-fetch": "2.7.0"}, "")
	if r != nil && len(r.Replace) != 0 {
		t.Fatalf("unknown Node must not suggest built-ins: %+v", r.Replace)
	}
}

func TestNothingToSay(t *testing.T) {
	if r := Build(map[string]string{"left-pad-x": "1.0.0"}, ""); r != nil {
		t.Fatalf("expected nil, got %+v", r)
	}
}

func TestRuleRangesValid(t *testing.T) {
	for _, r := range append(append([]rule{}, rules...), nodeRules...) {
		if !inRange(r.min, r.min, r.max) {
			t.Errorf("%s %s: min %s outside its own range", r.pkg, r.topic, r.min)
		}
		if len(r.texts) == 0 || !strings.HasPrefix(r.docs, "https://") {
			t.Errorf("%s: missing text or docs", r.topic)
		}
	}
	for _, x := range replacements {
		if x.use == "" || x.why == "" || !strings.HasPrefix(x.docs, "https://") {
			t.Errorf("replacement %s incomplete", x.pkg)
		}
	}
}
