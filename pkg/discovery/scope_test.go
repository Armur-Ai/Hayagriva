package discovery

import (
	"context"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://a.example/x":     "a.example",
		"GET https://api.b.io/v1": "api.b.io",
		"10.0.0.5:443/https":      "10.0.0.5",
		"c.example":               "c.example",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Fatalf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInScopeSubdomain(t *testing.T) {
	scope := []string{"example.test"}
	if !inScope("api.example.test", scope) {
		t.Fatal("subdomain should be in scope")
	}
	if !inScope("example.test", scope) {
		t.Fatal("apex should be in scope")
	}
	if inScope("evil.com", scope) {
		t.Fatal("out-of-scope host should be rejected")
	}
	if inScope("notexample.test", scope) {
		t.Fatal("suffix without dot boundary must not match")
	}
}

// scopeCollector emits an in-scope and an out-of-scope endpoint plus a tech label.
type scopeCollector struct{}

func (scopeCollector) Name() string { return "sc" }
func (scopeCollector) Collect(context.Context, Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	return []contracts.ComponentObservation{
		{Ref: "1", Kind: "endpoint", Value: "https://api.example.test/x"},
		{Ref: "2", Kind: "endpoint", Value: "https://evil.com/x"},
		{Ref: "3", Kind: "technology", Value: "nginx"},
	}, contracts.CollectorRun{Name: "sc", Ran: true}, nil
}

func TestRunEnforcesScope(t *testing.T) {
	d := New(scopeCollector{})
	b, err := d.Run(context.Background(), Job{Scope: []string{"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	// in-scope endpoint + the tech label kept; out-of-scope endpoint dropped.
	if len(b.Components) != 2 {
		t.Fatalf("want 2 kept, got %d: %+v", len(b.Components), b.Components)
	}
	foundLimit := false
	for _, l := range b.Limits {
		if l != "" && (l[:7] == "dropped") {
			foundLimit = true
		}
	}
	if !foundLimit {
		t.Fatalf("expected a dropped-out-of-scope limit note, got %v", b.Limits)
	}
}

func TestInScopeCIDR(t *testing.T) {
	scope := []string{"10.0.0.0/24", "example.test"}
	if !inScope("10.0.0.5", scope) {
		t.Fatal("IP within CIDR should be in scope")
	}
	if inScope("10.0.1.5", scope) {
		t.Fatal("IP outside CIDR should be rejected")
	}
	// domain entries still work alongside CIDR
	if !inScope("api.example.test", scope) {
		t.Fatal("subdomain should still match with a CIDR entry present")
	}
	// a hostname is not matched by a CIDR entry
	if inScope("evil.com", []string{"10.0.0.0/24"}) {
		t.Fatal("hostname must not match a CIDR entry")
	}
}
