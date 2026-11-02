package discovery

import (
	"context"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// fakeCollector emits one observation, to exercise assembly + provenance.
type fakeCollector struct{ name string }

func (f fakeCollector) Name() string { return f.name }
func (f fakeCollector) Collect(_ context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	return []contracts.ComponentObservation{{
			Ref: "o-1", Kind: "endpoint", Value: "https://example.test/api",
			ObservedBy: f.name, Trust: contracts.TrustObserved,
		}},
		contracts.CollectorRun{Name: f.name, Ran: true},
		nil
}

func TestRunAssemblesBundle(t *testing.T) {
	d := New(fakeCollector{name: "http"})
	b, err := d.Run(context.Background(), Job{Scope: []string{"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Components) != 1 || b.Components[0].ObservedBy != "http" {
		t.Fatalf("components = %+v", b.Components)
	}
	if len(b.Collectors) != 1 || b.Collectors[0].ItemsEmitted != 1 {
		t.Fatalf("collector run = %+v", b.Collectors)
	}
}

func TestEmptyRunReportsGapNotCleanScan(t *testing.T) {
	d := New()
	b, _ := d.Run(context.Background(), Job{Scope: []string{"example.test"}})
	if len(b.Limits) == 0 {
		t.Fatal("empty discoverer must report a coverage gap, not a clean scan")
	}
}
