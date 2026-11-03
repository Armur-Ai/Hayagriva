package discovery

import (
	"context"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// dupCollector emits the same observation twice.
type dupCollector struct{ ref string }

func (dupCollector) Name() string { return "dup" }
func (d dupCollector) Collect(context.Context, Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	o := contracts.ComponentObservation{Ref: d.ref, Kind: "endpoint", Value: "https://a.test/x", Trust: contracts.TrustObserved}
	return []contracts.ComponentObservation{o, o}, contracts.CollectorRun{Name: "dup", Ran: true}, nil
}

func TestCrossCollectorDedup(t *testing.T) {
	// Two collectors both reporting the same endpoint ref -> one observation.
	d := New(dupCollector{ref: "e1"}, dupCollector{ref: "e1"})
	b, err := d.Run(context.Background(), Job{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Components) != 1 {
		t.Fatalf("expected 1 deduped observation, got %d", len(b.Components))
	}
}

func TestDedupFallsBackToKindValue(t *testing.T) {
	// No Ref set: dedup on Kind|Value.
	in := []contracts.ComponentObservation{
		{Kind: "host", Value: "10.0.0.1"},
		{Kind: "host", Value: "10.0.0.1"},
		{Kind: "service", Value: "10.0.0.1"},
	}
	if got := dedupObservations(in); len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}
