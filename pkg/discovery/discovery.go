// Package discovery is Hayagriva's reusable reconnaissance engine. It runs a
// set of scope-bounded collectors and assembles a provenance-preserving
// contracts.DiscoveryBundle. It is embeddable (Swarm can instantiate it) and
// drives the standalone `hayagriva` CLI.
//
// Status: scaffold. The Discoverer + Collector seams are real and tested; the
// concrete collectors (httpx/katana/OpenAPI/etc.) are ported from Pentest
// Swarm's internal/agent/recon in migration phase P1. A Discoverer with no
// registered collectors honestly reports an empty bundle with a coverage gap —
// never a "clean" empty scan.
package discovery

import (
	"context"
	"fmt"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// Job describes one authorized discovery run. The capability interfaces are
// supplied by the host (Pentest Swarm during a combined assessment, or
// Hayagriva's own bounded host when standalone) and enforce scope/budget at the
// real network boundary.
type Job struct {
	Scope []string
	Guard contracts.ScopeGuard  // may be nil in a trusted standalone/offline run
	Gate  contracts.RequestGate // may be nil when unmetered
	Clock contracts.Clock       // injectable; defaults to wall clock when nil
}

// Collector is one discovery capability (HTTP probe, API-spec discovery,
// browser capture, ...). A collector reports its own capability/coverage; a
// missing optional binary is an explicit gap via CollectorRun.Unavailable, not
// a silent empty success.
type Collector interface {
	Name() string
	Collect(ctx context.Context, job Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error)
}

// Discoverer runs collectors and assembles a DiscoveryBundle.
type Discoverer struct {
	Collectors []Collector
}

// New builds a Discoverer from zero or more collectors.
func New(collectors ...Collector) *Discoverer {
	return &Discoverer{Collectors: collectors}
}

func (d *Discoverer) now(job Job) time.Time {
	if job.Clock != nil {
		return job.Clock.Now()
	}
	return time.Now().UTC()
}

// Run executes every collector within the job's scope and assembles the bundle.
// A collector error is recorded as that collector's Unavailable reason; it does
// not abort the run or imply a clean result.
func (d *Discoverer) Run(ctx context.Context, job Job) (contracts.DiscoveryBundle, error) {
	start := d.now(job)
	b := contracts.DiscoveryBundle{
		BundleID:  fmt.Sprintf("disc-%d", start.UnixNano()),
		Scope:     job.Scope,
		StartedAt: start,
	}
	for _, c := range d.Collectors {
		if err := ctx.Err(); err != nil {
			return b, err
		}
		obs, run, err := c.Collect(ctx, job)
		if err != nil {
			run.Ran = false
			if run.Unavailable == "" {
				run.Unavailable = err.Error()
			}
		}
		run.ItemsEmitted = len(obs)
		b.Collectors = append(b.Collectors, run)
		b.Components = append(b.Components, obs...)
	}
	if len(d.Collectors) == 0 {
		b.Limits = append(b.Limits, "no collectors registered — this is a coverage gap, not a clean scan (P1 ports recon collectors here)")
	}
	b.FinishedAt = d.now(job)
	return b, nil
}
