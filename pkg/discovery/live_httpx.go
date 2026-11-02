package discovery

import (
	"bytes"
	"context"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// LiveHTTPX is a Collector that probes live targets by running httpx through a
// contracts.ReviewedToolRunner — the suite capability that enforces which tools
// may run and under what isolation. Hayagriva never shells out directly; the
// host (Pentest Swarm during a combined run, or Hayagriva's standalone host)
// supplies the runner, which is where scope/isolation are enforced.
//
// This is the live-recon pattern ported from Pentest Swarm: build a reviewed
// tool invocation, run it, parse the structured output into observations. It is
// unit-testable with a fake runner (no network).
type LiveHTTPX struct {
	Runner  contracts.ReviewedToolRunner
	Targets []string // explicit targets/URLs to probe (within scope)
}

func (LiveHTTPX) Name() string { return "httpx" }

func (l LiveHTTPX) Collect(ctx context.Context, job Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: l.Name()}
	if l.Runner == nil {
		run.Unavailable = "no ReviewedToolRunner supplied (httpx is operator-installed and host-enforced)"
		return nil, run, nil // an explicit gap, not an error-abort
	}
	targets := l.Targets
	if len(targets) == 0 {
		targets = job.Scope
	}
	if len(targets) == 0 {
		run.Unavailable = "no targets in scope to probe"
		return nil, run, nil
	}

	// A reviewed tool invocation: the runner resolves the actual binary/policy;
	// we only pass validated args. -json gives us JSONL we already parse.
	spec := contracts.ToolSpec{Tool: "httpx", Args: append([]string{"-json", "-silent"}, targetArgs(targets)...)}
	res, err := l.Runner.Run(ctx, spec)
	if err != nil {
		run.Unavailable = "httpx run failed: " + err.Error()
		return nil, run, err // a tool failure is not a clean/empty result
	}
	if res.Failed {
		run.Unavailable = "httpx reported failure (exit " + itoa(res.ExitCode) + ")"
		return nil, run, nil
	}
	out := parseHTTPXJSONL(bytes.NewReader(res.Stdout), l.Name(), time.Now().UTC())
	run.Ran = true
	return out, run, nil
}

// targetArgs turns targets into `-u <t>` pairs (httpx accepts repeated -u).
func targetArgs(targets []string) []string {
	args := make([]string, 0, len(targets)*2)
	for _, t := range targets {
		args = append(args, "-u", t)
	}
	return args
}
