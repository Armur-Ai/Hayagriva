package discovery

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// URLListImport is a Collector that imports a plain URL list (one URL per line,
// e.g. katana or gau output) as endpoint ComponentObservations. Blank lines and
// comments (#) are skipped. Pure parsing, no network. Part of P1.
type URLListImport struct {
	Path   string
	Source string // label for provenance, e.g. "katana"; defaults to "urllist"
}

func (u URLListImport) Name() string {
	if u.Source != "" {
		return u.Source + "-import"
	}
	return "urllist-import"
}

func (u URLListImport) Collect(ctx context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: u.Name()}
	f, err := os.Open(u.Path)
	if err != nil {
		run.Unavailable = "cannot open url list: " + err.Error()
		return nil, run, err
	}
	defer f.Close()

	now := time.Now().UTC()
	seen := map[string]bool{}
	var out []contracts.ComponentObservation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 4*1024*1024)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return out, run, err
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "://") {
			continue // not a URL; skip rather than guess
		}
		if seen[line] {
			continue // de-dup within the file
		}
		seen[line] = true
		out = append(out, contracts.ComponentObservation{
			Ref: "url:" + line, Kind: "endpoint", Value: line,
			ObservedBy: u.Name(), ObservedAt: now, Trust: contracts.TrustObserved,
		})
	}
	if err := sc.Err(); err != nil {
		run.Unavailable = "read error: " + err.Error()
		return out, run, err
	}
	run.Ran = true
	return out, run, nil
}
