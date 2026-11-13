package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// NucleiImport imports a nuclei JSONL run as discovery evidence — but ONLY the
// surface it touched (the matched-at endpoints), never nuclei's vulnerability
// verdicts. Hayagriva observes surface; weakness adjudication belongs to the
// swarm's verification oracles, not an imported scanner claim. So a nuclei hit
// contributes the endpoint it reached, and nothing about severity/match is
// carried forward. Pure offline parsing.
type NucleiImport struct {
	Path string // path to a `nuclei -jsonl` output file
}

func (NucleiImport) Name() string { return "nuclei-import" }

// nucleiLine is the subset of nuclei JSONL fields we consume — the reached URL.
type nucleiLine struct {
	MatchedAt string `json:"matched-at"`
	Host      string `json:"host"`
	URL       string `json:"url"`
	Type      string `json:"type"`
}

// parseNucleiJSONL parses nuclei JSONL from r into endpoint observations only.
// Malformed lines are skipped; a line with no reachable URL is skipped.
func parseNucleiJSONL(r io.Reader, observedBy string, now time.Time) []contracts.ComponentObservation {
	var out []contracts.ComponentObservation
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var nl nucleiLine
		if err := json.Unmarshal(b, &nl); err != nil {
			continue
		}
		url := nl.MatchedAt
		if url == "" {
			url = nl.URL
		}
		if url == "" {
			url = nl.Host
		}
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		out = append(out, contracts.ComponentObservation{
			Ref: "nuclei:" + url, Kind: "endpoint", Value: url,
			ObservedBy: observedBy, ObservedAt: now, Trust: contracts.TrustObserved,
		})
	}
	return out
}

func (n NucleiImport) Collect(ctx context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: n.Name()}
	f, err := os.Open(n.Path)
	if err != nil {
		run.Unavailable = "cannot open nuclei file: " + err.Error()
		return nil, run, err
	}
	defer f.Close()
	if err := ctx.Err(); err != nil {
		return nil, run, err
	}
	out := parseNucleiJSONL(f, n.Name(), time.Now().UTC())
	run.Ran = true
	return out, run, nil
}
