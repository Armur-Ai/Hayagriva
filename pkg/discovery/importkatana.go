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

// KatanaImport is a Collector that imports a Katana crawl (JSONL) as discovery
// evidence. Katana (ProjectDiscovery) is a crawler, so it yields the reachable
// endpoint surface — the natural companion to the httpx importer, which probes
// a host list. Pure parsing, no network. Like every Hayagriva collector it
// observes surface only; it never emits a vulnerability claim.
type KatanaImport struct {
	Path string // path to a `katana -jsonl` output file
}

func (KatanaImport) Name() string { return "katana-import" }

// katanaLine is the subset of Katana JSONL fields we consume. Katana nests the
// crawled URL under request.endpoint and tech/status under response.
type katanaLine struct {
	Request struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"`
	} `json:"request"`
	Response struct {
		StatusCode   int      `json:"status_code"`
		Server       string   `json:"server"`
		Technologies []string `json:"technologies"`
	} `json:"response"`
}

// parseKatanaJSONL parses Katana JSONL from r into endpoint + technology
// observations. Malformed lines are skipped (a parse skip is not a finding).
func parseKatanaJSONL(r io.Reader, observedBy string, now time.Time) []contracts.ComponentObservation {
	var out []contracts.ComponentObservation
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var kl katanaLine
		if err := json.Unmarshal(b, &kl); err != nil {
			continue
		}
		url := kl.Request.Endpoint
		if url == "" {
			continue
		}
		attrs := map[string]string{}
		if kl.Request.Method != "" {
			attrs["method"] = kl.Request.Method
		}
		if kl.Response.StatusCode != 0 {
			attrs["status_code"] = itoa(kl.Response.StatusCode)
		}
		if kl.Response.Server != "" {
			attrs["server"] = kl.Response.Server
		}
		out = append(out, contracts.ComponentObservation{
			Ref: "katana:" + url, Kind: "endpoint", Value: url,
			Attributes: attrs, ObservedBy: observedBy, ObservedAt: now, Trust: contracts.TrustObserved,
		})
		for _, t := range kl.Response.Technologies {
			if t == "" {
				continue
			}
			out = append(out, contracts.ComponentObservation{
				Ref: "tech:" + url + ":" + t, Kind: "technology", Value: t,
				Attributes: map[string]string{"on": url},
				ObservedBy: observedBy, ObservedAt: now, Trust: contracts.TrustObserved,
			})
		}
	}
	return out
}

func (k KatanaImport) Collect(ctx context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: k.Name()}
	f, err := os.Open(k.Path)
	if err != nil {
		run.Unavailable = "cannot open katana file: " + err.Error()
		return nil, run, err
	}
	defer f.Close()
	if err := ctx.Err(); err != nil {
		return nil, run, err
	}
	out := parseKatanaJSONL(f, k.Name(), time.Now().UTC())
	run.Ran = true
	return out, run, nil
}
