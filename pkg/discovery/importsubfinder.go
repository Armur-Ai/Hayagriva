package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// SubfinderImport imports a subdomain-enumeration result (subfinder -oJ JSON
// lines, or a plain one-host-per-line list) as HOST observations — distinct
// from the URL/endpoint importers, which record reachable endpoints. Subdomain
// enumeration maps the name surface; whether each host is live is a separate
// (httpx) step. Pure offline parsing.
type SubfinderImport struct {
	Path string // path to a subfinder -oJ file, or a plain hostname list
}

func (SubfinderImport) Name() string { return "subfinder-import" }

// subfinderLine is the subset of subfinder -oJ fields we consume.
type subfinderLine struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

func (s SubfinderImport) Collect(ctx context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: s.Name()}
	f, err := os.Open(s.Path)
	if err != nil {
		run.Unavailable = "cannot open subfinder file: " + err.Error()
		return nil, run, err
	}
	defer f.Close()
	if err := ctx.Err(); err != nil {
		return nil, run, err
	}

	now := time.Now().UTC()
	var out []contracts.ComponentObservation
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, source := line, s.Name()
		// subfinder -oJ emits one JSON object per line; a plain list emits bare
		// hostnames. Accept both.
		if strings.HasPrefix(line, "{") {
			var sl subfinderLine
			if err := json.Unmarshal([]byte(line), &sl); err != nil || sl.Host == "" {
				continue
			}
			host = sl.Host
			if sl.Source != "" {
				source = s.Name() + ":" + sl.Source
			}
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, contracts.ComponentObservation{
			Ref: "host:" + host, Kind: "host", Value: host,
			ObservedBy: source, ObservedAt: now, Trust: contracts.TrustObserved,
		})
	}
	run.Ran = true
	return out, run, nil
}
