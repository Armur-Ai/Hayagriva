package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// HTTPXImport is a Collector that imports an httpx JSONL file as discovery
// evidence (endpoint + technology observations). It is pure parsing — no
// network — and is the first P1 collector ported from Pentest Swarm's recon
// ingestion (ctxpack). Scanner *vulnerability* claims are deliberately NOT
// emitted here: Hayagriva observes surface; weakness adjudication is not its job.
type HTTPXImport struct {
	Path string // path to an httpx -json / -jsonl output file
}

func (HTTPXImport) Name() string { return "httpx-import" }

// httpxLine is the subset of httpx JSONL fields we consume.
type httpxLine struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
	Webserver  string   `json:"webserver"`
}

func (h HTTPXImport) Collect(ctx context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: h.Name(), Ran: false}
	f, err := os.Open(h.Path)
	if err != nil {
		run.Unavailable = "cannot open httpx file: " + err.Error()
		return nil, run, err
	}
	defer f.Close()

	now := time.Now().UTC()
	var out []contracts.ComponentObservation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	line := 0
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return out, run, err
		}
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var hl httpxLine
		if err := json.Unmarshal(b, &hl); err != nil {
			continue // skip malformed lines; a parse skip is not a finding
		}
		url := hl.URL
		if url == "" {
			url = hl.Input
		}
		if url == "" {
			continue
		}
		attrs := map[string]string{}
		if hl.StatusCode != 0 {
			attrs["status_code"] = itoa(hl.StatusCode)
		}
		if hl.Title != "" {
			attrs["title"] = hl.Title
		}
		if hl.Webserver != "" {
			attrs["webserver"] = hl.Webserver
		}
		out = append(out, contracts.ComponentObservation{
			Ref:        "httpx:" + url,
			Kind:       "endpoint",
			Value:      url,
			Attributes: attrs,
			ObservedBy: h.Name(),
			ObservedAt: now,
			Trust:      contracts.TrustObserved,
		})
		for _, t := range hl.Tech {
			out = append(out, contracts.ComponentObservation{
				Ref:        "tech:" + url + ":" + t,
				Kind:       "technology",
				Value:      t,
				Attributes: map[string]string{"on": url},
				ObservedBy: h.Name(),
				ObservedAt: now,
				Trust:      contracts.TrustObserved,
			})
		}
	}
	if err := sc.Err(); err != nil {
		run.Unavailable = "read error: " + err.Error()
		return out, run, err
	}
	run.Ran = true
	return out, run, nil
}

// itoa avoids importing strconv for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
