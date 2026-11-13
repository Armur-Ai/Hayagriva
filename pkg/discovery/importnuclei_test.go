package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNucleiImportExtractsEndpointsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nuclei.jsonl")
	// Two distinct matched-at endpoints (one duplicated), plus a vuln severity
	// we must NOT carry forward, plus a malformed line.
	data := `{"template-id":"tech-detect","matched-at":"https://a.example/","host":"a.example","info":{"severity":"info","tags":["tech"]}}
{"template-id":"cve-2026-1","matched-at":"https://a.example/admin","info":{"severity":"critical"}}
{"template-id":"dup","matched-at":"https://a.example/"}
not-json
{"template-id":"nourl","info":{"severity":"low"}}
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	d := New(NucleiImport{Path: path})
	b, err := d.Run(context.Background(), Job{Scope: []string{"a.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Collectors) != 1 || !b.Collectors[0].Ran {
		t.Fatalf("collector run = %+v", b.Collectors)
	}
	endpoints := 0
	for _, o := range b.Components {
		if o.Kind != "endpoint" {
			t.Fatalf("nuclei import must only emit endpoints (surface), got kind %q", o.Kind)
		}
		endpoints++
		// Honesty check: no severity/vuln verdict leaks into attributes.
		if _, ok := o.Attributes["severity"]; ok {
			t.Errorf("severity must not be carried forward: %+v", o.Attributes)
		}
	}
	if endpoints != 2 { // deduped "/" + "/admin"
		t.Fatalf("endpoints = %d, want 2", endpoints)
	}
}

func TestNucleiImportMissingFileIsAGap(t *testing.T) {
	d := New(NucleiImport{Path: "/no/such/file.jsonl"})
	b, _ := d.Run(context.Background(), Job{})
	if len(b.Collectors) != 1 || b.Collectors[0].Ran || b.Collectors[0].Unavailable == "" {
		t.Fatalf("missing file must be an explicit gap, got %+v", b.Collectors)
	}
}
