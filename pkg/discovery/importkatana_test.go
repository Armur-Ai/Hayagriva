package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKatanaImportParsesEndpointsAndTech(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "katana.jsonl")
	data := `{"timestamp":"2026-01-01T00:00:00Z","request":{"method":"GET","endpoint":"https://a.example/api/users"},"response":{"status_code":200,"server":"nginx","technologies":["Nginx","PHP"]}}
{"request":{"method":"POST","endpoint":"https://a.example/login"},"response":{"status_code":401}}
not-json-skip-me
{"request":{"method":"GET","endpoint":""},"response":{"status_code":200}}
{"request":{"method":"GET","endpoint":"https://a.example/admin"},"response":{"status_code":403}}
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	d := New(KatanaImport{Path: path})
	b, err := d.Run(context.Background(), Job{Scope: []string{"a.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Collectors) != 1 || !b.Collectors[0].Ran {
		t.Fatalf("collector run = %+v", b.Collectors)
	}
	// 3 endpoints (empty-endpoint + malformed lines skipped) + 2 technologies.
	endpoints, techs := 0, 0
	var apiAttrs map[string]string
	for _, o := range b.Components {
		switch o.Kind {
		case "endpoint":
			endpoints++
			if o.Value == "https://a.example/api/users" {
				apiAttrs = o.Attributes
			}
		case "technology":
			techs++
		}
	}
	if endpoints != 3 {
		t.Fatalf("endpoints = %d, want 3", endpoints)
	}
	if techs != 2 {
		t.Fatalf("techs = %d, want 2", techs)
	}
	if apiAttrs["method"] != "GET" || apiAttrs["status_code"] != "200" || apiAttrs["server"] != "nginx" {
		t.Errorf("endpoint attributes not captured: %+v", apiAttrs)
	}
}

func TestKatanaImportMissingFileIsAGap(t *testing.T) {
	d := New(KatanaImport{Path: "/no/such/file.jsonl"})
	b, _ := d.Run(context.Background(), Job{})
	if len(b.Collectors) != 1 || b.Collectors[0].Ran || b.Collectors[0].Unavailable == "" {
		t.Fatalf("missing file must be an explicit gap, got %+v", b.Collectors)
	}
}
