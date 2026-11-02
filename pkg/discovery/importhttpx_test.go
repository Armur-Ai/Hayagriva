package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPXImportParsesEndpointsAndTech(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "httpx.jsonl")
	data := `{"url":"https://a.example/api","host":"a.example","status_code":200,"title":"API","tech":["nginx","php"]}
{"url":"https://a.example/login","status_code":401}
not-json-skip-me
{"input":"https://a.example/admin","status_code":403}
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	d := New(HTTPXImport{Path: path})
	b, err := d.Run(context.Background(), Job{Scope: []string{"a.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Collectors) != 1 || !b.Collectors[0].Ran {
		t.Fatalf("collector run = %+v", b.Collectors)
	}
	// 3 endpoints + 2 technologies = 5 observations (malformed line skipped).
	endpoints, techs := 0, 0
	for _, o := range b.Components {
		switch o.Kind {
		case "endpoint":
			endpoints++
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
}

func TestHTTPXImportMissingFileIsAGap(t *testing.T) {
	d := New(HTTPXImport{Path: "/no/such/file.jsonl"})
	b, _ := d.Run(context.Background(), Job{})
	if len(b.Collectors) != 1 || b.Collectors[0].Ran || b.Collectors[0].Unavailable == "" {
		t.Fatalf("missing file must be an explicit gap, got %+v", b.Collectors)
	}
}
