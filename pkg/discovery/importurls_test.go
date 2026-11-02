package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestURLListImportDedupsAndSkips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "urls.txt")
	body := "# crawl output\nhttps://a.example/x\nhttps://a.example/x\n\nnot-a-url\nhttps://a.example/y\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(URLListImport{Path: path, Source: "katana"})
	b, err := d.Run(context.Background(), Job{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Components) != 2 { // x (deduped) + y; comment/blank/non-url skipped
		t.Fatalf("endpoints = %d, want 2: %+v", len(b.Components), b.Components)
	}
	if b.Collectors[0].Name != "katana-import" {
		t.Fatalf("source label not applied: %q", b.Collectors[0].Name)
	}
}
