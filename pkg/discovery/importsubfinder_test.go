package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSubfinderImport_JSONAndPlainLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subs.txt")
	// Mix of subfinder -oJ JSON lines and bare hostnames, with a dup and a blank.
	data := `{"host":"api.example.com","input":"example.com","source":"crtsh"}
{"host":"www.example.com","input":"example.com","source":"dns"}
mail.example.com

api.example.com
# a comment
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	d := New(SubfinderImport{Path: path})
	b, err := d.Run(context.Background(), Job{Scope: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Collectors) != 1 || !b.Collectors[0].Ran {
		t.Fatalf("collector run = %+v", b.Collectors)
	}
	hosts := map[string]string{}
	for _, o := range b.Components {
		if o.Kind != "host" {
			t.Fatalf("subfinder import must emit host observations, got %q", o.Kind)
		}
		hosts[o.Value] = o.ObservedBy
	}
	if len(hosts) != 3 { // api, www, mail — api deduped
		t.Fatalf("hosts = %v, want 3 unique", hosts)
	}
	if hosts["api.example.com"] != "subfinder-import:crtsh" {
		t.Errorf("source provenance not carried: %q", hosts["api.example.com"])
	}
}

func TestSubfinderImport_MissingFileIsAGap(t *testing.T) {
	d := New(SubfinderImport{Path: "/no/such/subs.txt"})
	b, _ := d.Run(context.Background(), Job{})
	if len(b.Collectors) != 1 || b.Collectors[0].Ran || b.Collectors[0].Unavailable == "" {
		t.Fatalf("missing file must be an explicit gap, got %+v", b.Collectors)
	}
}
