package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAPIv3ImportExpandsOperations(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "openapi.json")
	spec := `{
      "openapi":"3.0.0",
      "servers":[{"url":"https://api.example.com/v1/"}],
      "paths":{
        "/users":{"get":{},"post":{}},
        "/users/{id}":{"get":{},"delete":{},"parameters":[]}
      }
    }`
	if err := os.WriteFile(p, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(OpenAPIImport{Path: p})
	b, err := d.Run(context.Background(), Job{})
	if err != nil {
		t.Fatal(err)
	}
	// 2 (users get/post) + 2 (users/{id} get/delete) = 4; "parameters" skipped.
	if len(b.Components) != 4 {
		t.Fatalf("want 4 operations, got %d: %+v", len(b.Components), b.Components)
	}
	for _, o := range b.Components {
		if o.Kind != "endpoint" {
			t.Fatalf("expected endpoint kind, got %q", o.Kind)
		}
		if o.Trust != "asserted" {
			t.Fatalf("spec-declared endpoints should be TrustAsserted, got %q", o.Trust)
		}
	}
}

func TestSwaggerV2HostBasePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "swagger.json")
	spec := `{"swagger":"2.0","host":"api.example.com","basePath":"/v2","paths":{"/ping":{"get":{}}}}`
	_ = os.WriteFile(p, []byte(spec), 0o644)
	d := New(OpenAPIImport{Path: p})
	b, _ := d.Run(context.Background(), Job{})
	if len(b.Components) != 1 || b.Components[0].Value != "GET api.example.com/v2/ping" {
		t.Fatalf("v2 base handling wrong: %+v", b.Components)
	}
}
