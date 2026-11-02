package discovery

import (
	"context"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// fakeRunner returns canned httpx JSONL without touching the network.
type fakeRunner struct {
	stdout  string
	gotSpec contracts.ToolSpec
	failRun bool
}

func (f *fakeRunner) Run(_ context.Context, spec contracts.ToolSpec) (contracts.ToolResult, error) {
	f.gotSpec = spec
	if f.failRun {
		return contracts.ToolResult{Failed: true, ExitCode: 1}, nil
	}
	return contracts.ToolResult{Stdout: []byte(f.stdout)}, nil
}

func TestLiveHTTPXParsesRunnerOutput(t *testing.T) {
	fr := &fakeRunner{stdout: `{"url":"https://a.example/","status_code":200,"tech":["nginx"]}` + "\n"}
	d := New(LiveHTTPX{Runner: fr, Targets: []string{"a.example"}})
	b, err := d.Run(context.Background(), Job{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Components) != 2 { // endpoint + 1 tech
		t.Fatalf("components = %d, want 2", len(b.Components))
	}
	if fr.gotSpec.Tool != "httpx" {
		t.Fatalf("expected reviewed httpx invocation, got %q", fr.gotSpec.Tool)
	}
}

func TestLiveHTTPXMissingRunnerIsAGapNotACleanScan(t *testing.T) {
	d := New(LiveHTTPX{Targets: []string{"a.example"}}) // nil runner
	b, _ := d.Run(context.Background(), Job{})
	if b.Collectors[0].Ran || b.Collectors[0].Unavailable == "" {
		t.Fatalf("missing runner must be an explicit gap: %+v", b.Collectors[0])
	}
}
