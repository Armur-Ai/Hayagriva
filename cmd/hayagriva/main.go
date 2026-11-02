// Command hayagriva is the standalone reconnaissance CLI. It runs discovery
// within an explicit scope and emits a contracts.DiscoveryBundle (wrapped in a
// versioned envelope) as JSON for the suite to consume.
//
// Status: scaffold. No collectors are registered yet (P1 ports Pentest Swarm's
// recon engine in), so `discover` currently emits an honest empty bundle whose
// Limits record the coverage gap.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Armur-Ai/Hayagriva/pkg/discovery"
	contracts "github.com/Armur-Ai/armur-contracts"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "discover":
		runDiscover(os.Args[2:])
	case "version":
		fmt.Printf("hayagriva (scaffold) — contracts %s\n", contracts.SchemaVersion)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hayagriva discover --scope <host[,host...]> [target]")
	fmt.Fprintln(os.Stderr, "       hayagriva version")
}

func runDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	scope := fs.String("scope", "", "comma-separated authorized scope (required)")
	_ = fs.Parse(args)
	if *scope == "" {
		fmt.Fprintln(os.Stderr, "error: --scope is required")
		os.Exit(2)
	}

	d := discovery.New() // P1 registers real collectors here
	bundle, err := d.Run(context.Background(), discovery.Job{Scope: splitComma(*scope)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery error: %v\n", err)
		os.Exit(1)
	}

	env, err := contracts.NewEnvelope(
		contracts.NSHayagriva,
		contracts.Producer{Product: "hayagriva", Version: "scaffold"},
		"DiscoveryBundle", bundle,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envelope error: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(env)
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
