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
	fmt.Fprintln(os.Stderr, "usage: hayagriva discover --scope <host[,host...]> [--urls f] [--import-httpx f] [--import-nmap f] [--import-openapi f] [--import-katana f] [--import-nuclei f]")
	fmt.Fprintln(os.Stderr, "       (with no import flags, discover emits an honest empty bundle whose Limits record the coverage gap)")
	fmt.Fprintln(os.Stderr, "       hayagriva version")
}

func runDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	scope := fs.String("scope", "", "comma-separated authorized scope (required)")
	urls := fs.String("urls", "", "path to a URL/endpoint list (one per line; e.g. katana/gau output)")
	urlsSource := fs.String("urls-source", "urllist", "provenance label for --urls (e.g. katana, gau)")
	importHTTPX := fs.String("import-httpx", "", "path to an httpx -json/-jsonl output file")
	importNmap := fs.String("import-nmap", "", "path to an nmap -oX XML file")
	importOpenAPI := fs.String("import-openapi", "", "path to an openapi.json / swagger.json file")
	importKatana := fs.String("import-katana", "", "path to a katana -jsonl crawl output file")
	importNuclei := fs.String("import-nuclei", "", "path to a nuclei -jsonl output file (endpoints only; vuln verdicts are not imported)")
	_ = fs.Parse(args)
	if *scope == "" {
		fmt.Fprintln(os.Stderr, "error: --scope is required")
		os.Exit(2)
	}

	// Register the import collectors the operator pointed at. These turn existing
	// recon artifacts (katana/gau URL lists, httpx JSON, nmap XML, OpenAPI specs)
	// into a provenance-preserving DiscoveryBundle — offline, no network. Live
	// collectors (httpx/katana) register here too once a ReviewedToolRunner host
	// supplies the tool boundary.
	var collectors []discovery.Collector
	if *urls != "" {
		collectors = append(collectors, discovery.URLListImport{Path: *urls, Source: *urlsSource})
	}
	if *importHTTPX != "" {
		collectors = append(collectors, discovery.HTTPXImport{Path: *importHTTPX})
	}
	if *importNmap != "" {
		collectors = append(collectors, discovery.NmapImport{Path: *importNmap})
	}
	if *importOpenAPI != "" {
		collectors = append(collectors, discovery.OpenAPIImport{Path: *importOpenAPI})
	}
	if *importKatana != "" {
		collectors = append(collectors, discovery.KatanaImport{Path: *importKatana})
	}
	if *importNuclei != "" {
		collectors = append(collectors, discovery.NucleiImport{Path: *importNuclei})
	}

	d := discovery.New(collectors...)
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
