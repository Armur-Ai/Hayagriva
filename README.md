# Hayagriva

**Reusable reconnaissance & application discovery for the Armur suite — a Go library and CLI.**

> **Status: scaffold.** This repository is initialized; the implementation
> described below is **planned**, not yet built. Nothing here claims a working
> feature until its own package/docs say "implemented". Written in **Go**.

Hayagriva is the discovery engine of the Armur product suite. It performs
reconnaissance and application discovery, collects and parses evidence from a
target's exposed surface, and emits **structured, attributable discovery
evidence** that downstream products consume. It is useful standalone (point it
at a target, get a parsed inventory) and embeddable as a Go library.

## Role in the Armur suite

Hayagriva produces discovery evidence; other products reason over it. It is one
of six independent, interoperable products.

```mermaid
flowchart TD
  H[Hayagriva] -->|Discovery evidence| A[Akira]
  T[Trishul] -->|Code and dependency evidence| A
  E[Engira] -->|Advisory enrichment| A
  A -->|Eligible actions and paths| S[Pentest Swarm AI]
  S -->|Execution evidence| A
  A -->|Assessment snapshots| E
  E -->|Remediation request| D[Dhantra]
  D -->|Changed-source rescan| T
  D -->|Change evidence and retest request| E
  E -->|Authorized dynamic retest| S
```

Hayagriva does **not** attack, score, or report — it discovers and parses. That
separation is deliberate: recon ownership lives here (formerly split across
other tools), so there is exactly one authoritative discovery producer.

## What it will do (planned)

- **Reconnaissance** — resolve a target scope into hosts, services, endpoints,
  and application surface. Passive and active modes, scope-bounded.
- **Application discovery** — enumerate routes, parameters, forms, APIs
  (OpenAPI/GraphQL introspection where available), auth surfaces, and object
  references.
- **Collection** — capture raw evidence (responses, headers, fingerprints) with
  provenance (what was seen, when, how).
- **Parsing** — normalize tool output (nmap, httpx, katana, nuclei, and
  Hayagriva-native probes) into one typed evidence model.
- **Reusable Go library** — `pkg/` exposes the engine; the CLI and any API
  adapter are thin consumers of it, never of each other's internals.

## Design principles

- **Evidence, with provenance.** Every discovered item carries how/when it was
  observed. Downstream trust depends on it.
- **Scope-bounded and safe.** Discovery honors an explicit scope; no traffic
  outside it. Active probing is opt-in and rate-limited.
- **Standalone first.** A useful recon workflow must not require any other Armur
  service running.
- **One engine, many adapters.** File/CLI, in-process Go, and optional
  authenticated HTTP adapters implement the same declared semantics.

## Install (planned)

```bash
go install github.com/Armur-Ai/Hayagriva/cmd/hayagriva@latest
```

Module path: `github.com/Armur-Ai/Hayagriva`.

## Usage (planned)

```bash
# Discover an application surface within an explicit scope
hayagriva discover https://target.example --scope target.example --out recon.json

# Use as a library
#   import "github.com/Armur-Ai/Hayagriva/pkg/discovery"
```

### Import existing recon (offline, no network)

Hayagriva turns the output of the recon tools you already run into one
provenance-preserving `DiscoveryBundle` — the swarm consumes it to warm-start
and skip rediscovery. Each importer is pure parsing; a missing file is reported
as an explicit gap, never a silent clean scan. Scanner *vulnerability verdicts*
are deliberately not imported — Hayagriva observes surface; adjudication is the
swarm's job.

```bash
hayagriva discover --scope target.example \
  --urls urls.txt \                 # a URL/endpoint list (katana/gau/… )
  --import-httpx httpx.jsonl \       # httpx -json/-jsonl  → endpoints + tech
  --import-nmap scan.xml \           # nmap -oX            → hosts + services
  --import-openapi openapi.json \    # OpenAPI/Swagger     → operations
  --import-katana katana.jsonl \     # katana -jsonl crawl → endpoints + tech
  --import-nuclei nuclei.jsonl \     # nuclei -jsonl       → endpoints (surface only)
  --import-subfinder subs.txt        # subfinder -oJ/list  → hosts (subdomains)
```

| Flag | Source tool | Emits |
|---|---|---|
| `--urls` | katana / gau URL list | endpoints |
| `--import-httpx` | httpx `-json`/`-jsonl` | endpoints + technologies |
| `--import-nmap` | nmap `-oX` | hosts + services |
| `--import-openapi` | OpenAPI / Swagger spec | API operations |
| `--import-katana` | katana `-jsonl` | endpoints + technologies |
| `--import-nuclei` | nuclei `-jsonl` | endpoints (surface only; no verdicts) |
| `--import-subfinder` | subfinder `-oJ` / host list | hosts (subdomains) |

## Status & roadmap

This is a fresh scaffold. See [ROADMAP.md](./ROADMAP.md) for the phased plan.

## License

See `LICENSE` (to be added).
