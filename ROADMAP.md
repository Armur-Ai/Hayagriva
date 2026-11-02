# Hayagriva — Roadmap

> Planning document. Phases are sequenced; each ships a usable standalone
> increment. Status legend: ☐ planned · ◐ in progress · ☑ done. Everything is ☐
> today (fresh scaffold).

## Phase 0 — Foundations
- ☐ Go module `github.com/Armur-Ai/Hayagriva`; `pkg/` (engine) + `cmd/hayagriva` (CLI) split, CLI consumes `pkg/` only.
- ☐ Typed **evidence model** (hosts, services, endpoints, params, auth surfaces, object refs) with provenance fields (source, timestamp, method).
- ☐ Explicit **scope** type + enforcement (deny traffic outside scope); dry-run mode.
- ☐ JSON output schema (versioned) + golden-file tests.
- ☐ LICENSE, CONTRIBUTING, CI (build + `go test ./...`).

## Phase 1 — Passive & active discovery
- ☐ Scope resolution: domains/CIDRs → hosts/services.
- ☐ HTTP surface probing (headers, fingerprints, tech detection), rate-limited.
- ☐ Route/endpoint enumeration (crawl) with bounded depth and politeness controls.
- ☐ Parameter/form extraction.

## Phase 2 — API discovery
- ☐ OpenAPI/Swagger ingestion and endpoint expansion.
- ☐ GraphQL introspection → typed endpoint/field inventory.
- ☐ Object-reference detection (IDs in paths/bodies) for downstream BOLA/IDOR reasoning.

## Phase 3 — Tool parsing & normalization
- ☐ Parsers for nmap XML, httpx/nuclei/katana JSONL → the evidence model.
- ☐ Import adapter: merge external recon output with provenance preserved.
- ☐ De-duplication keyed on stable fingerprints.

## Phase 4 — Library & adapters
- ☐ Stable `pkg/discovery` API (semver).
- ☐ In-process Go adapter + optional authenticated HTTP transport (same semantics, conformance fixtures).
- ☐ Emit **discovery evidence** in the shared contract Akira consumes.

## Phase 5 — Hardening & docs
- ☐ Resource/time bounds, cancellation, partial-result handling (a probe failure is not a negative result).
- ☐ Architecture doc + the suite topology (Mermaid).
- ☐ Reproducibility: deterministic runs on fixtures.

## Non-goals
- No attack/exploitation (that's Swarm), no scoring/reporting (Engira), no code analysis (Trishul). Hayagriva discovers and parses — nothing more.
