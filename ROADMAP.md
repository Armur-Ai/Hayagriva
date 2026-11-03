# Hayagriva — Roadmap

> Planning document. Phases are sequenced; each ships a usable standalone
> increment. Status legend: ☐ planned · ◐ in progress · ☑ done. Everything is ☐
> today (fresh scaffold).

## Phase 0 — Foundations
- ☐ Go module `github.com/Armur-Ai/Hayagriva`; `pkg/` (engine) + `cmd/hayagriva` (CLI) split, CLI consumes `pkg/` only.
- ☐ Typed **evidence model** (hosts, services, endpoints, params, auth surfaces, object refs) with provenance fields (source, timestamp, method).
- ◐ Scope enforcement: observations outside Job.Scope are dropped with a note (deny-traffic + dry-run pending).
- ☐ JSON output schema (versioned) + golden-file tests.
- ☐ LICENSE, CONTRIBUTING, CI (build + `go test ./...`).

## Phase 1 — Passive & active discovery
- ☐ Scope resolution: domains/CIDRs → hosts/services.
- ◐ HTTP surface probing via the live httpx collector (ReviewedToolRunner); rate-limiting via RequestGate pending.
- ☐ Route/endpoint enumeration (crawl) with bounded depth and politeness controls.
- ☐ Parameter/form extraction.

## Phase 2 — API discovery
- ☑ OpenAPI v3 / Swagger v2 ingestion and endpoint expansion (pkg/discovery OpenAPIImport).
- ☐ GraphQL introspection → typed endpoint/field inventory.
- ☐ Object-reference detection (IDs in paths/bodies) for downstream BOLA/IDOR reasoning.

## Phase 3 — Tool parsing & normalization
- ☑ Parsers for httpx JSONL, nmap XML, and URL-list (katana/gau) → the evidence model (pkg/discovery import collectors).
- ☑ Import adapter: external recon output merges onto the evidence model with provenance (ObservedBy/ObservedAt/Trust).
- ☑ Cross-collector de-duplication (by Ref, else Kind|Value) in Discoverer.Run.

## Phase 4 — Library & adapters
- ☐ Stable `pkg/discovery` API (semver).
- ◐ In-process Go consumed directly; the shared Adapter/transport lives in armur-contracts (conformance suite pending).
- ☐ Emit **discovery evidence** in the shared contract Akira consumes.

## Phase 5 — Hardening & docs
- ☐ Resource/time bounds, cancellation, partial-result handling (a probe failure is not a negative result).
- ☐ Architecture doc + the suite topology (Mermaid).
- ☐ Reproducibility: deterministic runs on fixtures.

## Non-goals
- No attack/exploitation (that's Swarm), no scoring/reporting (Engira), no code analysis (Trishul). Hayagriva discovers and parses — nothing more.
