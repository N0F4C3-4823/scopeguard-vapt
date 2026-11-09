# Implementation plan

## Delivered foundation

- FastAPI app with SQLite persistence, health/dependency APIs, SPA serving, REST job lifecycle, and SSE events.
- Bounded scope parser and authorization audit records.
- 40-case canonical registry with fixture-driven command execution and deterministic status rules.
- Per-testcase live adapter registry with a checked-in 40-entry capability matrix; 34 adapters execute allowlisted nmap/curl/dig commands and six conditions fail closed pending specialized authorized sensors.
- Four assessment profiles with centralized capability-aware per-condition applicability and persisted reasons.
- Evidence provenance, SHA-256 hashes, exact POC folder structure, strict command/output PNG rendering, CSV, JSON, and ZIP export.
- Optional Ollama health/triage boundary with schema validation and no classification authority.
- Controlled local fixtures, actual loopback HTTP live services, production-path live assessments, unit/integration tests, and Playwright MCP browser acceptance coverage.

## Remaining environment-specific gates

Live network assessment behavior is intentionally conservative and requires an explicitly authorized target. Kali WSL capabilities and scanner availability are detected and surfaced rather than simulated. The installer supports an approved project-local Ollama runtime/model download; the active environment has exercised the CPU runtime and exact model through the local API.
