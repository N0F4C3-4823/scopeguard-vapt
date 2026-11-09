# Changelog

## v1.0.0-beta.1 — 2026-11-09

- Added the guided minimal assessment wizard for details, targets, profile selection, review, and start.
- Added responsive corporate UI styling, live activity, results filtering, evidence preview, report downloads, and settings navigation.
- Persisted client/project metadata and added export availability and file-size reporting.
- Preserved 40 testcase records, four assessment profiles, capability-aware applicability, deterministic classification, evidence provenance, PNG POCs, CSV/JSON/ZIP exports, and optional Ollama triage.
- Added Linux release packaging, pinned runtime/development dependency manifests, installer diagnostics, project-local Ollama setup, health-checking launcher, CI, and security/release documentation.
- Added service-first TCP/UDP discovery with protocol-preserving observations, explicit scan-completeness handling, service gates, and executable-specific timeout/error explanations.
- Added bounded discrepancy recovery through a typed safe-action registry; Ollama suggestions remain advisory and deterministic classification remains authoritative.
- Added fail-closed export validation requiring evidence-backed POC PNGs for finalized FOUND/NOT_FOUND results and two-line explanations for every finalized verdict.
- Added target-wise testcase tables with per-target POC preview, download, PNG clipboard copy, and exact two-line description copy actions.
- Enforced client-safe two-line descriptions without target identifiers, tool names, AI references, or internal execution terminology; added capped progressive timeout recovery with changed-command and no-loop safeguards.

Controlled validation remains distinct from exhaustive external vulnerability validation. See the capability matrices under docs/.
