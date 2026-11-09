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
- Made complete installation fail closed unless Ollama, `qwen2.5:1.5b-instruct`, raw inference, and ScopeGuard structured AI self-test all pass; added explicit limited-mode installation and real timeout-retry schema guidance for Qwen.
- Configured project-managed Ollama startup for documented CPU execution, 2048-token context, one model, one request, bounded queueing, and disabled cloud features; CPU library selection falls back to the portable library when AVX2 is unavailable.
- Added build diagnostics and a versioned external-accessibility classification policy: confirmed filtered TCP endpoints can become evidence-backed NA without rescanning, UDP `open|filtered` remains explicitly ambiguous, and incomplete checks remain separate operational coverage states.
- Added safe historical evidence re-adjudication, genuine NA applicability POCs (including scope-only probes), and preserved target-owned command/output provenance for CSV, JSON, and ZIP exports.
- Replaced curl-based anonymous FTP validation with a bounded native protocol probe that distinguishes a real 230 anonymous-login response, explicit denial, and timeout/failure.
- Moved HTTP/HTTPS security checks to Nmap's safe HTTP scripts with condition-aware parsing; separated ICMP timestamp/address-mask checks from host reachability and retained DNS UDP/TCP response flags independently.
- Added operator-reviewed Testcase 11 software/version review with preserved ambiguous and unidentified entries, genuine discovery POCs, auditable decisions, per-target isolation, and no online vulnerability research.
- Added bounded target-level parallel scheduling for up to 10 concurrent targets, with queued-target backfill, independent progress, evidence, and worker failure boundaries.

Controlled validation remains distinct from exhaustive external vulnerability validation. See the capability matrices under docs/.
