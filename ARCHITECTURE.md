# ScopeGuard VAPT architecture

ScopeGuard is a local-first FastAPI application with a static, accessible frontend. The backend owns scope validation, job lifecycle, deterministic testcase evaluation, evidence persistence, and exports. The browser renders persisted state and receives real job events; it never makes security decisions.

```text
Browser (static HTML/CSS/JS)
        | REST + Server-Sent Events
        v
FastAPI application
  |-- Scope validator (ipaddress + bounded FQDN/CIDR handling)
  |-- SQLite state store
  |-- Assessment orchestrator (bounded worker, checkpoints, cancellation)
  |-- Allowlisted command runner (argv-only, timeout/process cleanup)
  |-- 40 registered deterministic testcase plugins
  |-- Live adapter matrix (34 allowlisted command adapters; 6 capability-only)
  |-- Capability-aware per-condition applicability engine
  |-- Evidence store (raw bytes, hashes, provenance, PNG renderer)
  |-- CSV/ZIP exporters (read-only, traversal-safe, atomic)
  |-- Optional Ollama client (secondary explanation only)
```

## Safety boundaries

- No default targets are stored in the database or frontend.
- `fixture://...` targets execute only the local deterministic fixture command. A separately authorized local-loopback live test exercises the production adapter path with actual nmap/curl/dig subprocesses.
- Authorized network targets use the per-testcase adapter in `app/live_adapters.py`; the checked-in machine-readable contract is `docs/live_capability_matrix.json` and is also served at `/api/capability-matrix`.
- Controlled service outcomes are tracked separately in `docs/security_engine_validation_matrix.json`: 34 live command paths execute, 16 have direct local-service positive/negative/inconclusive validation, and six are capability-only.
- Network targets require an explicit authorization affirmation and are never expanded beyond the normalized user scope.
- Commands are argv arrays from a fixed registry. Target strings and LLM responses are never passed to a shell.
- The classifier consumes captured execution records and fixed predicates. Ollama cannot assign a status, execute a command, or mutate evidence.
- Live parsers inspect raw stdout/stderr and exit status. They never append `STATUS` tokens to live command output, so required PNG POCs remain the original command plus the original captured output only.

## Assessment-aware applicability

Every assessment stores one of four types: External Network Pentest — Unauthenticated, Internal Network Pentest — Unauthenticated, Internal Network Pentest — Authenticated, or Custom / Hybrid Network Pentest. Each testcase condition declares its required vantage, capabilities, explicit permissions, credential requirement, and tool contract. The centralized applicability engine records `APPLICABLE`, `NA`, or an applicability limitation; the latter becomes `INCONCLUSIVE` and is never hidden as a negative result. Internal placement does not grant layer-2, wireless, inventory, egress, or credential capability by itself.

## Persistence

SQLite stores assessments, normalized targets, events, executions, testcase results, evidence records, and LLM triage. The filesystem stores immutable raw command output and generated exports beneath the configured data directory. Assessment status is reconstructed from the database after a process restart.
