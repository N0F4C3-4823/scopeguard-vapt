---
name: scopeguard-qa
description: Build, test, debug, and verify ScopeGuard VAPT workflows with deterministic security classifications and provenance-preserving evidence; use for assessment engine, GUI, evidence/POC, Ollama, or Kali WSL changes.
---

# ScopeGuard QA

Use this skill for any ScopeGuard feature, bug fix, security testcase, evidence exporter, GUI workflow, local-LLM integration, installation path, or runtime-recovery change. Work only against authorized targets and controlled fixtures. Before browser or export testing, verify a controlled-fixture identity or an explicit authorization record and preserve that scope in the assessment. Read the repository's existing `AGENTS.md`, test configuration, testcase registry, and evidence schemas before changing them; preserve existing project instructions.

## Source of truth and documentation

- Treat the deterministic assessment engine, its fixture inputs, and persisted execution evidence as authoritative. The UI and local LLM are clients of that result, not alternate sources of truth.
- When an unfamiliar or changing framework/library API is needed, use Context7 MCP first: resolve the library, query current documentation for the exact API/version, then implement the smallest compatible change. Do not rely on remembered signatures.
- Record assumptions and environment limitations in the test report. Never present an unrun, partially run, or inferred workflow as working.

## Required testcase contract

Before implementing or declaring a security check complete:

1. Locate the canonical registry and verify it contains exactly 40 unique, stable testcase IDs. Fail loudly for missing, duplicate, disabled, or unregistered checks; do not silently reduce the set.
2. For every testcase, identify its controlled fixtures and execute every state declared by the fixture contract, including positive, negative, not-applicable, and failure/incomplete paths where supported. Tests must exercise the real evaluator and evidence writer, not only mocked return values. Produce a machine-readable coverage manifest linking all 40 IDs to fixture IDs, executed states, persisted results, exported rows, and evidence artifact paths/hashes.
3. Use the evidence-based classifier as the only authority:
   - `FOUND` requires the testcase's positive predicate and complete supporting evidence.
   - `NOT_FOUND` requires a successful, complete check that establishes the negative predicate.
   - `NA` requires an explicit, deterministic applicability decision from the target/fixture contract.
   - Preserve `INCONCLUSIVE` whenever timeout, permission failure, command failure, missing output, parse ambiguity, incomplete execution, or insufficient evidence prevents a conclusion. Never convert an error or incomplete check into `NOT_FOUND`.
4. Keep the local LLM out of execution and classification. It may summarize already-persisted results or suggest follow-up text, but it must not invent findings/evidence, execute arbitrary commands, select a final status, edit exit codes/hashes/provenance, or override deterministic results. Enforce this at the backend boundary, not only in prompts.

Use the detailed contract in [references/evidence-contract.md](references/evidence-contract.md) when adding fixtures, result models, POCs, or exporters.

## Evidence and POC invariants

- Preserve the original command/argv, exact captured stdout/stderr, exit code, execution timestamps, target and fixture identifiers, testcase ID, tool/runtime information, and evidence provenance. Hash the original bytes and the generated evidence artifact with a documented algorithm (SHA-256 unless the project specifies another one).
- Keep command execution allowlisted and structured as an argv list. Do not build shell strings from target or LLM input; reject arbitrary commands, unsafe interpolation, and scope escapes.
- For every testcase, maintain exactly this logical layout, with condition-specific directories below each status:

  ```text
  POCs/<FOUND|NOT_FOUND>/<condition-specific-folder>/
  ```

  Put `INCONCLUSIVE` and `NA` records in the project's explicit non-POC result/evidence representation; do not misfile them under `NOT_FOUND`.
- Every PNG POC must contain only the actual executed command and its actual output, rendered verbatim. It must contain no heading, branding, metadata, timestamp decoration, status label, explanatory prose, or invented text. Store provenance, exit code, hashes, and structured metadata in sidecar data or the result store, never by adding text to the PNG.
- Verify PNG content from the produced file (including OCR/pixel or source-level checks appropriate to the renderer) and compare it with the captured command/output. A visually plausible screenshot is not evidence of correctness.
- Define and test the PNG renderer's lossless text contract: command text must come from the recorded argv using the documented serialization, stdout/stderr ordering and delimiter rules must be stable, text encoding and line endings must be explicit, and binary output must be preserved as a sidecar or cause a clear export failure rather than being invented or silently changed.

## GUI verification with Playwright MCP

Use Playwright MCP for every GUI workflow; do not substitute screenshots, API calls, or component tests for browser coverage. Exercise and assert the complete user-visible path for:

- target entry and validation;
- assessment creation/configuration;
- live progress, polling/streaming, cancellation, retry, and terminal-state handling;
- results, per-testcase status, `FOUND`/`NOT_FOUND`/`NA`/`INCONCLUSIVE` rendering, and error states;
- evidence previews, including command/output fidelity and provenance visibility without contaminating PNG content;
- CSV export/download and ZIP export/download, including filenames, HTTP/download success, archive contents, testcase coverage, evidence paths, and hashes.

Prefer accessibility snapshots and stable roles/labels, then assert observable text, state transitions, network/download responses, and persisted artifact contents. Use controlled fixtures so browser assertions cover known outcomes. A GUI test passes only when the browser workflow and its backend result agree.

For exports, select one assessment/target and verify the download is read-only, contains no other assessment's data, and does not mutate result rows, evidence bytes, or hashes. Validate the canonical CSV header/order/encoding/quoting/newline and exact status tokens from the project schema; reject duplicate/unknown testcase IDs and test spreadsheet-injection handling for untrusted text. Validate deterministic ZIP paths, required evidence/provenance sidecars, a manifest, and rejection of absolute paths, traversal, symlinks, or unsafe archive entries. Missing or malformed required evidence must fail closed with a clear error and cleanup of partial artifacts; it must never be silently synthesized or reclassified.

## Test and debug gates

For each change, run the project build plus lint/type-check/schema checks when available, then the relevant unit tests, backend integration tests, and Playwright browser tests; for assessment/evidence changes, run the complete 40-testcase fixture matrix and export coverage manifest. Reproduce and fix failures that are deterministic, then rerun the failing test and the affected regression set.

Also verify, in a fresh or appropriately isolated Kali Linux WSL environment when available:

- installation and dependency checks, including clean-start and missing-dependency diagnostics;
- Ollama connectivity, model availability, timeout/error handling, and the no-authority boundary for LLM output;
- resource management: bounded concurrency, cancellation, subprocess cleanup, timeouts, temporary-file cleanup, and no orphaned workers;
- recovery after interrupted assessments, crashed workers, lost Ollama, partial evidence writes, and restart/resume paths.

If Kali WSL, Ollama, or a required browser/runtime is unavailable, run every safe substitute, label the missing gate explicitly as blocked/unverified, and do not claim the feature works.

## Review-only mode and completion report

If the request is explicitly review-only, do not edit application files or run live assessments. Inspect the applicable instructions/artifacts and report that application behavior remains unverified. In every report, separate `Inspected` evidence (files, schemas, code) from `Executed` evidence (commands, tests, browser runs, downloads). Do not turn a successful documentation review into a claim that the feature works.

Before handing off implementation work, report the exact commands/tests run and their outcomes, build/type-check results, the 40-testcase coverage manifest result, the fixture/result states exercised, authorization preflight, evidence/PNG/export checks, read-only/scope-isolation checks, and any blocked environment gates. Link to preserved failure artifacts when useful. Never infer success from code inspection or a partial test run.
