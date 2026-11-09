# ScopeGuard engineering requirements

These instructions apply to the ScopeGuard VAPT application and its test/assessment tooling.

## Engineering

- Inspect the existing architecture, registry, schemas, and project instructions before changing behavior. Keep changes small and preserve public contracts unless the task explicitly changes them.
- Use Context7 MCP to consult current, version-appropriate documentation before using an unfamiliar or changing framework/library API. Verify the installed version and test the actual integration.
- Keep security decisions in deterministic, testable backend code. UI state and local-LLM text are presentations or suggestions, never authoritative assessment state.
- Use structured, allowlisted command execution with explicit argv, bounded timeouts, scope validation, and cleanup. Never pass target or LLM text to an unrestricted shell.
- Before browser/export tests, verify the target is a controlled fixture or has an explicit authorization record. Keep exports read-only and scoped to the selected assessment/target.

## Security and classification

- Run only against authorized targets and controlled fixtures. Preserve target scope and authorization context in assessment records.
- Support the four assessment profiles explicitly: external unauthenticated, internal unauthenticated, internal authenticated, and custom/hybrid. Applicability is evaluated per security condition from the selected profile, authorized scope, detected capabilities, credentials, permissions, tools, and vantage point; internal placement alone is never proof of capability.
- Every testcase condition must declare its prerequisites and receive an independent applicability decision. Automatically record precise `NA` reasons for genuinely inapplicable conditions and preserve `INCONCLUSIVE` for applicable checks that are blocked, unavailable, failed, timed out, or incomplete.
- The canonical registry must contain exactly 40 unique required security testcases. Every testcase must be implemented, registered, and exercised by controlled fixtures; missing or disabled checks fail validation.
- Classify only from complete, deterministic evidence:
  - `FOUND`: positive predicate proven.
  - `NOT_FOUND`: negative predicate proven by a successful complete check.
  - `NA`: explicit applicability decision.
  - `INCONCLUSIVE`: failed, timed out, denied, incomplete, ambiguous, or insufficient evidence.
- Never convert a failed or incomplete check into `NOT_FOUND`. Never let the local LLM invent a finding, execute a command, choose a classification, alter evidence, or override the deterministic evaluator. Enforce these boundaries in code and integration tests.

## Evidence and POCs

- Preserve original command/argv, exact stdout/stderr, exit code, hashes, timestamps, testcase/target/fixture IDs, tool versions, and provenance. Do not replace unknown facts with guesses.
- Keep the exact logical POC structure:

  ```text
  POCs/FOUND/<condition-specific-folder>/
  POCs/NOT_FOUND/<condition-specific-folder>/
  ```

- `NA` and `INCONCLUSIVE` are not `NOT_FOUND` POCs. Store them in the result/evidence model used for non-POC outcomes.
- PNG POCs contain only the actual executed command and its actual output. No heading, branding, metadata, timestamp decoration, status label, explanatory prose, or invented text may be rendered into a PNG. Keep provenance, exit code, and hashes in structured sidecars/result storage.
- The PNG renderer must define and test argv serialization, stdout/stderr ordering, delimiters, encoding, line endings, and binary-output handling; do not reconstruct or invent output.

## Testing and verification

- Run the project build, lint/type-check/schema checks when available, then unit tests, backend integration tests, and Playwright MCP browser tests for every relevant change. GUI coverage must include target entry, assessment creation, live progress, results, evidence previews, and CSV/ZIP downloads.
- For assessment changes, run the complete controlled-fixture matrix for all 40 testcases, including every declared positive, negative, applicability, and incomplete/error path, and produce a registry-to-fixture-to-result-to-export coverage manifest.
- Test installation and dependency diagnostics, Ollama connectivity/model/error handling, resource limits and cleanup, cancellation, and recovery from worker/Ollama/evidence interruptions on Kali Linux WSL when available.
- Inspect downloaded CSV/ZIP files and PNG contents, not just the UI notification. Confirm canonical CSV formatting, deterministic ZIP paths/manifests, artifact hashes, provenance, path layout, result consistency, and no cross-assessment leakage or mutation.
- Missing or malformed required export evidence must fail closed, clean partial output, and never synthesize or reclassify results; reject archive traversal, absolute paths, symlinks, and unsafe entries.
- Reproduce and fix deterministic failures, then rerun the failing test and affected regressions. If an environment gate cannot run, label it blocked/unverified and do not claim the feature works.
