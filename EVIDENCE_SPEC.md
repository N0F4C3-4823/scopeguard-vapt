# Evidence and export specification

## Command/output contract

Every command execution records its argv array, a lossless `shlex.join(argv)` display string, working directory, start/end timestamps, exit code, timeout state, tool version, exact stdout/stderr bytes, and SHA-256 hashes. POC PNG pages render only:

```text
<recorded displayed command>

<stdout bytes decoded as UTF-8 with replacement, then stderr bytes decoded the same way>
```

The PNG has no title, status, severity, timestamp, branding, metadata, or generated commentary. The raw streams and provenance remain in sidecar files. Long output is paginated without truncation; binary output is retained as raw evidence and does not get invented into display text.

## Result storage

Each target/testcase directory always contains `POCs/FOUND/` and `POCs/NOT_FOUND/`. Only a valid `FOUND` or conclusive `NOT_FOUND` condition creates a condition-named folder and PNG. `NA` and `INCONCLUSIVE` are represented in `result.json` and have no misleading POC.

## Assessment profiles

The four supported assessment types are stored in the authorization manifest. Applicability is not inferred from the profile name alone: internal vantage, credentials, layer-2 access, wireless hardware/proximity, approved egress vantage, asset inventory, explicit permissions, and host/tool availability are evaluated per condition. A genuinely inapplicable condition is `NA` with a precise reason. A condition that is applicable but blocked by a temporary capability or execution failure is `INCONCLUSIVE`.

## Export contract

`testcase_results.csv` has one row for each normalized target and each of the 40 IDs. CSV uses the canonical header and UTF-8 newline rules from `app/exporter.py`. ZIP entries are deterministic, relative to the assessment root, and are rejected if they are absolute, traverse parents, or are symlinks. Required evidence missing or malformed causes a fail-closed export with no partial final archive.
