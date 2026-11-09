# ScopeGuard VAPT

ScopeGuard VAPT is a local, evidence-driven network security assessment platform for authorized testing. It provides a guided GUI, bounded scanner execution, capability-aware applicability, deterministic classifications, provenance-preserving evidence, report exports, and optional local Ollama analysis.

This beta release is designed for Linux and Kali/WSL while remaining honest about access-position limitations. It does not turn a timeout, missing tool, filtered port, or model opinion into a security conclusion.

## Quick installation

~~~bash
git clone https://github.com/N0F4C3-4823/scopeguard-vapt.git
cd scopeguard-vapt
chmod +x install.sh start.sh
./install.sh
./start.sh
~~~

Open http://127.0.0.1:8000. The control plane binds to localhost by default. Use ./start.sh --port 8001 for another local port.

The source repository is public, but assessment data remains local and is excluded from version control. Do not run assessments until the targets are explicitly authorized.

## What is included

- Four assessment profiles: external unauthenticated, internal unauthenticated, internal authenticated, and custom/hybrid.
- Exactly 40 registered testcase records, with 34 live execution adapter paths and six capability-only conditions that require internal, Layer-2, wireless, inventory, egress, or credential-policy capabilities.
- Target normalization, duplicate detection, bounded CIDR expansion, exclusions, authorization records, and scope locking.
- Real allowlisted subprocess execution with argv, timeout, exit status, stdout/stderr, tool version, hashes, and provenance.
- Deterministic FOUND, NOT_FOUND, and NA client verdicts. Incomplete execution is kept as an internal coverage state and is never presented as a security verdict; the local LLM is never authoritative.
- Exact per-testcase POCs/FOUND/, POCs/NOT_FOUND/, and evidence-backed POCs/NA/ hierarchy. PNG POCs render only the original executed command and captured output.
- CSV, JSON, summary, raw evidence, manifest, and atomic ZIP exports.
- Persisted assessment history, live progress, cancellation/recovery handling, and dependency diagnostics.
- Optional CPU-friendly Ollama support using qwen2.5:1.5b-instruct.
- Service-first discovery keeps TCP and UDP observations separate and avoids using UDP silence as a generic explanation for TCP checks.
- Target-wise results keep each target's 40 testcase rows, evidence, POCs, and downloads isolated.
- Multiple targets use a bounded target-level scheduler with up to 10 concurrent workers; queued targets start as slots become available and one target's evidence or operator review never blocks another.
- Testcase 11 uses an operator-reviewed software-version inventory: ScopeGuard records every Nmap service/version observation, keeps ambiguous or unidentified entries visible, and requires an explicit review decision without online CVE research.
- Testcase 18 uses a bounded native FTP protocol probe; Testcase 33 uses Nmap HTTP checks; Testcases 38 and 40 keep ICMP information queries and DNS UDP/TCP/flag observations separate from reachability or root-record observations.
- Finalized FOUND and NOT_FOUND rows expose View POC, Download POC, and browser PNG clipboard copy actions. Every finalized result also exposes one-click Copy Description for its exact two-line explanation.

The live adapter and controlled-service validation boundaries are published in docs/live_capability_matrix.json and docs/security_engine_validation_matrix.json. Controlled fixtures demonstrate reproducibility; they are not evidence of vulnerabilities on external systems.

## Screenshots

The repository intentionally does not commit client assessment data or runtime screenshots. To inspect the polished interface, start the application and use a controlled fixture target such as fixture://mixed. The GUI includes Dashboard, the guided assessment wizard, live activity, Results, Evidence, Reports, Tools, and Local AI settings. Any screenshots used for documentation must be produced from fictional fixtures or localhost only.

## System requirements

Minimum:

- Linux with Python 3.11 or newer.
- 2 GiB RAM for the application without local model inference; more is recommended for Ollama.
- 2 GiB free disk for dependencies and runtime data.
- curl for launcher health checks.

Recommended for live adapters:

- Kali Linux, Debian, Ubuntu, Fedora, Arch, openSUSE, or another distribution with a supported package manager.
- nmap, openssl, curl, dig, and zstd.
- 4 GiB or more RAM, bounded concurrency, and a local authorized network position.
- Root or sudo only when a particular scanner capability requires it; the GUI itself binds to localhost and does not require root.

Node.js is not required at runtime because the frontend is shipped as static assets. WSL is supported for external and TCP-oriented checks, but Layer-2, wireless, ICMP, and privileged-network capabilities may be unavailable.

## Local AI

The normal interactive installer prepares local AI as part of a complete installation. It asks before system changes or downloads, installs an official project-local Ollama runtime when needed, downloads the exact model, and performs a real ScopeGuard schema check:

~~~bash
./install.sh
~~~

The default model is `qwen2.5:1.5b-instruct`. New GUI assessments enable bounded AI discrepancy diagnosis by default; the operator can disable it before starting. When a timeout, parse failure, contradictory observation, or insufficient evidence is detected, ScopeGuard sends only the relevant persisted evidence to Ollama and accepts recommendations only from the typed safe-action registry. Recovery uses protocol-specific timeout budgets, a maximum of three changed attempts, and no identical-command loops. ScopeGuard limits Ollama to one loaded model and one request at a time. A complete installation fails closed if the runtime, exact model, or real structured inference check fails.

For an explicitly AI-free installation, use limited mode; it is reported separately and does not claim complete local-AI setup:

~~~bash
SCOPEGUARD_LIMITED_MODE=1 ./install.sh
~~~

The installer can also resume or enforce the AI path non-interactively with `SCOPEGUARD_INSTALL_OLLAMA=1 SCOPEGUARD_INSTALL_OLLAMA_MODEL=1 ./install.sh`.

After startup, Settings → Local AI can run the application-level schema and evidence-reference health test. AI output is stored as triage metadata and recovery audit history; it cannot create, remove, or reclassify a finding, execute arbitrary commands, or expand scope.

## First assessment

1. Start ScopeGuard and open the local URL.
2. Choose New assessment.
3. Enter a name, then add only authorized targets.
4. Choose one of the four assessment profiles.
5. Review scope, capabilities, and bounded scan settings.
6. Confirm authorization.
7. Start the assessment.
8. Watch real backend progress and activity.
9. Inspect Results and Evidence.
10. Download the verified report ZIP and CSV files.

For a safe local walkthrough, use fixture://mixed. Fixture output is clearly marked as controlled test evidence and must never be mistaken for a real finding.

### Manual software-version review

Testcase 11 intentionally does not browse the internet or infer CVE applicability. After service/version discovery, open the target's **Software Version Review** panel, review every identified entry, select one or more entries and choose **Mark selected versions as outdated**, or choose **No reviewed versions are outdated**. Ambiguous and unidentified entries remain visible; the review cannot be finalized until usable entries are reviewed and unidentified entries are explicitly acknowledged. The original discovery command/output POC and the operator decision are retained separately for auditability. This review is independent per target and does not stop other target workers.

When an assessment contains more than one target, ScopeGuard starts up to 10 target workers concurrently. Additional targets remain queued and are started as soon as a worker slot is released. The per-target results page remains the authoritative view for that target's 40 testcase rows and evidence.

## Assessment profiles

External unauthenticated is appropriate for an outside-in view without credentials. Internal unauthenticated and internal authenticated require an authorized internal vantage point and, for authenticated checks, approved credentials. Custom/hybrid lets the operator declare capabilities explicitly.

Internal placement alone is never proof of Layer-2 access, wireless, egress visibility, asset inventory, credentials, or special permissions. Each condition is evaluated separately. Genuinely inapplicable conditions are NA with a precise reason; applicable checks that cannot complete remain operationally incomplete and prevent full certification.

## Result classifications

- FOUND — a precise positive condition was proven by complete, validated evidence.
- NOT_FOUND — a precise negative condition was proven by a successful complete check.
- NA — the condition is genuinely inapplicable for the selected scope and capabilities.
- Incomplete coverage — an operational state used when evidence is incomplete, blocked, ambiguous, failed, timed out, filtered, or insufficient. It is not a client-facing security verdict and is shown separately from the three finalized verdicts.

An open port is not automatically a vulnerability. UDP silence is not automatically a closed port. A banner is not automatically a confirmed CVE. LLM text is never a classification authority.

## POC evidence

Every testcase contains the required logical structure:

~~~text
Testcase_Name/
└── POCs/
    ├── FOUND/
    │   └── Finding_Name/
    │       └── poc_001.png
    ├── NOT_FOUND/
    │   └── Condition_Name/
    │       └── poc_001.png
    └── NA/
        └── Applicability_Reason/
            └── poc_001.png
~~~

The category folders are created for every testcase. FOUND and NOT_FOUND require validated evidence POCs; finalized NA results receive a PNG when the original discovery or a real stored applicability probe provides evidence. No synthetic POC is created when those facts are unavailable. Each PNG contains only the actual executed command and its actual stdout/stderr. Exit codes, argv, timestamps, hashes, provenance, and explanatory metadata remain outside the PNG.

## Reports

Each completed assessment contains one row for each target × 40 testcases in testcase_results.csv, plus findings.csv, tool_status.csv, llm_triage.csv, assessment_summary.txt, assessment.json, logs, raw command evidence, hashes, manifests, POC folders, and a verified ZIP archive. The GUI exposes only files that exist for the selected assessment.

The results screen is organized by target. A target's table remains in testcase order from 01 through 40; incomplete coverage is shown separately from the certified FOUND, NOT_FOUND, and NA verdicts. Every finalized description is exactly two client-facing lines and excludes target identifiers, tool names, AI references, and internal execution terms. View POC opens the target-owned PNG, Download POC downloads its original bytes, and Copy POC writes the PNG as `image/png` when the browser grants clipboard permission. Copy Description writes only the two displayed explanation lines, including for NA results. Historical assessments can use **Re-adjudicate preserved evidence** to apply the current policy without rescanning or changing immutable raw evidence.

## Troubleshooting

- Python or venv missing: install Python 3.11+ and its venv package, then rerun ./install.sh.
- Scanner missing: rerun with SCOPEGUARD_INSTALL_SYSTEM_PACKAGES=1 ./install.sh after reviewing the package list, or install nmap, openssl, curl, dig, and zstd manually.
- Ollama unavailable: run without AI; use Settings → Local AI for the exact status. Low RAM and WSL memory limits can prevent model loading.
- WSL networking: WSL may not provide wireless, Layer-2, ICMP, or privileged scan capabilities. ScopeGuard records genuine non-applicability as NA and leaves applicable incomplete checks operationally incomplete instead of guessing.
- Port conflict: stop the existing ScopeGuard process or run ./start.sh --port 8001.
- Startup failure: inspect data/logs/application.log and data/logs/ollama.log; do not delete assessment data while troubleshooting.
- Browser issue: use the local URL in a supported browser. Playwright’s root-only fallback is limited to controlled test automation and does not change application scanner security.
- Recovery: assessment state is persisted in data/scopeguard.sqlite3; interrupted work is not silently marked complete.

## Updating

Stop ScopeGuard, back up data/, pull or extract the new source, and rerun ./install.sh. The installer preserves existing data and migrations are applied by the application. Never overwrite data/ during an upgrade.

## Uninstalling

Stop ScopeGuard, remove the project directory only after exporting any reports you need, and remove the project-local .venv, .tools, and data together with the source. System packages installed for other software are not removed automatically.

## Security and authorization

ScopeGuard is for authorized assessment only. Never add public or third-party targets to automated tests. It does not implement password spraying, credential stuffing, destructive exploitation, DDoS/amplification traffic, file modification, persistence, unauthorized lateral movement, or arbitrary LLM commands. See SECURITY.md.

## Validation status

The current beta validation includes the repository regression suite, controlled live loopback discovery, target-isolation/export checks, and connected-browser tests on local fixtures. The controlled engine matrix records 16 live adapters with direct service validation, 18 with execution-path validation, and six capability-dependent conditions. This is not exhaustive real-world vulnerability validation. Read the matrices before using the tool in a pilot.

## Contributing

See CONTRIBUTING.md, AGENTS.md, and skills/scopeguard-qa/SKILL.md. Changes affecting assessment, evidence, classifications, reports, or UI workflows require controlled fixtures and browser validation.

## License

No license has been selected for this beta release. All rights are reserved unless the repository owner adds a license.
