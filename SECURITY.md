# Security policy

ScopeGuard VAPT is intended for authorized network security assessments only. Operators are responsible for authorization, scope, rate limits, and applicable law.

## Reporting a vulnerability

Do not open a public issue containing exploit details, target data, credentials, scan output, or POC images. For this private beta, contact the repository owner through the private GitHub security channel or another pre-arranged private channel. Include a minimal reproduction using a local fixture when possible.

## Design boundaries

- The control plane binds to 127.0.0.1 by default.
- User targets and LLM output are never passed to an unrestricted shell.
- Scanner commands use allowlisted argv adapters and bounded timeouts.
- Scope authorization is persisted and target expansion is bounded.
- Deterministic backend rules control classifications.
- Ollama receives validated evidence only and cannot execute commands or override findings.
- Failed, timed out, filtered, or incomplete checks remain INCONCLUSIVE.
- Destructive exploitation, brute force, password spraying, DDoS/amplification traffic, persistence, file modification, and unauthorized lateral movement are out of scope.

Please report suspected scope bypass, evidence fabrication, unsafe command execution, secret leakage, archive traversal, or classification integrity defects privately.
