# Contributing to ScopeGuard VAPT

ScopeGuard is security-sensitive software. Keep changes small, evidence-driven, and reviewable.

Before changing behavior:

1. Read AGENTS.md and skills/scopeguard-qa/SKILL.md.
2. Inspect the registry, applicability engine, classifier, evidence model, and export code.
3. Use controlled local fixtures only.
4. Preserve original command output and deterministic status semantics.

Before opening a change:

~~~bash
.venv/bin/ruff check app tests
node --check static/app.js
.venv/bin/pytest -q
~~~

For UI changes, run the application and the explicit Playwright suite. For assessment or evidence changes, run the full 40-testcase fixture matrix, inspect PNGs and ZIP contents, and update the capability and validation matrices when coverage changes.

Do not add real customer targets, scan results, credentials, model weights, runtime databases, or generated POCs to commits. Do not weaken tests to make a result pass. Use INCONCLUSIVE when evidence cannot establish a conclusion.

Pull requests should explain security impact, migration impact, tests run, controlled fixtures used, and known limitations. There is currently no selected open-source license for this private beta.
