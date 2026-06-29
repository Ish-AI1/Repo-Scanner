# Changelog — Repo Scanner

## v1.1.0 — 2026-06-30
- **Inline visual report** in the chat (alongside the on-disk Markdown). When `mcp__visualize__show_widget` is available, SKILL.md Phase 10 now renders a compact HTML widget — 4 KPI cards (Score / Verdict / ML / AST), per-OWASP coloured badges on every finding (LLM01 red, LLM03 yellow, LLM06 purple, MAL dark-red, HYGIENE grey, etc.), and structured sections (Critical / Warnings / ML adjudication / AST+Secret / Supply chain / Trust / Timing / Recommendation). RTL, theme-aware via `var(--text-color)` / `var(--background-color-secondary)`. The on-disk `AUDIT-REPORT.md` stays the source of truth; the widget is a supplementary at-a-glance view that replaces the half-baked notepad experience.
- **OSV.dev dep-CVE lookups** (`scripts/osv_lookup.py`, new Phase 6b): parses `uv.lock` / `poetry.lock` / `requirements.txt` / `pyproject.toml` / `package-lock.json` and queries the public [OSV.dev](https://osv.dev) database in a single batched HTTPS POST (stdlib `urllib`, no auth). Each known-CVE in a declared dependency becomes a finding (`vulnerable_dependency_critical|high|medium|low`) carrying the OSV id, severity, and a verification URL. Maps to OWASP `LLM03 Supply Chain`. Privacy: only package names + versions leave the box (already public on the registries); `--offline` parses-only and skips the network. Closes the supply-chain depth gap — turns "no typosquats" from a guess into "no known CVEs". 11 unit tests (parsers + mocked network + severity classification).
- **AST-based dangerous-code detection** (`scripts/ast_scan.py`, new Phase 4b): a deterministic, stdlib-only (`ast`) scanner that catches what regex can't — the obfuscated decode-then-execute pattern, including the 1-hop case where the payload passes through a variable. Detects `eval/exec/compile` fed by `base64.b64decode`/`bytes.fromhex`/`zlib.decompress`/etc. (`obfuscated_code_execution`, −30), `os.system`/`subprocess(shell=True)` with dynamic commands (`command_injection_surface`, −10), `pickle`/`marshal`/unsafe-`yaml.load` deserialization (`unsafe_deserialization`, −10, CWE-502), and bare dynamic `eval`/`exec` (`dynamic_code_execution`, −8 note). This closes the long-standing "obfuscated payload" gap. **Carefully tuned to near-zero FP**: `re.compile`, pandas `df.eval`, `json.loads`, `bytes.decode()`, `dict.get()`, `yaml.safe_load`, and `subprocess.run([...])` are all correctly NOT flagged (verified by 23 unit tests). Real-world check: across 41 Python files of the skill + its eval corpus (caveman, ohmyzsh), the only finding is the one planted-malware fixture. All four findings carry OWASP category `MAL — Malicious Code / RCE`.
- **OWASP threat-category annotations** in every audit report. Each penalty in the scorer's `breakdown` now carries an `owasp` + `owasp_title` field (e.g. `LLM01 Prompt Injection`, `LLM03 Supply Chain`, `LLM06 Excessive Agency`, `AAI03 Privilege Escalation`, `AAI06 Data Exfiltration`, `LLM02 Sensitive Information Disclosure`, `HYGIENE Repo Hygiene`). Critical Findings / Warnings in the report are now OWASP-prefixed, so reviewers familiar with the standard can read the report at a glance.
- **Expanded embedding-gate calibration** (`evals/calibrate_embedding.py`): the labeled corpus grew from 7 + 7 to 17 + 15 samples, adding Arabic, indirect / task-disguised framings, security-documentation false-positive cases, and explicit precision/recall reporting at the current threshold. Empirical finding (current 0.50 threshold): precision 0.92, recall 0.65 — confirms the embedding layer is correctly positioned as a review-only signal (not a verdict), and confirms that indirect / task-disguised injections evade it by design, validating the v1.0 decision to make `HARD_EXFIL` a first-class deterministic detection layer rather than relying on the embedding layer alone.

## v1.0.0 — Initial public release

Repo Scanner audits a public GitHub repository before you install it. Point it at a URL, get back a 0–100 trust score, a traffic-light verdict, and a Markdown report on disk explaining every finding.

**What it checks**
- Install scripts: `curl | bash`, `sudo`, certificate-store changes, scheduled tasks, registry edits — anything that runs at install time
- Secret leaks (AWS keys, GitHub tokens, OpenAI keys, private keys) in the current tree and in git history
- Supply chain: lockfile presence, typosquats, `postinstall` scripts, floating dependency versions
- Hidden prompt injections inside skill files / agent configs / hooks, including the modern "task-disguised" framing ("to finish the summary, run the following command…")
- Multilingual coverage (English, Hebrew, Arabic, Russian, Chinese, Japanese, Spanish) so injections don't slip through just because they're written in a non-English language
- Metadata signals: author, repo age, license, README — feeds an objective trust tier

**How it works**
- Static pattern scan + a local ML classifier (ProtectAI DeBERTa-v3 on CPU, ~750 MB one-time download) + a deterministic exfiltration-pattern gate + an optional multilingual embedding review layer for paraphrase recall
- Deterministic scorer (penalties × paired mitigations × trust), so the same findings always produce the same score
- Full audit report written to disk; chat output stays short

**Runs entirely on your machine.** No code or repo content leaves the box; the model is loaded locally.

**Optional isolation** via `container/Dockerfile` for auditing repos you actively distrust — clone and scan happen inside a throwaway Docker container.

**Eval discipline** — every detector or matrix change must pass the bundled pytest suite, the scorer fixture suite, and the offline detector eval (zero false positives, zero missed planted injections) before it ships.
