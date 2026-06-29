# Changelog — Repo Scanner

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
