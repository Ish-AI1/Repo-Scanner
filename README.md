<div align="center">

# 🛡️ Repo Scanner

**Check whether a GitHub repo is safe — before you install it.**

A skill for [Claude Code](https://www.anthropic.com/claude-code) that reads a repository the way a careful security engineer would, and gives you a clear traffic-light answer.

🟢 safe · 🟡 install with care · 🔴 don't

[עברית](README.he.md) · [What it checks](#what-it-checks) · [Install](#install-step-by-step) · [FAQ](#faq) · [Limitations](#known-limitations)

</div>

---

## Why this exists

Installing a repo — a CLI tool, a Claude Code skill, a script — runs someone else's code on your machine. Most of the time it's fine. Occasionally it isn't: a hidden `curl … | bash`, a leaked API key, a skill file quietly telling your AI assistant to read your SSH keys.

Reading every line yourself is slow and easy to get wrong. **Repo Scanner does the first pass for you in about two minutes** and hands you a plain report you can act on. It never installs anything without your explicit go-ahead.

## What it checks

| Layer | What it looks for |
|-------|-------------------|
| 🧷 **Install scripts** | `curl … \| bash`, `sudo`, certificate/registry changes, scheduled tasks, anything that runs at install time |
| 🔑 **Secrets** | API keys, tokens, private keys — in the current files and in git history |
| 📦 **Supply chain** | Missing lockfiles, typosquatted dependencies, sneaky `postinstall` scripts |
| 🧠 **Prompt injection** | Hidden instructions in skill/config files that try to hijack an AI agent — a local AI model + a deterministic multilingual rule layer + an optional cross-lingual review net |
| 🌐 **Where it phones home** | Every URL the code talks to, expected vs. suspicious |
| 👥 **Reputation** | Stars, contributors, age — weighed as a bounded tiebreaker, never a free pass |

It produces a 0–100 score and writes a full report to disk.

## What a result looks like

```
🟢 92/100 — some-cool-tool
• Installer uses an official vendor curl|bash (get.docker.com) — no signature (−15)
• Sandbox disabled for contributors only (−10)
• 0 confirmed injections across 61 files (2 CJK files reviewed via the multilingual layer)
• Reputation: established project (+5)
Full report: ~/…/AUDIT-REPORT.md
```

## Install (step by step)

### Step 0 — Prerequisites
- **Git** — to clone repos. ([git-scm.com](https://git-scm.com/downloads))
- **Python 3.10 or newer** — for the local AI scanner. The installer checks this and tells you the exact command if it's missing (`winget install Python.Python.3.12` on Windows, `brew install python` on macOS, `apt install python3 python3-venv` on Debian/Ubuntu).
- **~1 GB free disk** — for the AI model + dependencies, downloaded once.
- **Claude Code** — this is a Claude Code *skill*; you run it from inside Claude Code.

> You don't install Python yourself beyond having it present — the installer builds the isolated environment, installs the dependencies, and downloads the model for you.

### Step 1 — Get the code
**macOS / Linux**
```bash
git clone https://github.com/Ish-AI1/Repo-Scanner.git
cd Repo-Scanner
```
**Windows (PowerShell)**
```powershell
git clone https://github.com/Ish-AI1/Repo-Scanner.git
cd Repo-Scanner
```

### Step 2 — (optional) Verify the installer hasn't been tampered with
```bash
# macOS/Linux
sha256sum install.sh
# Windows
Get-FileHash install.ps1 -Algorithm SHA256
```
Compare against the published hashes in [Integrity](#integrity-verify-the-installer) below.

### Step 3 — Run the installer
**macOS / Linux**
```bash
chmod +x install.sh
./install.sh
```
**Windows (PowerShell)**
```powershell
.\install.ps1
```
What it does, live, in front of you:
1. copies the skill into `~/.claude/skills/`
2. finds your Python and creates an isolated environment (it picks the right spot for your machine — no hardcoded paths)
3. installs the dependencies
4. **asks for your consent**, then downloads the AI model (~1 GB)
5. records the environment path so the skill finds it automatically
6. runs a built-in self-test (you should see `8 passed, 0 failed`)

> **Just want the skill without the AI layer?** `./install.sh --skill-only` (or `.\install.ps1 -SkillOnly`). You can still audit with `/repo-scanner <url> --quick`.

### Step 4 — Reload and use
In Claude Code:
```
/reload-skills
/repo-scanner https://github.com/owner/repo
```

### (Optional) Step 5 — Add the multilingual review layer
This adds a second, language-agnostic model (~120 MB, Apache-2.0, no account needed) that surfaces *paraphrased* or *non-English* injection attempts for review. Skip it if you only audit English repos.
```bash
# use the python the installer created (printed at the end of install, and in
# ~/.claude/skills/repo-scanner/.venv-path)
<venv-python> -m pip install sentence-transformers
<venv-python> -c "from sentence_transformers import SentenceTransformer as S; S('sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2'); print('ready')"
```
The skill detects it automatically. Without it, the deterministic multilingual rule layer still runs.

## Integrity (verify the installer)

These are the SHA256 hashes of the installer scripts in this repo (line endings pinned to LF via `.gitattributes`, so the hash is identical on every OS):

| File | SHA256 |
|------|--------|
| `install.sh` | `16b3577b94f7dda85f028a6483872cc8ef09ec9ff10c9afac76be5a30169771e` |
| `install.ps1` | `77b9928701da42845f8c555ad94262a89dc877ddcdf0bbe2068682d59f48d36c` |

If your computed hash doesn't match, **do not run the script** — re-clone or open an issue.

## How it scores

Two axes, kept separate on purpose:
- **Capability risk** — what the repo's install mechanics *can do* to your machine.
- **Trust** — provenance: who maintains it, for how long, under how many eyes (a bounded +5/+10 nudge, capped, and **ignored entirely when there's hard evidence of malice** — popularity never rescues a backdoor: `xz`, `event-stream`).

| Verdict | Score | Meaning |
|---------|-------|---------|
| 🟢 GREEN | 70–100 | Safe to install |
| 🟡 YELLOW | 55–69 | Install with care — read the findings |
| 🔴 RED | 0–54 | Don't install |

The score is computed by code (`scorer.py`), not guessed — the same findings always produce the same number.

## Your privacy

The AI models run **entirely on your own CPU**. Nothing about the repos you scan leaves your machine. The models are open-source, downloaded once from Hugging Face, then cached. You can go fully offline after the first download (`TRANSFORMERS_OFFLINE=1`).

## FAQ

**Do I need to know Python?** No. You need Python *present*; the installer does the rest.

**Nothing happens / "command not recognized" when I paste a link.** Claude Code doesn't auto-install from a URL. You install once with `git clone` + `./install.sh`, then run `/repo-scanner <url>` inside Claude Code.

**It said "Done" but the scan says the ML scanner is unavailable.** You likely chose "no" at the model-download prompt, or ran `--skill-only`. Re-run `./install.sh` and accept the download, or use `--quick`.

**How big is the download, really?** ~1 GB once (PyTorch CPU + the injection model). Cached forever after. The optional multilingual layer adds ~120 MB.

**Can I run it without the internet?** After the first model download, yes — set `TRANSFORMERS_OFFLINE=1`. The clone step still needs network.

**Does it change my system?** Only: copies the skill into `~/.claude/skills/`, and creates one Python environment under your user folder. No admin/root, no system PATH changes. Uninstall = delete those two folders.

**Why did a popular repo still get dinged?** Reputation is a small bonus, not a pass. Real risks (unsigned `curl|bash`, disabled sandbox) outweigh it by design.

**How do I update?** `git pull` in the repo, then re-run the installer; `/reload-skills` in Claude Code.

**Is my scan private?** Yes — fully local CPU inference, see [Privacy](#your-privacy).

## Known limitations

Honest about what it does *not* do:
- **Static analysis only.** It reads code; it does not run it. A repo that's benign at install time but malicious at runtime can evade static checks.
- **Default scans docs + agent-config + hooks.** Use `--deep` to scan every file. Determined obfuscation (encoded/binary payloads) can still evade text scanning.
- **The multilingual ML review layer is a recall net, not a verdict.** It surfaces candidates for Claude to judge; it never moves the score on its own. Non-English coverage is best-effort.
- **Shallow clone by default** (`--depth 50`). Commits — *and the secret-leak history scan* — beyond that depth aren't covered; a credential committed and removed long ago can be missed.
- It's a **second opinion**, not a guarantee. For high-stakes installs, still read the code.

## License & author

MIT. Built by **Ish-AI** — see [ABOUT](ABOUT.md).
