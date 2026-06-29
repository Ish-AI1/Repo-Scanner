#!/usr/bin/env python3
"""
run_eval.py — measures the injection-detector layer (promptguard) against a
ground-truth corpus. THE gate for any detector/rule change: run before and
after, compare false-positive and false-negative counts.

What it measures (automatable): which files produce PENALTY-ELIGIBLE findings
(likely_false_positive == false), compared to hand-labeled expectations in
manifest.json. Legit repos expect zero — every genuine finding there is a FP.
Fixtures with planted injections expect specific files — a miss is a FN.

What it does NOT measure: the LLM-side findings extraction (static phases)
and scoring. Those are covered by tests/run_tests.py + pytest.

Usage:
  python evals/run_eval.py             # fixtures only (offline, fast)
  python evals/run_eval.py --live      # + clone/scan live repos (network)

Live repos are cloned shallow, hooks disabled, into evals/corpus/ (gitignored)
and reused on later runs.
"""
import json
import os
import re
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EVALS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(EVALS_DIR)
CORPUS_DIR = os.path.join(EVALS_DIR, "corpus")
PROMPTGUARD = os.path.join(SKILL_DIR, "scripts", "promptguard.py")

# Mirror the skill's default-mode selection (SKILL.md Phase 7): docs +
# agent-config + hooks — NOT just README/SKILL. Kept in sync so the eval gate
# actually exercises every file type the live audit scans (a payload hidden in
# .mcp.json or hooks/ must be testable).
DOC_FILE_RE = re.compile(
    r'^(readme.*\.md|skill\.md|claude\.md|agents\.md|.*\.instructions\.md|'
    r'\.mcp\.json|.*\.mcp\.json)$', re.IGNORECASE)


def default_file_selection(root):
    """Docs + agent-config + hooks: README*/SKILL/CLAUDE/AGENTS, *.instructions.md,
    .mcp.json / *.mcp.json, and any file under a hooks/ directory (any depth)."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build'}]
        in_hooks = 'hooks' in os.path.normpath(dirpath).split(os.sep)
        for f in filenames:
            if DOC_FILE_RE.match(f) or in_hooks:
                out.append(os.path.join(dirpath, f))
    return out


def ensure_live_clone(case):
    dest = os.path.join(CORPUS_DIR, case["id"])
    if os.path.isdir(os.path.join(dest, ".git")):
        return dest
    os.makedirs(CORPUS_DIR, exist_ok=True)
    print(f"  cloning {case['url']} ...")
    env = dict(os.environ,
               GIT_CONFIG_COUNT="1",
               GIT_CONFIG_KEY_0="core.hooksPath",
               GIT_CONFIG_VALUE_0=os.devnull)
    r = subprocess.run(
        ["git", "clone", "--no-checkout", "--depth", "1", case["url"], dest],
        capture_output=True, text=True, encoding="utf-8", env=env)
    if r.returncode != 0:
        raise RuntimeError(f"clone failed: {r.stderr.strip()[-200:]}")
    r = subprocess.run(["git", "-C", dest, "-c", f"core.hooksPath={os.devnull}", "checkout"],
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(f"checkout failed: {r.stderr.strip()[-200:]}")
    return dest


def scan(files):
    listing = "\n".join(files) + "\n"
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    r = subprocess.run(
        [sys.executable, PROMPTGUARD, "--stdin-list"],
        input=listing, capture_output=True, text=True, encoding="utf-8", env=env)
    if r.returncode != 0:
        raise RuntimeError(f"promptguard failed: {r.stderr.strip()[-300:]}")
    return json.loads(r.stdout)


def main():
    live = "--live" in sys.argv
    with open(os.path.join(EVALS_DIR, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)

    total_fp = total_fn = 0
    review_miss = 0          # review_expected case with no review_flag = hard fail
    results = []

    for case in manifest["cases"]:
        if case["kind"] == "live" and not live:
            continue
        try:
            root = (os.path.join(SKILL_DIR, case["path"]) if case["kind"] == "fixture"
                    else ensure_live_clone(case))
            files = default_file_selection(root)
            out = scan(files) if files else {"findings": [], "review_flags": [], "stats": {}}
        except Exception as e:
            results.append((case["id"], None, None, f"ERROR {e}", 0, None))
            total_fn += 1  # an errored case is a failure, count conservatively
            continue

        genuine = {os.path.basename(f["file"]) for f in out["findings"]
                   if not f["likely_false_positive"]}
        expected = set(case["ml_genuine_files"])
        fps = genuine - expected
        fns = expected - genuine
        total_fp += len(fps)
        total_fn += len(fns)

        # Embedding review layer (v4.1): recall check + noise report.
        # review_flags are CANDIDATES the orchestrator (Claude) adjudicates; they
        # never affect the score. So raw flags on legit repos are NOT a failure
        # (Claude clears them) — we only HARD-FAIL when a case labeled
        # review_expected produces ZERO flags (a recall miss).
        rflags = out.get("review_flags", [])
        rmiss = None
        if case.get("review_expected"):
            if not rflags:
                review_miss += 1
                rmiss = "RECALL MISS (no review_flag)"
        results.append((case["id"], sorted(fps), sorted(fns), None, len(rflags), rmiss))

    print("=" * 64)
    print("repo-scanner detector eval (promptguard layer)")
    print("=" * 64)
    for cid, fps, fns, err, rflag_n, rmiss in results:
        if err:
            print(f"  ✗ {cid}: {err}"); continue
        note = f"  [review_flags: {rflag_n}]" if rflag_n else ""
        if not fps and not fns and not rmiss:
            print(f"  ✓ {cid}{note}")
        else:
            if fps:   print(f"  ✗ {cid}: FALSE POSITIVES: {fps}")
            if fns:   print(f"  ✗ {cid}: MISSED INJECTIONS: {fns}")
            if rmiss: print(f"  ✗ {cid}: {rmiss}")
    print("=" * 64)
    print(f"  cases: {len(results)}   penalty FP: {total_fp}   penalty missed: {total_fn}   review recall-miss: {review_miss}")
    print("  (raw review_flags are Claude-adjudicated candidates — not scored, not a failure)")
    print("=" * 64)
    sys.exit(0 if (total_fp == 0 and total_fn == 0 and review_miss == 0) else 1)


if __name__ == "__main__":
    main()
