#!/usr/bin/env bash
# install.sh — repo-scanner installer for macOS / Linux.
#
# This actually sets things up — it is NOT just a file copy:
#   1. Copies the skill into ~/.claude/skills/
#   2. Finds Python (>=3.10), creates a dedicated venv
#   3. Installs the ML dependencies (PyTorch CPU + transformers)
#   4. Downloads the injection-detection model (~750MB) — ONLY after you say yes
#   5. Records the venv path so the skill finds it on any machine
#   6. Runs the built-in self-test
#
# Usage:   ./install.sh             (full setup)
#          ./install.sh --skill-only (copy the skill, skip the ML setup)
#
# No sudo needed. Re-running is safe (idempotent).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_TARGET="${HOME}/.claude/skills"
SKILL_DEST="${SKILLS_TARGET}/repo-scanner"
VENV_DIR="${HOME}/.venv-repo-scanner"
VENV_PY="${VENV_DIR}/bin/python"
SKILL_ONLY=false
[ "${1:-}" = "--skill-only" ] && SKILL_ONLY=true

echo ""
echo "=== repo-scanner installer (macOS/Linux) ==="
echo ""

# --- 1. Copy the skill -------------------------------------------------------
mkdir -p "$SKILLS_TARGET"
for d in "$REPO_DIR/skills"/*/; do
  [ -d "$d" ] || continue
  name="$(basename "$d")"
  rm -rf "${SKILLS_TARGET:?}/$name"
  cp -R "$d" "$SKILLS_TARGET/$name"
  echo "  installed skill: $name"
done

if [ "$SKILL_ONLY" = true ]; then
  echo ""
  echo "Skill copied. ML scanner NOT set up (--skill-only)."
  echo "Run /repo-scanner <url> --quick for static-only audits."
  echo "In Claude Code: /reload-skills"
  exit 0
fi

# --- 2. Find Python ----------------------------------------------------------
echo ""
echo "Looking for Python (>=3.10)..."
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    v="$("$cand" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "")"
    maj="${v%%.*}"; min="${v##*.}"
    if [ -n "$v" ] && [ "$maj" -ge 3 ] && [ "$min" -ge 10 ]; then
      PY="$cand"; echo "  found Python $v ($cand)"; break
    fi
  fi
done
if [ -z "$PY" ]; then
  echo "  Python >=3.10 not found. Install it, then re-run:"
  echo "    macOS:  brew install python@3.12"
  echo "    Debian/Ubuntu:  sudo apt install python3 python3-venv python3-pip"
  echo "  The skill still works without ML: /repo-scanner <url> --quick"
  exit 0
fi

# --- 3. Consent before the big download --------------------------------------
echo ""
echo "The ML scanner needs PyTorch + an injection-detection model."
echo "This downloads about 1 GB (one time) and uses ~1 GB disk."
printf "Set it up now? [Y/n] "
read -r ans </dev/tty || ans="y"
case "${ans:-y}" in
  [Nn]*) echo "Skipped ML setup. Use --quick mode, or re-run later."; exit 0 ;;
esac

# --- 4. Create venv + install deps -------------------------------------------
echo ""
echo "Creating venv at $VENV_DIR ..."
[ -x "$VENV_PY" ] || "$PY" -m venv "$VENV_DIR"
"$VENV_PY" -m pip install --upgrade pip --quiet
echo "  installing PyTorch (CPU)..."
"$VENV_PY" -m pip install torch --index-url https://download.pytorch.org/whl/cpu --quiet
echo "  installing transformers + deps..."
"$VENV_PY" -m pip install -r "$SKILL_DEST/requirements.txt" --quiet

# --- 5. Download the model + record the venv path ----------------------------
echo ""
echo "Downloading the injection-detection model (~750MB)..."
"$VENV_PY" - <<'PY'
from transformers import AutoTokenizer, AutoModelForSequenceClassification
m = 'protectai/deberta-v3-base-prompt-injection-v2'
rev = 'e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5'
AutoTokenizer.from_pretrained(m, revision=rev)
AutoModelForSequenceClassification.from_pretrained(m, revision=rev)
print('model ready')
PY

printf '%s' "$VENV_PY" > "$SKILL_DEST/.venv-path"
echo "  recorded venv path -> $SKILL_DEST/.venv-path"

# --- 6. Self-test ------------------------------------------------------------
echo ""
echo "Running self-test..."
"$VENV_PY" "$SKILL_DEST/tests/run_tests.py"

echo ""
echo "Done. In Claude Code: /reload-skills"
echo "Then try:  /repo-scanner https://github.com/owner/repo"
echo ""
echo "Optional: add multilingual injection review (~120MB) — see README 'Step 5'."
