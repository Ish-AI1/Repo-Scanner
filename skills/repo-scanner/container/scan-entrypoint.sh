#!/bin/sh
# Containerized scan: safe-clone $REPO_URL, run promptguard over the default
# doc-file selection, print JSON to stdout. The repo's code never executes.
set -eu

[ -n "${REPO_URL:-}" ] || { echo '{"error":"REPO_URL not set"}' >&2; exit 1; }

WORK=/tmp/repo
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null \
  git clone --no-checkout --depth 50 "$REPO_URL" "$WORK" >&2
git -C "$WORK" -c core.hooksPath=/dev/null checkout >&2

find "$WORK" -type f \( -iname 'README*.md' -o -name 'SKILL.md' -o -name 'CLAUDE.md' \
  -o -name 'AGENTS.md' -o -name '*.instructions.md' -o -name '.mcp.json' \
  -o -name '*.mcp.json' -o -path '*/hooks/*' \) \
  ! -path '*/.git/*' | python /audit/scripts/promptguard.py --stdin-list
