#!/usr/bin/env python3
"""
scorer.py v3.3 — deterministic scoring engine for repo-scanner.

Takes a JSON findings object (from the orchestrator's static + ML phases),
applies the penalty/mitigation matrix in CODE (not LLM interpretation),
and returns a final score + verdict.

This fixes the "LLM computes the score in its head" problem: scoring is now
reproducible. Same findings → same score, every time.

v3.3 changes:
  - Trust axis: established_project tiers (objective GitHub-metric criteria,
    separate category + cap, can never offset a hard-fail)
  - Pairing enforcement: a mitigation only earns full credit when it actually
    addresses a penalized finding type; unpaired mitigations earn half
  - Three-way curl|bash classification (signed / vendor_official / unsigned)
  - sandbox_disabled split into _install (user-facing) vs _dev (contributors)
  - stdin tolerates UTF-8 BOM (PowerShell pipes); file-path arg supported

Usage:
  echo '<findings_json>' | python scorer.py
  python scorer.py findings.json

Input JSON schema:
{
  "findings": [
    {"type": "<penalty_key>", "detail": "...", "file": "...", "count": 1}
  ],
  "mitigations": [
    {"type": "<mitigation_key>", "detail": "..."}
  ],
  "trust": [
    {"type": "established_project_tier1", "detail": "30K stars, 29 contributors, ..."}
  ]
}

Output JSON:
{
  "score": 83,
  "verdict": "GREEN",
  "emoji": "🟢",
  "penalty_total": -32,
  "mitigation_total": 15,
  "trust_total": 15,
  "breakdown": [...],
  "capped_notes": [...]
}
"""

import sys
import io
import json

# Windows pipes default to a legacy codepage (e.g. cp1255) that can't encode
# the verdict emoji — found by tests/run_tests.py. Force UTF-8 output so the
# scorer works without callers having to set PYTHONUTF8.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCORER_VERSION = "1.0.0"

# ---- Penalty matrix (negative numbers) ----
# Each key maps to (per_occurrence_penalty, max_total_cap_or_None)
PENALTIES = {
    "hard_fail":                  (-100, None),  # forces RED
    "ml_injection_genuine_high":  (-100, None),  # genuine ML >= 0.95
    "ml_injection_genuine_mid":   (-10, -30),    # genuine ML 0.80-0.94, capped
    "sandbox_disabled_install":   (-20, None),   # user-facing install/runtime flow depends on it
    "sandbox_disabled_dev":       (-10, None),   # only affects contributors opening repo in Claude Code
    "sandbox_disabled":           (-20, None),   # legacy alias == _install
    "root_ca_modification":       (-15, None),
    "scheduled_task_root":        (-12, None),
    "curl_pipe_bash_unsigned":    (-25, None),   # project's own / unknown domain, no verification
    "curl_pipe_bash_vendor_official": (-10, -15),# official vendor-documented installer (get.docker.com etc.)
    "curl_pipe_bash_signed":      (-5, None),    # cryptographic signature verified before run
    "dangerous_skip_permissions": (-10, -25),
    "suspicious_dependency":      (-15, None),
    "floating_versions":          (-5, None),
    "missing_lockfile":           (-10, None),
    "postinstall_script":         (-10, None),
    "no_license":                 (-10, None),
    "no_readme":                  (-10, None),
    "anonymous_author":           (-15, None),
    "young_repo_with_installers": (-20, None),
    "suspicious_network_domain":  (-15, None),
    "secret_in_history":          (-10, None),
}

# ---- Mitigation matrix (positive numbers) ----
# Credit for professional security engineering. Capped so a repo can't
# "buy back" past a hard-fail.
MITIGATIONS = {
    "signature_verification":  (+10, None),  # RSA/GPG signature checked before run
    "backup_restore":          (+5, None),   # backup taken, restore path exists
    "threat_model_documented": (+5, None),   # README explains the risks honestly
    "reproducible_pinned_deps":(+5, None),   # lockfile + pinned versions
}

# ---- Pairing map (anti-gaming) ----
# A mitigation earns FULL credit only if it addresses a finding type that is
# actually present. Otherwise it earns HALF credit (good hygiene, but it does
# not mitigate the penalized risk — a lockfile doesn't protect against
# pipe-to-shell). "*" = pairs with any finding.
PAIRS_WITH = {
    "signature_verification": {"curl_pipe_bash_signed", "curl_pipe_bash_unsigned",
                               "curl_pipe_bash_vendor_official"},
    "backup_restore":         {"root_ca_modification", "scheduled_task_root",
                               "sandbox_disabled", "sandbox_disabled_install",
                               "sandbox_disabled_dev"},
    "threat_model_documented": "*",  # documenting risks pairs with having risks
    "reproducible_pinned_deps": {"suspicious_dependency", "floating_versions",
                                 "postinstall_script", "missing_lockfile"},
}

# ---- Trust signals (separate axis — provenance, not engineering) ----
# Objective criteria the orchestrator verifies via GitHub API + git log.
# ALL conditions must hold for a tier (documented in SKILL.md):
#   tier1: >=5000 stars AND >=10 contributors AND >=180 days since first
#          commit AND a commit within the last 30 days
#   tier2: >=500 stars AND >=5 contributors AND >=90 days since first commit
# Trust can lift ambiguity; it can NEVER offset evidence (hard-fail blocks it):
# supply-chain attacks on popular repos are real (xz, event-stream).
TRUST_SIGNALS = {
    "established_project_tier1": +10,
    "established_project_tier2": +5,
}
# Deliberately bounded (v4.1.0): trust is a tiebreaker that nudges a borderline
# repo, NOT a force that flips a verdict band on its own. Capability evidence
# dominates — a single real risk (unsigned curl|bash −25, sandbox −20) outweighs
# the maximum trust bonus. Trust is still ignored entirely on a hard-fail.
TRUST_CAP = 10

# Total mitigation cap — mitigations can lift a score but not turn RED into GREEN
MITIGATION_CAP = 20

# Verdict thresholds (recalibrated from review)
GREEN_MIN = 70
YELLOW_MIN = 55


def compute(data):
    findings = data.get("findings", [])
    mitigations = data.get("mitigations", [])
    trust = data.get("trust", [])

    score = 100
    penalty_total = 0
    mitigation_total = 0
    trust_total = 0
    breakdown = []
    capped_notes = []
    forced_red = False

    # Aggregate penalties by type (for cap logic)
    penalty_by_type = {}
    for f in findings:
        t = f.get("type")
        c = f.get("count", 1)
        penalty_by_type.setdefault(t, 0)
        penalty_by_type[t] += c

    present_finding_types = set(penalty_by_type.keys())

    for t, total_count in penalty_by_type.items():
        if t not in PENALTIES:
            breakdown.append({"type": t, "applied": 0, "note": "unknown penalty type, ignored"})
            continue
        per, cap = PENALTIES[t]
        raw = per * total_count
        if cap is not None and raw < cap:
            applied = cap
            capped_notes.append(f"{t}: {total_count}x{per} = {raw}, capped at {cap}")
        else:
            applied = raw
        if per <= -100:
            forced_red = True
        penalty_total += applied
        breakdown.append({"type": t, "count": total_count, "applied": applied})

    # Mitigations — pairing enforced: full credit only when the mitigation
    # addresses a finding type that is actually present; otherwise half.
    mit_by_type = {}
    for m in mitigations:
        t = m.get("type")
        mit_by_type.setdefault(t, 0)
        mit_by_type[t] += 1

    for t, count in mit_by_type.items():
        if t not in MITIGATIONS:
            continue
        per, _ = MITIGATIONS[t]
        pairs = PAIRS_WITH.get(t, set())
        if pairs == "*":
            paired = bool(present_finding_types)
        else:
            paired = bool(pairs & present_finding_types)
        applied = per if paired else per // 2
        mitigation_total += applied  # mitigations count once regardless of repetition
        entry = {"type": t, "applied": f"+{applied}", "category": "mitigation"}
        if not paired:
            entry["note"] = "unpaired (does not address any penalized finding) — half credit"
        breakdown.append(entry)

    # Cap total mitigations
    if mitigation_total > MITIGATION_CAP:
        capped_notes.append(f"mitigations {mitigation_total} capped at {MITIGATION_CAP}")
        mitigation_total = MITIGATION_CAP

    # Trust signals — provenance axis. Highest tier only, capped, and NEVER
    # applied on a forced-red repo (popularity does not offset evidence).
    if trust and not forced_red:
        best = 0
        best_type = None
        for tr in trust:
            t = tr.get("type")
            val = TRUST_SIGNALS.get(t, 0)
            if val > best:
                best, best_type = val, t
        if best_type:
            trust_total = min(best, TRUST_CAP)
            breakdown.append({"type": best_type, "applied": f"+{trust_total}",
                              "category": "trust"})
    elif trust and forced_red:
        capped_notes.append("trust signals ignored: hard-fail evidence present")

    score = 100 + penalty_total + mitigation_total + trust_total
    score = max(0, min(100, score))

    if forced_red:
        score = min(score, 49)

    # Verdict
    if score >= GREEN_MIN:
        verdict, emoji = "GREEN", "🟢"
    elif score >= YELLOW_MIN:
        verdict, emoji = "YELLOW", "🟡"
    else:
        verdict, emoji = "RED", "🔴"

    return {
        "scorer_version": SCORER_VERSION,
        "score": score,
        "verdict": verdict,
        "emoji": emoji,
        "penalty_total": penalty_total,
        "mitigation_total": mitigation_total,
        "trust_total": trust_total,
        "forced_red": forced_red,
        "breakdown": breakdown,
        "capped_notes": capped_notes,
        "thresholds": {"green_min": GREEN_MIN, "yellow_min": YELLOW_MIN},
    }


def main():
    if len(sys.argv) > 1:
        # utf-8-sig: tolerate a BOM (PowerShell Out-File/Set-Content default)
        with open(sys.argv[1], 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
    else:
        # Re-wrap stdin so a UTF-8 BOM from PowerShell pipes doesn't break json.load
        stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8-sig')
        data = json.load(stdin)
    result = compute(data)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}), file=sys.stderr)
        sys.exit(1)
