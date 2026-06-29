#!/usr/bin/env python3
"""
run_tests.py — validates the scorer against fixture findings.

Each fixture has a hand-labeled findings set (what the static+ML phases
SHOULD detect) and an expected verdict. This proves the scorer produces
correct, deterministic verdicts.

This is NOT a full integration test (it doesn't run git clone or the ML
model). It tests the SCORING LOGIC against known inputs — the part most
likely to drift between versions.

Usage: python run_tests.py
Exit 0 = all pass, 1 = at least one failure.
"""

import sys
import os
import json
import subprocess

# Windows consoles default to a legacy codepage (e.g. cp1255) that can't
# print check marks or the scorer's verdict emoji — make output robust.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCORER = os.path.join(os.path.dirname(__file__), "..", "scripts", "scorer.py")

# Each case: (name, findings_input, expected_verdict, score_range)
CASES = [
    (
        "clean-repo",
        {"findings": [], "mitigations": [{"type": "reproducible_pinned_deps"}]},
        "GREEN",
        (95, 100),
    ),
    (
        "malware-curlbash",
        {"findings": [
            {"type": "curl_pipe_bash_unsigned", "count": 1},
        ], "mitigations": []},
        # -25 only → 75, still GREEN by score but the curl|bash should really
        # be caught as hard-fail by the orchestrator's exfil check. Here we test
        # the pure unsigned-curl penalty path.
        "GREEN",
        (70, 80),
    ),
    (
        "malware-curlbash-as-exfil",
        {"findings": [
            {"type": "hard_fail", "count": 1},
        ], "mitigations": []},
        "RED",
        (0, 49),
    ),
    (
        "secret-leak",
        {"findings": [
            {"type": "hard_fail", "count": 1},  # current-tree secret = hard fail
        ], "mitigations": []},
        "RED",
        (0, 49),
    ),
    (
        "injection-skill",
        {"findings": [
            {"type": "ml_injection_genuine_high", "count": 1},
        ], "mitigations": []},
        "RED",
        (0, 49),
    ),
    (
        "kitchen-sink",
        {"findings": [
            {"type": "hard_fail", "count": 1},
            {"type": "suspicious_dependency", "count": 1},
            {"type": "postinstall_script", "count": 1},
        ], "mitigations": []},
        "RED",
        (0, 49),
    ),
    (
        "rtl-patch-regression",
        {"findings": [
            {"type": "root_ca_modification", "count": 1},
            {"type": "scheduled_task_root", "count": 1},
            {"type": "curl_pipe_bash_signed", "count": 1},
        ], "mitigations": [
            {"type": "signature_verification"},
            {"type": "backup_restore"},
            {"type": "threat_model_documented"},
        ]},
        "GREEN",
        (80, 90),
    ),
    (
        "ml-penalty-cap",
        {"findings": [
            # 5 genuine mid injections = -50 raw, should cap at -30 → score 70
            {"type": "ml_injection_genuine_mid", "count": 5},
        ], "mitigations": []},
        "GREEN",
        (68, 72),
    ),
]


def run_case(findings_input):
    result = subprocess.run(
        [sys.executable, SCORER],
        input=json.dumps(findings_input),
        capture_output=True, text=True, encoding="utf-8",
    )
    if result.returncode != 0:
        raise RuntimeError(f"scorer failed: {result.stderr}")
    return json.loads(result.stdout)


def main():
    passed = 0
    failed = 0
    print("=" * 60)
    print("repo-scanner scorer test suite")
    print("=" * 60)

    for name, inp, expected_verdict, (lo, hi) in CASES:
        try:
            out = run_case(inp)
        except Exception as e:
            print(f"  ✗ {name}: ERROR {e}")
            failed += 1
            continue

        score = out["score"]
        verdict = out["verdict"]
        ok_verdict = (verdict == expected_verdict)
        ok_score = (lo <= score <= hi)

        if ok_verdict and ok_score:
            print(f"  ✓ {name}: {out['emoji']} {score}/100 ({verdict})")
            passed += 1
        else:
            print(f"  ✗ {name}: got {score}/100 ({verdict}), "
                  f"expected {expected_verdict} in [{lo},{hi}]")
            failed += 1

    print("=" * 60)
    print(f"  {passed} passed, {failed} failed")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
