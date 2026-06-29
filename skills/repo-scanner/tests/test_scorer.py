"""Deterministic-scorer regression tests.

Run (from the skill root, with your venv's python):
  <venv-python> -m pytest tests/ -q
Every matrix change MUST keep these green or update them with justification
in CHANGELOG.md.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import scorer  # noqa: E402


def test_benchmark_rtl_patch():
    """shraga100/claude-desktop-rtl-patch — calibration anchor: 88 GREEN."""
    data = {
        "findings": [
            {"type": "root_ca_modification", "count": 1},
            {"type": "scheduled_task_root", "count": 1},
            {"type": "curl_pipe_bash_signed", "count": 1},
        ],
        "mitigations": [
            {"type": "signature_verification"},
            {"type": "backup_restore"},
            {"type": "threat_model_documented"},
        ],
    }
    r = scorer.compute(data)
    assert r["score"] == 88
    assert r["verdict"] == "GREEN"
    assert r["mitigation_total"] == 20  # all paired, at cap


def test_unpaired_mitigation_gets_half_credit():
    """Anti-gaming: a lockfile doesn't mitigate a sandbox finding."""
    data = {
        "findings": [{"type": "sandbox_disabled_dev", "count": 1}],
        "mitigations": [{"type": "reproducible_pinned_deps"}],
    }
    r = scorer.compute(data)
    assert r["score"] == 92  # 100 - 10 + (5 // 2)
    unpaired = [b for b in r["breakdown"] if b.get("note")]
    assert len(unpaired) == 1


def test_vendor_curl_pipe_cap():
    """4 vendor-official installers cap at -15, not -40."""
    data = {"findings": [{"type": "curl_pipe_bash_vendor_official", "count": 4}]}
    r = scorer.compute(data)
    assert r["score"] == 85
    assert any("capped" in n for n in r["capped_notes"])


def test_hard_fail_blocks_trust_and_forces_red():
    """xz/event-stream rule: popularity never offsets evidence."""
    data = {
        "findings": [{"type": "hard_fail", "count": 1}],
        "mitigations": [{"type": "signature_verification"}],
        "trust": [{"type": "established_project_tier1"}],
    }
    r = scorer.compute(data)
    assert r["forced_red"] is True
    assert r["verdict"] == "RED"
    assert r["score"] <= 49
    assert r["trust_total"] == 0


def test_trust_highest_tier_only_and_score_ceiling():
    data = {
        "findings": [],
        "trust": [
            {"type": "established_project_tier2"},
            {"type": "established_project_tier1"},
        ],
    }
    r = scorer.compute(data)
    assert r["trust_total"] == 10  # highest tier only (v4.1.0: tier1 = +10)
    assert r["score"] == 100  # ceiling holds


def test_trust_cannot_flip_band_alone():
    """v4.1.0 bound: max trust (+10) cannot rescue a sub-YELLOW capability score.
    A repo at RED on capability stays RED-ish; trust only nudges within a band."""
    data = {
        "findings": [{"type": "curl_pipe_bash_unsigned", "count": 1},
                     {"type": "sandbox_disabled_install", "count": 1}],  # -45 -> 55
        "trust": [{"type": "established_project_tier1"}],  # +10 -> 65, still YELLOW
    }
    r = scorer.compute(data)
    assert r["score"] == 65
    assert r["verdict"] == "YELLOW"


def test_benchmark_nanoclaw():
    """nanocoai/nanoclaw — calibration anchor: 95 GREEN under v3.3."""
    data = {
        "findings": [
            {"type": "sandbox_disabled_dev", "count": 1},
            {"type": "curl_pipe_bash_vendor_official", "count": 4},
        ],
        "mitigations": [
            {"type": "reproducible_pinned_deps"},
            {"type": "threat_model_documented"},
            {"type": "backup_restore"},
        ],
        "trust": [{"type": "established_project_tier2"}],
    }
    r = scorer.compute(data)
    assert r["score"] == 92  # v4.1.0: tier2 trust is +5 (was +8)
    assert r["verdict"] == "GREEN"


def test_benchmark_caveman_static_only():
    """JuliusBrussee/caveman — after v3.3.1, ML noise carries no penalty:
    only the unsigned installer counts. 75 GREEN."""
    data = {"findings": [{"type": "curl_pipe_bash_unsigned", "count": 1}]}
    r = scorer.compute(data)
    assert r["score"] == 75
    assert r["verdict"] == "GREEN"


def test_unknown_type_ignored_not_crash():
    r = scorer.compute({"findings": [{"type": "made_up_key", "count": 3}]})
    assert r["score"] == 100


def test_verdict_thresholds():
    assert scorer.GREEN_MIN == 70
    assert scorer.YELLOW_MIN == 55
