"""Tests for the OSV-dev dep-CVE lookup (osv_lookup.py).

Manifest parsers are tested directly. Network is mocked — these tests run
fully offline and never hit api.osv.dev.
"""
import os
import sys
import json
import tempfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import osv_lookup as osv  # noqa: E402


# ---- requirements.txt parser ----

def test_parse_requirements_basic(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.31.0\nDjango>=4.2.0\n# comment\n-e .\nflask~=3.0\n")
    out = osv._parse_requirements_txt(str(f))
    eco_names = {(e, n) for e, n, _ in out}
    assert ("PyPI", "requests") in eco_names
    assert ("PyPI", "django") in eco_names
    assert ("PyPI", "flask") in eco_names
    # The bare `-e .` line must NOT produce an entry.
    assert all(name for _, name, _ in out)


def test_parse_requirements_skips_unpinned(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("somepkg\nother  # no version\n")
    out = osv._parse_requirements_txt(str(f))
    assert out == []  # nothing pinned, nothing to query


# ---- pyproject.toml parser (only when tomllib is available) ----

def test_parse_pyproject_extracts_lower_bound(tmp_path):
    if not osv._HAS_TOML:
        return  # python < 3.11 path; the rest of the system still works
    f = tmp_path / "pyproject.toml"
    f.write_text(
        '[project]\nname = "x"\ndependencies = ['
        '"requests>=2.31.0", "urllib3 ==2.0.7", "flask>=3.0,<4.0"]\n'
    )
    out = osv._parse_pyproject(str(f))
    names = {n for _, n, _ in out}
    assert "requests" in names
    assert "urllib3" in names
    assert "flask" in names


# ---- package-lock.json parser ----

def test_parse_package_lock_v3(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps({
        "packages": {
            "": {"name": "myapp", "version": "0.1.0"},  # the root, skipped
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express": {"version": "4.18.2"},
        }
    }))
    out = osv._parse_package_lock(str(f))
    eco_names = {(e, n) for e, n, _ in out}
    assert ("npm", "lodash") in eco_names
    assert ("npm", "express") in eco_names


# ---- collect_packages: lock vs manifest priority ----

def test_collect_packages_finds_manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    pkgs, manifests, errors = osv.collect_packages(str(tmp_path))
    assert errors == 0
    assert "requirements.txt" in manifests
    assert any(n == "requests" for _, n, _ in pkgs)


def test_collect_packages_empty_dir(tmp_path):
    pkgs, manifests, errors = osv.collect_packages(str(tmp_path))
    assert pkgs == []
    assert manifests == []


# ---- query_osv: mocked network ----

def _fake_response(payload):
    """Build a context-manager mock that mimics urlopen()."""
    cm = mock.MagicMock()
    cm.__enter__.return_value.read.return_value = json.dumps(payload).encode("utf-8")
    cm.__exit__.return_value = False
    return cm


def test_query_osv_returns_vulns_when_present():
    packages = [("PyPI", "requests", "2.31.0"), ("PyPI", "urllib3", "2.0.7")]
    fake = {
        "results": [
            {"vulns": [{"id": "GHSA-xxxx", "summary": "test vuln",
                        "database_specific": {"severity": "HIGH"}}]},
            {},  # no vulns for urllib3
        ]
    }
    with mock.patch("urllib.request.urlopen", return_value=_fake_response(fake)):
        out = osv.query_osv(packages)
    assert len(out) == 2
    assert out[0][0]["id"] == "GHSA-xxxx"
    assert out[1] is None or out[1] == []  # missing 'vulns' key


def test_query_osv_handles_network_error():
    import urllib.error
    with mock.patch("urllib.request.urlopen",
                    side_effect=urllib.error.URLError("offline")):
        out = osv.query_osv([("PyPI", "x", "1.0")])
    assert out == [None]


def test_query_osv_empty_input_short_circuits():
    # no network call at all when there are no packages
    with mock.patch("urllib.request.urlopen") as m:
        out = osv.query_osv([])
        assert out == []
        assert m.call_count == 0


# ---- severity classification ----

def test_severity_explicit_word():
    assert osv._severity_of({"database_specific": {"severity": "CRITICAL"}}) == "CRITICAL"
    assert osv._severity_of({"database_specific": {"severity": "HIGH"}}) == "HIGH"
    assert osv._severity_of({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
    assert osv._severity_of({"database_specific": {"severity": "LOW"}}) == "LOW"


def test_severity_unknown_when_no_data():
    assert osv._severity_of({}) == "UNKNOWN"
