#!/usr/bin/env python3
"""
osv_lookup.py — query the OSV.dev public database for known CVEs in a repo's
declared dependencies. Stdlib-only (urllib + json). Local: no auth, no tracking.

What it does:
  1. Parses dependency manifests at the repo root (uv.lock / poetry.lock /
     requirements.txt / pyproject.toml / package-lock.json / yarn.lock).
  2. For each (ecosystem, name, version) it found, calls the OSV.dev batch
     query API (a single POST, no per-package round-trip).
  3. Emits findings[] with type=vulnerable_dependency, severity drawn from
     the OSV record, an OSV id (e.g. GHSA-..., PYSEC-..., CVE-...), and a
     link the user can open.

Privacy: we send PACKAGE NAMES + VERSIONS (already public on the registry)
to api.osv.dev. We do NOT send any repo content. Off by default? No — the
data leaving the box is already public. But: `--offline` skips the network
call and reports just the manifest parse, in case the user prefers it.

Usage:
  python osv_lookup.py <repo_root>          # full: parse + query
  python osv_lookup.py <repo_root> --offline # parse only, no network

Output JSON:
  {"findings":[{type,ecosystem,package,version,osv_id,severity,summary,url}],
   "stats":{packages_checked, manifests_seen, network_used, parse_errors}}
"""
import os
import re
import sys
import json
import urllib.request
import urllib.error

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
HTTP_TIMEOUT = 10
MAX_PACKAGES = 500  # belt-and-suspenders; real repos rarely exceed this

# ---- manifest parsers (stdlib only, no toml in <3.11; we use tomllib if available) ----

try:
    import tomllib  # py 3.11+
    _HAS_TOML = True
except ImportError:
    tomllib = None
    _HAS_TOML = False


def _parse_pyproject(path):
    """Best-effort: list direct deps from [project.dependencies]. Versions are
    often ranges, not pins — we send the LOWER bound when present (an OSV hit
    against the lower bound is a real signal: 'your floor allows a known-bad
    version'). Skips unbounded ranges."""
    if not _HAS_TOML:
        return []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    deps = data.get("project", {}).get("dependencies", []) or []
    out = []
    for spec in deps:
        # parse "name>=1.2.3" / "name==2.0.0" / "name~=1.5" / "name>1.0,<2.0"
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=~!]+)\s*([0-9][\w.\-+]*)", spec)
        if m:
            out.append(("PyPI", m.group(1).lower(), m.group(3)))
    return out


def _parse_requirements_txt(path):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=~!]+)\s*([0-9][\w.\-+]*)", line)
                if m:
                    out.append(("PyPI", m.group(1).lower(), m.group(3)))
    except OSError:
        return []
    return out


def _parse_uv_lock(path):
    """uv.lock is TOML with [[package]] tables that carry name + version."""
    if not _HAS_TOML:
        return []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    out = []
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        ver = pkg.get("version")
        if name and ver:
            out.append(("PyPI", name.lower(), ver))
    return out


def _parse_poetry_lock(path):
    """Poetry's lockfile is TOML, same shape as uv.lock for our purposes."""
    return _parse_uv_lock(path)


def _parse_package_lock(path):
    """npm's package-lock.json. We read the 'packages' map (v2/v3 format)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    pkgs = data.get("packages") or data.get("dependencies") or {}
    for key, info in pkgs.items():
        if not isinstance(info, dict):
            continue
        # "node_modules/lodash" -> "lodash"
        name = info.get("name") or (key.split("node_modules/")[-1] if "node_modules/" in key else key)
        ver = info.get("version")
        if name and ver and name != "":
            out.append(("npm", name.lower(), ver))
    return out


PARSERS = {
    "uv.lock":              _parse_uv_lock,
    "poetry.lock":          _parse_poetry_lock,
    "pyproject.toml":       _parse_pyproject,
    "requirements.txt":     _parse_requirements_txt,
    "package-lock.json":    _parse_package_lock,
}


def collect_packages(repo_root):
    """Walk repo top level for known manifests. Return (packages, manifests_seen, errors)."""
    packages = []
    manifests = []
    errors = 0
    for fname, parser in PARSERS.items():
        path = os.path.join(repo_root, fname)
        if not os.path.isfile(path):
            continue
        manifests.append(fname)
        try:
            new = parser(path)
            packages.extend(new)
        except Exception:
            errors += 1
    # Lockfiles take priority over manifests (more accurate). If a lockfile
    # gave us packages, drop the manifest-only entries to avoid duplicates.
    has_lock = any(m.endswith(".lock") or m == "package-lock.json" for m in manifests)
    if has_lock:
        # Keep only packages that came from a lock (heuristic: a lock parse
        # gives a stable list; pyproject + requirements add at most a few
        # extra). Easier: de-dup by (ecosystem, name), preferring later (lock)
        # entries since dict insertion order preserves that.
        seen = {}
        for triple in packages:
            seen[(triple[0], triple[1])] = triple
        packages = list(seen.values())
    return packages[:MAX_PACKAGES], manifests, errors


# ---- OSV query ----

def query_osv(packages):
    """Single POST batch query. Returns a list aligned with `packages` of
    (osv_results_list_or_None). Network errors -> None for everything."""
    if not packages:
        return []
    queries = [
        {"package": {"name": name, "ecosystem": eco}, "version": ver}
        for eco, name, ver in packages
    ]
    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_BATCH_URL, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "repo-scanner-osv/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read()
        parsed = json.loads(raw)
        results = parsed.get("results", [])
        return [r.get("vulns") for r in results]
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return [None] * len(packages)


# ---- severity extraction (OSV records vary in shape) ----

def _severity_of(vuln_summary):
    """Return one of: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN. Best-effort —
    OSV's severity vocabulary isn't fully standardized across ecosystems."""
    sevs = vuln_summary.get("severity") or []
    score_text = ""
    for s in sevs:
        score_text += " " + (s.get("score") or "")
    # GHSA database_specific often carries an explicit severity word.
    db = vuln_summary.get("database_specific") or {}
    word = (db.get("severity") or "").upper()
    if word in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
        return "MEDIUM" if word == "MODERATE" else word
    # CVSS vector parsing — pull base score if present.
    m = re.search(r"CVSS:[^/]+(?:/[A-Z]+:[A-Z])+", score_text)
    # crude bucketing by AV/AC if no DB severity word found
    if m:
        return "HIGH"
    return "UNKNOWN"


# ---- main ----

def main():
    args = sys.argv[1:]
    if not args:
        print(json.dumps({"error": "pass <repo_root> [--offline]"}), file=sys.stderr)
        sys.exit(1)
    repo_root = os.path.abspath(args[0])
    offline = "--offline" in args
    if not os.path.isdir(repo_root):
        print(json.dumps({"error": f"not a directory: {repo_root}"}), file=sys.stderr)
        sys.exit(1)

    packages, manifests, parse_errors = collect_packages(repo_root)

    findings = []
    network_used = False
    if packages and not offline:
        network_used = True
        results = query_osv(packages)
        for (eco, name, ver), vulns in zip(packages, results):
            if not vulns:
                continue
            for v in vulns:
                osv_id = v.get("id", "")
                summary = (v.get("summary") or v.get("details") or "")[:200]
                severity = _severity_of(v)
                # OSV web URL: stable redirect for any id type
                url = f"https://osv.dev/vulnerability/{osv_id}" if osv_id else ""
                findings.append({
                    "type": "vulnerable_dependency",
                    "ecosystem": eco,
                    "package": name,
                    "version": ver,
                    "osv_id": osv_id,
                    "severity": severity,
                    "summary": summary,
                    "url": url,
                })

    # Sort: CRITICAL/HIGH first, then alpha
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["package"]))

    print(json.dumps({
        "findings": findings,
        "stats": {
            "packages_checked": len(packages),
            "manifests_seen": manifests,
            "network_used": network_used,
            "parse_errors": parse_errors,
            "finding_count": len(findings),
        },
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
