#!/usr/bin/env python3
"""
ast_scan.py — deterministic AST-based dangerous-code detector (Repo Scanner).

Closes the obfuscation gap that pure regex misses. Parses Python with the stdlib
`ast` module and flags dangerous code-execution patterns, including the 1-hop
case where a payload passes through a local variable before reaching the sink:

  eval(base64.b64decode(blob))            -> obfuscated_code_execution
  payload = zlib.decompress(x); exec(payload)  -> obfuscated_code_execution (1-hop)
  exec(requests.get(url).text)            -> dynamic_code_execution
  pickle.loads(open(p,'rb').read())       -> unsafe_deserialization
  os.system(user_input)                   -> command_injection_surface
  eval("1+1")                             -> dynamic_code_execution (note)

Why AST and not regex: a decode-then-execute chain can span two lines, use any
of a dozen decode functions, and assign through a variable — regex can't track
that. The `ast` walk can. No model, no network, stdlib only, fast.

Usage:
  python ast_scan.py <dir>                 # walk dir for *.py
  python ast_scan.py --list-file files.txt # explicit file list (one path/line)
  find . -name '*.py' | python ast_scan.py --stdin-list

Output (JSON to stdout):
  {"findings": [{file,line,type,detail,snippet}],
   "stats": {"py_files_scanned","parse_errors","finding_count"}}

Exit codes: 0 = scan completed (even with findings); 1 = bad invocation.
"""
import os
import sys
import json
import ast

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---- signatures ----

# Decode / deobfuscation function NAMES (last attribute component). High signal:
# legitimate code rarely decode-then-executes. Generic ".decode()" is excluded —
# bytes.decode() is ubiquitous and benign.
DECODE_FUNCS = {
    "b64decode", "b32decode", "b16decode", "a85decode", "b85decode",
    "urlsafe_b64decode", "decodebytes", "decodestring",
    "unhexlify", "a2b_hex", "a2b_base64", "a2b_qp",
    "fromhex", "decompress",
}

# Dynamic code-execution builtins.
EXEC_BUILTINS = {"eval", "exec", "compile"}

# subprocess functions that take a command; flagged only with shell=True + a
# non-constant command (constant `subprocess.run("ls", shell=True)` is benign-ish).
SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call",
                    "getoutput", "getstatusoutput"}

# Unsafe deserialization sinks as (module_first, func_last). json.loads is SAFE
# and intentionally absent. yaml.load is unsafe unless a Safe loader is passed.
DESERIALIZE = {
    ("pickle", "loads"), ("pickle", "load"),
    ("_pickle", "loads"), ("_pickle", "load"),
    ("cpickle", "loads"), ("cpickle", "load"),
    ("dill", "loads"), ("dill", "load"),
    ("marshal", "loads"), ("marshal", "load"),
    ("yaml", "load"),
}


def func_last(func):
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def exec_builtin_name(func):
    """Return 'eval'/'exec'/'compile' ONLY when this is the actual builtin —
    a bare Name, or builtins.<name>. Critically NOT `re.compile`, `df.eval`
    (pandas), or any other `obj.compile/eval/exec` attribute call, which are
    benign and common (re.compile alone caused dozens of FPs on caveman)."""
    if isinstance(func, ast.Name) and func.id in EXEC_BUILTINS:
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in EXEC_BUILTINS:
        base = func.value
        if isinstance(base, ast.Name) and base.id in ("builtins", "__builtins__"):
            return func.attr
    return None


def dotted(func):
    """Dotted name for a Call.func, e.g. 'base64.b64decode', 'os.system', 'eval'."""
    parts = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts)


def collect_assignments(tree):
    """name -> list of assigned value nodes (for 1-hop variable resolution)."""
    amap = {}
    for node in ast.walk(tree):
        targets = []
        value = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        elif isinstance(node, ast.NamedExpr):  # walrus :=
            targets, value = [node.target], node.value
        if value is None:
            continue
        for tgt in targets:
            if isinstance(tgt, ast.Name):
                amap.setdefault(tgt.id, []).append(value)
    return amap


def subtree_decode(node):
    """If the expression subtree calls a decode/deobfuscation function, return
    its name; else None."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and func_last(n.func) in DECODE_FUNCS:
            return func_last(n.func)
    return None


def arg_decode(arg, amap):
    """Decode call directly in arg, or (1-hop) in the value assigned to arg if
    arg is a bare Name. Returns (decode_func, via_var_or_None) or (None, None)."""
    d = subtree_decode(arg)
    if d:
        return d, None
    if isinstance(arg, ast.Name) and arg.id in amap:
        for val in amap[arg.id]:
            d = subtree_decode(val)
            if d:
                return d, arg.id
    return None, None


def is_trivial_literal(node):
    """eval('1+1') is noisy-but-low-risk; a pure constant/number arg is trivial."""
    if isinstance(node, ast.Constant):
        return True
    # f-string of only constants
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def yaml_is_safe(call):
    """yaml.load(..., Loader=yaml.SafeLoader / SafeLoader / CSafeLoader) is safe."""
    for kw in call.keywords:
        if kw.arg in ("Loader",):
            name = func_last(kw.value) if isinstance(kw.value, (ast.Attribute, ast.Name)) else ""
            if name and "Safe" in name:
                return True
    return False


def scan_source(source, rel):
    findings = []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return findings, True  # parse_error = True

    amap = collect_assignments(tree)

    def add(node, ftype, detail):
        seg = ""
        try:
            seg = ast.get_source_segment(source, node) or ""
        except Exception:
            seg = ""
        findings.append({
            "file": rel,
            "line": getattr(node, "lineno", 0),
            "type": ftype,
            "detail": detail,
            "snippet": seg[:160].replace("\n", " ").strip(),
        })

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        last = func_last(node.func)
        dot = dotted(node.func)
        eb = exec_builtin_name(node.func)

        # 1) eval / exec / compile (the real builtins only)
        if eb:
            arg = node.args[0] if node.args else None
            if arg is None:
                continue
            dfn, via = arg_decode(arg, amap)
            if dfn:
                via_s = f" via `{via}`" if via else ""
                add(node, "obfuscated_code_execution",
                    f"{eb}() fed by {dfn}(){via_s} — decode-then-execute, the classic obfuscated-payload pattern")
            elif not is_trivial_literal(arg):
                add(node, "dynamic_code_execution",
                    f"{eb}() with a dynamic (non-constant) argument")
            else:
                add(node, "dynamic_code_execution",
                    f"{eb}() on a string/code literal")

        # 2) os.system / os.popen
        elif dot in ("os.system", "os.popen"):
            arg = node.args[0] if node.args else None
            if arg is not None and not is_trivial_literal(arg):
                add(node, "command_injection_surface",
                    f"{dot}() with a dynamic command — shell injection surface")

        # 3) subprocess(..., shell=True) with dynamic command
        elif last in SUBPROCESS_FUNCS and ("subprocess" in dot or last == "Popen"):
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                             and kw.value.value is True for kw in node.keywords)
            arg = node.args[0] if node.args else None
            if shell_true and arg is not None and not is_trivial_literal(arg):
                add(node, "command_injection_surface",
                    f"{dot}(shell=True) with a dynamic command — shell injection surface")

        # 4) unsafe deserialization
        else:
            first = dot.split(".")[0].lower() if dot else ""
            if (first, last) in DESERIALIZE:
                if last == "load" and first == "yaml" and yaml_is_safe(node):
                    continue
                add(node, "unsafe_deserialization",
                    f"{dot}() — deserializing untrusted data can execute arbitrary code (CWE-502)")

    return findings, False


def collect_py_from_dir(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}]
        for f in filenames:
            if f.endswith(".py"):
                out.append(os.path.join(dirpath, f))
    return out


def collect_from_listfile(path):
    out = []
    with open(path, "r", encoding="utf-8-sig") as fh:
        for line in fh:
            p = line.strip()
            if p and os.path.isfile(p):
                out.append(p)
    return out


def collect_from_stdin():
    out = []
    for line in sys.stdin:
        p = line.strip()
        if p and os.path.isfile(p):
            out.append(p)
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print(json.dumps({"error": "pass a directory, --list-file <path>, or --stdin-list"}), file=sys.stderr)
        sys.exit(1)

    if args[0] == "--list-file":
        if len(args) < 2 or not os.path.isfile(args[1]):
            print(json.dumps({"error": "--list-file requires a readable file path"}), file=sys.stderr)
            sys.exit(1)
        files = collect_from_listfile(args[1])
        repo_root = os.getcwd()
    elif args[0] == "--stdin-list":
        files = collect_from_stdin()
        repo_root = os.getcwd()
    else:
        repo_root = os.path.abspath(args[0])
        if not os.path.isdir(repo_root):
            print(json.dumps({"error": f"not a directory: {repo_root}"}), file=sys.stderr)
            sys.exit(1)
        files = collect_py_from_dir(repo_root)

    all_findings = []
    parse_errors = 0
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError:
            continue
        try:
            rel = os.path.relpath(fp, repo_root)
        except ValueError:
            rel = fp
        findings, parse_err = scan_source(source, rel)
        if parse_err:
            parse_errors += 1
        all_findings.extend(findings)

    # Severity order for the report: obfuscated first.
    order = {"obfuscated_code_execution": 0, "command_injection_surface": 1,
             "unsafe_deserialization": 2, "dynamic_code_execution": 3}
    all_findings.sort(key=lambda f: (order.get(f["type"], 9), f["file"], f["line"]))

    print(json.dumps({
        "findings": all_findings,
        "stats": {
            "py_files_scanned": len(files),
            "parse_errors": parse_errors,
            "finding_count": len(all_findings),
        },
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
