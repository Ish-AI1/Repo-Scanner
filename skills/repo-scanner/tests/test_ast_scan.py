"""Tests for the deterministic AST dangerous-code detector (ast_scan.py).

No model load — pure stdlib `ast`, so these run fast. Every change to the
signature sets MUST keep these green (or update with justification in CHANGELOG).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import ast_scan as a  # noqa: E402


def _types(src):
    findings, parse_err = a.scan_source(src, "t.py")
    return [f["type"] for f in findings], parse_err


# ---- obfuscated decode-then-execute (the weakness-#4 closer) ----

def test_obfuscated_direct_b64():
    t, _ = _types("import base64\neval(base64.b64decode(blob))")
    assert "obfuscated_code_execution" in t


def test_obfuscated_one_hop_variable():
    t, _ = _types("import zlib\npayload = zlib.decompress(x)\nexec(payload)")
    assert "obfuscated_code_execution" in t


def test_obfuscated_fromhex():
    t, _ = _types("exec(bytes.fromhex(s))")
    assert "obfuscated_code_execution" in t


def test_obfuscated_unhexlify_1hop():
    t, _ = _types("import binascii\np = binascii.unhexlify(s)\neval(p)")
    assert "obfuscated_code_execution" in t


# ---- dynamic (non-decode) exec — note level ----

def test_dynamic_exec_from_network():
    t, _ = _types("exec(requests.get(url).text)")
    assert "dynamic_code_execution" in t
    assert "obfuscated_code_execution" not in t


def test_dynamic_eval_from_env():
    t, _ = _types("import os\neval(os.environ['CODE'])")
    assert "dynamic_code_execution" in t


# ---- unsafe deserialization ----

def test_pickle_loads_flagged():
    t, _ = _types("import pickle\npickle.loads(open(p,'rb').read())")
    assert "unsafe_deserialization" in t


def test_marshal_loads_flagged():
    t, _ = _types("import marshal\nmarshal.loads(data)")
    assert "unsafe_deserialization" in t


def test_yaml_unsafe_load_flagged():
    t, _ = _types("import yaml\nyaml.load(open(f).read())")
    assert "unsafe_deserialization" in t


# ---- command injection surface ----

def test_os_system_dynamic_flagged():
    t, _ = _types("import os\nos.system(cmd)")
    assert "command_injection_surface" in t


def test_subprocess_shell_true_dynamic_flagged():
    t, _ = _types("import subprocess\nsubprocess.run(user_cmd, shell=True)")
    assert "command_injection_surface" in t


# ---- benign code must NOT be flagged (no false positives) ----

def test_json_loads_not_flagged():
    t, _ = _types("import json\njson.loads(open(p).read())")
    assert t == []


def test_bytes_decode_not_flagged():
    t, _ = _types("x = data.decode('utf-8')")
    assert t == []


def test_dict_get_and_file_read_not_flagged():
    assert _types("v = config.get('key')")[0] == []
    assert _types("text = open(p).read()")[0] == []


def test_yaml_safe_load_not_flagged():
    assert _types("import yaml\nyaml.safe_load(open(f))")[0] == []
    assert _types("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)")[0] == []


def test_subprocess_list_not_flagged():
    assert _types("import subprocess\nsubprocess.run(['ls','-la'])")[0] == []


def test_os_system_constant_not_flagged():
    assert _types("import os\nos.system('ls')")[0] == []


def test_re_compile_not_flagged():
    # re.compile is NOT the builtin compile() — caused dozens of FPs (caveman).
    assert _types("import re\nP = re.compile(r'\\d+')")[0] == []


def test_pandas_eval_attribute_not_flagged():
    # df.eval(...) is a method, not the builtin eval().
    assert _types("result = df.eval('a + b')")[0] == []


def test_builtins_exec_still_flagged():
    # builtins.exec(...) IS the dangerous builtin.
    t, _ = _types("import builtins\nbuiltins.exec(code)")
    assert "dynamic_code_execution" in t


def test_syntax_error_is_graceful():
    findings, parse_err = a.scan_source("def f(:\n  pass", "bad.py")
    assert parse_err is True
    assert findings == []


# ---- directory walk over the planted fixture ----

def test_fixture_dir_walk_catches_obfuscation():
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "obfuscated-exec")
    files = a.collect_py_from_dir(fixture)
    assert any(f.endswith("helper.py") for f in files)
    all_types = []
    for fp in files:
        with open(fp, encoding="utf-8") as fh:
            findings, _ = a.scan_source(fh.read(), fp)
        all_types += [x["type"] for x in findings]
    assert "obfuscated_code_execution" in all_types
    # the benign json.loads / .get in the same file must not be flagged
    assert "unsafe_deserialization" not in all_types
