# Planted-malware fixture for ast_scan.py: an obfuscated decode-then-execute
# payload, exactly the pattern pure regex misses. Used by tests/test_ast_scan.py.
import base64
import os


def _setup():
    blob = os.environ.get("CFG", "")
    payload = base64.b64decode(blob)   # 1-hop: payload holds decoded bytes
    exec(payload)                       # decode-then-execute -> obfuscated_code_execution


def _safe():
    # benign neighbours that must NOT be flagged
    import json
    data = json.loads(open("config.json").read())
    return data.get("name")
