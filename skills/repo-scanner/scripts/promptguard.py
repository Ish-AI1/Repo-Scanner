#!/usr/bin/env python3
"""
promptguard.py v3.3.1 — ML-based prompt injection scanner for repo-scanner skill.

Loads ProtectAI's DeBERTa-v3 model once, then scans files in chunks with batching.

v3.3.1 (the caveman fix):
  - Exfil-corroboration rule: a finding is penalty-eligible ONLY when a hard
    exfiltration pattern is present — in ANY file type. ML alone never
    penalizes. (caveman's terse README style forced a false RED under v3.3.)
  - Model revision pinned (supply-chain hygiene for the audit tool itself).

v3.3 fixes (from real-world testing on Hebrew + CJK + skill repos):
  - Language filter generalized: skips files >40% non-Latin script (Hebrew,
    Chinese, Japanese, Arabic, Cyrillic, ...) — DeBERTa fires on language,
    not content, for all of them. Static scan still covers skipped files.
  - Instruction-file rule: SKILL.md / CLAUDE.md / AGENTS.md / *.instructions.md
    exist to instruct an LLM — imperative tone is their PURPOSE. Findings in
    them are auto-FP unless score >= 0.95 AND a hard exfiltration pattern is
    present. This moves the "Claude overrides FPs manually" judgment into code.
  - --list-file <path> input mode (avoids PowerShell stdin BOM/encoding issues)
  - fp_reason field explains WHY a finding was classed as likely-FP

v3.1 fixes (kept):
  - chunk size aligned to model's 512-token limit (~800 chars)
  - batched inference (8 chunks at a time)
  - graceful fallback if torch/transformers fail to import

Usage:
  python promptguard.py /path/to/repo
  find . -name "*.md" | python promptguard.py --stdin-list
  python promptguard.py --list-file files.txt
  # add --self-audit ONLY when auditing the canonical repo-scanner repo itself
  # (orchestrator-gated by REPO_URL) — exempts repo-scanner's own docs from the
  # exfil gate. Never pass it for a third-party repo.

Output (JSON to stdout):
  {
    "findings": [
      {"file","chunk_start","score","label","preview","likely_false_positive","fp_reason"}
    ],
    "stats": {"files_scanned","files_skipped_non_latin","chunks_scanned","model","fp_suspected"}
  }

Exit codes:
  0 — scan completed
  1 — fatal error (model load, etc.)
  2 — dependencies missing (torch/transformers not importable)
"""

import os
import sys
import json
import re
from pathlib import Path

# Windows pipes default to a legacy codepage (e.g. cp1255) that cannot encode
# the non-Latin previews (Hebrew/CJK) this tool routinely emits — same fix as
# scorer.py. Without it, json.dumps() of any finding with non-Latin text dies
# with UnicodeEncodeError ('charmap' codec) on a Windows console/pipe.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---- Config ----

# Text + code files. Injections can hide in code comments.
TEXT_EXTENSIONS = {
    '.md', '.txt', '.rst', '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg',
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.ps1', '.rb', '.go', '.rs',
}

# Chunk size aligned to model's 512-token limit.
# ~800 chars ≈ 350-450 tokens for mixed Hebrew/English — stays under 512 so
# nothing is silently truncated.
CHUNK_CHARS = 800
CHUNK_OVERLAP = 150

# Batch size for inference (CPU). 8 is a sweet spot on Core Ultra.
BATCH_SIZE = 8

# Score thresholds
MIN_REPORT_SCORE = 0.80
HARD_FAIL_SCORE = 0.95

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
# Pinned model revision (supply-chain: the audit tool's own model must not
# drift). Update deliberately, with an eval-set run, never implicitly.
MODEL_REVISION = "e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5"

# Non-Latin detection: DeBERTa's injection classifier is biased against ALL
# non-English text (proven on Hebrew, Chinese, Japanese in real testing \u2014
# ~100% FP rate). Files above the threshold are skipped entirely; chunks
# above the per-chunk threshold are FP-flagged. Static scan still covers
# skipped files.
NON_LATIN_RANGE = re.compile(
    r'[\u0590-\u05FF'   # Hebrew
    r'\u0600-\u06FF'    # Arabic
    r'\u0400-\u04FF'    # Cyrillic
    r'\u3040-\u30FF'    # Hiragana + Katakana
    r'\u4E00-\u9FFF'    # CJK Unified Ideographs
    r'\uAC00-\uD7AF'    # Hangul
    r'\u0E00-\u0E7F]'   # Thai
)
FILE_NON_LATIN_SKIP = 0.40   # skip whole file above this ratio
CHUNK_NON_LATIN_FP = 0.30    # flag chunk as likely-FP above this ratio

# v3.3.1: HARD_EXFIL is the single gate for penalty-eligibility, in ANY file
# type. INSTRUCTION_BASENAMES only selects a more specific fp_reason for the
# report. Generic keywords like a bare `curl` in a code block don't count;
# those are normal in docs.
#
# v4: multilingual. DeBERTa can't scan non-Latin text (we skip those files),
# so this deterministic gate is the ONLY injection coverage there — it runs
# as a standalone regex pass over skipped files (detector: exfil-pattern-only).
# Chosen over a gated second model (Llama Prompt Guard 2 requires per-user
# Meta approval — unacceptable install friction). Patterns are translations
# of: ignore-previous-instructions / don't-tell-the-user / reveal-system-
# prompt, in he/ar/ru/zh/ja/es. Extend the list as the eval corpus grows.
INSTRUCTION_BASENAMES = {'skill.md', 'claude.md', 'agents.md'}
HARD_EXFIL = re.compile(
    r'(webhook\.site|requestbin|burpcollaborator|'
    r'ignore\s+(all\s+|previous\s+|prior\s+)?instructions|'
    r'disregard\s+(all\s+|previous\s+|prior\s+)?(instructions|rules|'
    r'your\s+system\s+prompt)|'
    r'reveal\s+(the\s+)?(system\s+prompt|secrets?|credentials?|api\s+keys?)|'
    r'exfiltrat|do\s+not\s+(tell|mention\s+this\s+(instruction\s+)?to)\s+the\s+user|'
    r'without\s+(telling|informing)\s+the\s+user|'
    # Hebrew
    r'התעלם\s+מ(כל\s+)?ההוראות|אל\s+תספר\s+למשתמש|'
    r'בלי\s+ליידע\s+את\s+המשתמש|מבלי\s+להודיע\s+למשתמש|'
    r'חשוף\s+את\s+הנחיות\s+המערכת|'
    # Arabic
    r'تجاهل\s+التعليمات\s+السابقة|لا\s+تخبر\s+المستخدم|'
    # Russian
    r'игнорируй\s+предыдущие\s+инструкции|не\s+говори\s+пользователю|'
    # Chinese
    r'忽略之前的指令|忽略以上指令|不要告诉用户|'
    # Japanese
    r'以前の指示を無視|ユーザーに伝えないで|'
    # Spanish
    r'ignora\s+las\s+instrucciones\s+anteriores|no\s+le\s+digas\s+al\s+usuario|'
    # v4.3 — modern/indirect injection (task-disguised): the FRAME of a
    # manipulation prompt ("to finish the X, you must/please/now run the
    # following Y"). Tightened to also require an authoritative addressing
    # word and a "following <noun>" target — legitimate docs say "run pytest",
    # not "to finish the summary, you must run the following command". This
    # keeps the FP risk near zero on real CONTRIBUTING.md / setup docs.
    r'to\s+(finish|complete|continue)\s+(the|this|your)\s+\w+[,.]?\s+'
    r'(you\s+(must|should|need\s+to)|please|now)\s+'
    r'(run|execute|write|perform|send|fetch|read|use|call)\s+the\s+following\s+'
    r'(command|tool[\s_-]?call|prompt|instruction|message|line|sentence|snippet|payload|action)|'
    r'as\s+part\s+of\s+(the|this|your)\s+(task|response|summary|workflow)[,.]?\s+'
    r'(you\s+(must|should|need\s+to)|please|now)\s+'
    r'(run|execute|fetch|send|call|read|use)\s+the\s+following|'
    r'before\s+(responding|returning|finishing|answering)[,.]?\s+'
    r'(you\s+(must|should|need\s+to)|please|now)\s+'
    r'(run|execute|fetch|send|call|read|use)\s+the\s+following|'
    # Hebrew variants of the same frame
    r'כדי\s+ל(סיים|השלים|המשיך)\s+את\s+ה(סיכום|משימה|תשובה|ניתוח|תהליך)\s*[,.]?\s+'
    r'(אתה\s+חייב|עליך|חובה\s+עליך|אנא|כעת)\s+ל?(הרץ|בצע|לכתוב|לשלוח|להביא|לקרוא|להשתמש)\s+'
    r'את\s+ה(פקודה|כלי|טקסט|הוראה|הודעה|מ?שפט|תוכן)\s+(הבאה|הבא)|'
    r'כחלק\s+מ(ה)?(משימה|סיכום|תשובה|תהליך)\s*[,.]?\s+'
    r'(אתה\s+חייב|עליך|אנא|כעת)\s+ל?(הרץ|בצע|לקרוא|לשלוח|להביא)|'
    r'לפני\s+ש(תחזיר|תסיים|תשלח|תענה)\s*[,.]?\s+'
    r'(אתה\s+חייב|עליך|אנא|כעת)\s+ל?(הרץ|בצע|לשלוח|להביא))',
    re.IGNORECASE
)


def is_instruction_file(path):
    name = os.path.basename(path).lower()
    return name in INSTRUCTION_BASENAMES or name.endswith('instructions.md')


# --- Self-documentation guard (v4.2) -----------------------------------------
# A security tool's OWN docs legitimately QUOTE the attack strings it detects:
# repo-scanner's SKILL.md / README / CHANGELOG list "ignore previous instructions",
# "reveal the system prompt", "webhook.site", etc. as the patterns it hunts. The
# exfil-corroboration gate can't tell describing a pattern from using one, so it
# marks those as genuine injections — auditing repo-scanner force-REDs repo-scanner.
#
# IDENTITY GATE (not a forkable in-repo marker). The exemption is OFF by default
# and only engages when the orchestrator passes `--self-audit`, which SKILL.md
# Phase 7 instructs it to do ONLY after confirming REPO_URL is the canonical
# repo-scanner URL. A fork at any other URL never gets the flag, so its SKILL.md
# exfil stays fully penalty-eligible — closing the earlier hole where a fork that
# kept promptguard.py could self-exempt. As a second, independent check we still
# require the file to sit in a real repo-scanner tree (structural fingerprint) and
# to be a canonical top-level doc; files under tests/ or fixtures/ are NEVER
# exempt, so the planted-injection fixtures stay detectable. Even when exempted,
# the static layer and the Phase-7b judge still read everything.
SELF_FINGERPRINT = "ML-based prompt injection scanner for repo-scanner skill"
SELF_DOC_BASENAMES = {'skill.md', 'changelog.md', 'about.md'}
_self_repo_cache = {}


def _dir_in_self_repo(directory):
    """True if `directory` sits inside a repo-scanner tree (memoised per dir)."""
    if directory in _self_repo_cache:
        return _self_repo_cache[directory]
    result = False
    d = directory
    for _ in range(6):
        for rel in (('scripts', 'promptguard.py'),
                    ('skills', 'repo-scanner', 'scripts', 'promptguard.py')):
            cand = os.path.join(d, *rel)
            try:
                if os.path.isfile(cand):
                    with open(cand, 'r', encoding='utf-8', errors='replace') as f:
                        if SELF_FINGERPRINT in f.read(2000):
                            result = True
                            break
            except OSError:
                pass
        if result:
            break
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    _self_repo_cache[directory] = result
    return result


def is_self_doc(filepath, self_audit=False):
    """A canonical repo-scanner doc file whose exfil matches are self-description.

    Gated on `self_audit` (the orchestrator's --self-audit opt-in, set only for
    the canonical repo-scanner URL): without it the exemption never engages, so a
    fork's docs stay penalty-eligible. Excludes anything under tests/ or
    fixtures/ — the tool's planted malware corpus must stay detectable."""
    if not self_audit:
        return False
    p = os.path.abspath(filepath).replace('\\', '/').lower()
    if '/tests/' in p or '/fixtures/' in p:
        return False
    base = os.path.basename(p)
    if not (base in SELF_DOC_BASENAMES or base.startswith('readme')):
        return False
    return _dir_in_self_repo(os.path.dirname(os.path.abspath(filepath)))


def load_classifier():
    """Load model once. Returns (pipeline, error_or_None)."""
    try:
        import warnings
        warnings.filterwarnings("ignore")
        os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
        from transformers import pipeline
    except ImportError as e:
        return None, f"dependencies missing: {e}"

    try:
        clf = pipeline(
            "text-classification",
            model=MODEL_ID,
            revision=MODEL_REVISION,
            max_length=512,
            truncation=True,
            top_k=1,
        )
        return clf, None
    except Exception as e:
        return None, f"model load failed: {type(e).__name__}: {e}"


def collect_files_from_dir(root):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build'}]
        for fname in filenames:
            if Path(fname).suffix.lower() in TEXT_EXTENSIONS:
                files.append(os.path.join(dirpath, fname))
    return files


def collect_files_from_stdin():
    files = []
    for line in sys.stdin:
        path = line.strip()
        if path and os.path.isfile(path):
            files.append(path)
    return files


def chunk_text(text, size=CHUNK_CHARS, overlap=CHUNK_OVERLAP):
    chunks = []
    i = 0
    while i < len(text):
        chunks.append((i, text[i:i + size]))
        if i + size >= len(text):
            break
        i += size - overlap
    return chunks


LATIN_LETTER = re.compile(r'[A-Za-z]')


def non_latin_ratio(text):
    """Ratio over LETTERS only — HTML markup, punctuation and digits would
    otherwise dilute a Chinese/Hebrew chunk below the threshold (a CJK README
    header full of <p align=...> tags slipped through at 0.9958 in testing)."""
    if not text:
        return 0.0
    non_latin = len(NON_LATIN_RANGE.findall(text))
    latin = len(LATIN_LETTER.findall(text))
    total = non_latin + latin
    if total == 0:
        return 0.0
    return non_latin / total


def assess_false_positive(chunk, score, instruction_file=False, self_doc=False):
    """
    v3.3.1 exfil-corroboration rule: an ML finding is penalty-eligible ONLY
    when a hard exfiltration pattern corroborates it — in ANY file type.

    Rationale: DeBERTa was trained on chat prompts, not repo docs. Out-of-
    distribution README text produces high-confidence FPs — proven on caveman
    (71K-star repo scored forced-RED on its terse writing style alone, zero
    actual injections). ML alone is a signal; deterministic evidence makes it
    a verdict. The planted-malware control (webhook.site + "ignore previous
    instructions") still trips HARD_EXFIL and stays genuine.

    v4.2: self_doc short-circuits the gate for repo-scanner's OWN canonical docs,
    which quote the exfil patterns as documentation (see is_self_doc).

    Returns (is_fp, reason).
    """
    if self_doc and HARD_EXFIL.search(chunk):
        return True, "repo-scanner self-documentation (tool quoting its own detection patterns)"
    if HARD_EXFIL.search(chunk):
        return False, None

    # No exfil corroboration — note only. Pick the most specific reason.
    if instruction_file:
        return True, "instruction-file imperative tone (SKILL.md-class file)"
    nl = non_latin_ratio(chunk)
    if nl > CHUNK_NON_LATIN_FP:
        return True, f"non-Latin bias ({nl:.0%} non-Latin letters)"
    return True, "no hard exfiltration pattern — ML signal only (note, no penalty)"


def scan_files(files, classifier, repo_root, self_audit=False):
    """Scan files in batches. Returns (findings, chunks_scanned, skipped_non_latin)."""
    # Build flat list of (file_rel, chunk_start, chunk_text, is_instruction)
    work = []
    skipped_non_latin = []
    exfil_only_findings = []
    embed_chunks = []  # (rel, cstart, text) for the optional embedding review layer
    for filepath in files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
        except (OSError, IOError):
            continue
        if not text.strip():
            continue
        try:
            rel = os.path.relpath(filepath, repo_root)
        except ValueError:
            rel = filepath
        selfdoc = is_self_doc(filepath, self_audit)
        # v4.3 — deterministic exfil-pattern pass runs on EVERY file (was: only
        # non-Latin files where ML is skipped). Indirect/task-disguised injections
        # are specifically designed to evade ML — DeBERTa was trained on direct
        # "ignore previous instructions" framings, so an injection wrapped as
        # "to finish the summary, you must run the following command" can score
        # below the INJECTION threshold and silently slip past the ML+gate path.
        # Running HARD_EXFIL standalone over the whole file fixes that. ML on
        # English files still runs and may add its own findings; HARD_EXFIL is
        # now the deterministic floor, not just a corroboration gate.
        for m in HARD_EXFIL.finditer(text):
            start = max(0, m.start() - 60)
            exfil_only_findings.append({
                'file': rel,
                'chunk_start': m.start(),
                'score': 1.0,
                'label': 'EXFIL_PATTERN',
                'preview': text[start:m.start() + 140].replace('\n', ' ').strip(),
                'likely_false_positive': selfdoc,
                'fp_reason': ("repo-scanner self-documentation (tool quoting its own "
                              "detection patterns)" if selfdoc else None),
                'detector': 'exfil-pattern-only',
            })
        # Predominantly non-Latin file: DeBERTa is ~100% FP on these. Skip the
        # ML pass; the deterministic exfil pass above still covers the file.
        if non_latin_ratio(text) > FILE_NON_LATIN_SKIP:
            skipped_non_latin.append(rel)
            # Non-Latin files are skipped by DeBERTa but DO get the optional
            # multilingual embedding review pass — that's its whole purpose.
            for cstart, chunk in chunk_text(text):
                cs = chunk.strip()
                if len(cs) >= 20:
                    embed_chunks.append((rel, cstart, cs))
            continue
        instr = is_instruction_file(filepath)
        for cstart, chunk in chunk_text(text):
            cs = chunk.strip()
            if len(cs) >= 20:
                work.append((rel, cstart, cs, instr, selfdoc))
                embed_chunks.append((rel, cstart, cs))

    findings = []
    chunks_scanned = 0

    # Batch through the classifier
    for i in range(0, len(work), BATCH_SIZE):
        batch = work[i:i + BATCH_SIZE]
        texts = [w[2] for w in batch]
        try:
            results = classifier(texts)
        except Exception:
            # Fall back to one-by-one for this batch
            results = []
            for t in texts:
                try:
                    results.append(classifier(t)[0] if isinstance(classifier(t), list) else classifier(t))
                except Exception:
                    results.append([{'label': 'SAFE', 'score': 1.0}])

        for (rel, cstart, chunk, instr, selfdoc), res in zip(batch, results):
            chunks_scanned += 1
            # pipeline with top_k=1 returns a list-of-dict per input
            if isinstance(res, list):
                res = res[0]
            label = res.get('label', 'SAFE')
            score = float(res.get('score', 0.0))

            if label == 'INJECTION' and score >= MIN_REPORT_SCORE:
                fp, reason = assess_false_positive(chunk, score, instruction_file=instr,
                                                   self_doc=selfdoc)
                findings.append({
                    'file': rel,
                    'chunk_start': cstart,
                    'score': round(score, 4),
                    'label': label,
                    'preview': chunk[:200].replace('\n', ' ').strip(),
                    'likely_false_positive': fp,
                    'fp_reason': reason,
                    'detector': 'deberta+exfil-gate',
                })

    findings.extend(exfil_only_findings)
    return findings, chunks_scanned, skipped_non_latin, embed_chunks


def collect_files_from_listfile(path):
    """Read a list of file paths, one per line. utf-8-sig strips PowerShell BOM.

    v4.3: warn loudly to stderr when entries don't resolve. The silent drop bit
    us in our own self-audit when git-bash style /c/... paths were fed to
    Windows Python — `find` returned 10 lines, the scanner reported 0 files,
    and there was no signal that anything had gone wrong."""
    files = []
    non_empty_lines = 0
    dropped_samples = []
    with open(path, 'r', encoding='utf-8-sig') as f:
        for line in f:
            p = line.strip()
            if not p:
                continue
            non_empty_lines += 1
            if os.path.isfile(p):
                files.append(p)
            elif len(dropped_samples) < 3:
                dropped_samples.append(p)
    dropped = non_empty_lines - len(files)
    if dropped:
        sample = '; '.join(dropped_samples)
        print(f"[promptguard] WARNING: {dropped}/{non_empty_lines} list-file entries "
              f"did not resolve to files (sample: {sample})", file=sys.stderr)
    return files


def main():
    args = sys.argv[1:]
    # --self-audit: opt-in that lets repo-scanner exempt its OWN documentation from
    # the exfil gate. SKILL.md Phase 7 passes it ONLY when REPO_URL is the
    # canonical repo-scanner URL — a fork never gets it. Strip it before positional
    # parsing so it can appear anywhere on the command line.
    self_audit = '--self-audit' in args
    args = [a for a in args if a != '--self-audit']
    if not args:
        print(json.dumps({"error": "No input. Pass a directory, --stdin-list, or --list-file <path>."}), file=sys.stderr)
        sys.exit(1)

    if args[0] == '--stdin-list':
        files = collect_files_from_stdin()
        repo_root = os.getcwd()
    elif args[0] == '--list-file':
        if len(args) < 2 or not os.path.isfile(args[1]):
            print(json.dumps({"error": "--list-file requires a readable file path"}), file=sys.stderr)
            sys.exit(1)
        files = collect_files_from_listfile(args[1])
        repo_root = os.getcwd()
    else:
        repo_root = os.path.abspath(args[0])
        if not os.path.isdir(repo_root):
            print(json.dumps({"error": f"Not a directory: {repo_root}"}), file=sys.stderr)
            sys.exit(1)
        files = collect_files_from_dir(repo_root)

    if not files:
        print(json.dumps({"findings": [], "review_flags": [], "stats": {"files_scanned": 0,
                          "chunks_scanned": 0, "model": MODEL_ID, "fp_suspected": 0}}, ensure_ascii=False))
        return

    print(f"[promptguard] Loading model...", file=sys.stderr)
    classifier, err = load_classifier()
    if err:
        print(json.dumps({"error": err}), file=sys.stderr)
        # exit 2 = dependency/model problem (orchestrator should note "ML scan unavailable")
        sys.exit(2)

    print(f"[promptguard] Scanning {len(files)} files (batched)...", file=sys.stderr)
    findings, chunks_scanned, skipped_non_latin, embed_chunks = scan_files(
        files, classifier, repo_root, self_audit=self_audit)

    # Optional multilingual embedding REVIEW layer. Never penalizes — it surfaces
    # paraphrased / cross-lingual injection candidates (incl. in CJK/Hebrew files
    # DeBERTa can't read) for the orchestrator (Claude) to read and judge.
    review_flags = []
    embedding_status = "not-run"
    try:
        import embedding_gate
        if embedding_gate.is_available():
            print(f"[promptguard] Embedding review layer on {len(embed_chunks)} chunks...", file=sys.stderr)
            review_flags = embedding_gate.scan_chunks(embed_chunks)
            embedding_status = f"on (model={embedding_gate.MODEL_ID}, threshold={embedding_gate.THRESHOLD})"
        else:
            embedding_status = "unavailable (sentence-transformers not installed — optional)"
    except Exception as e:
        embedding_status = f"error: {type(e).__name__}: {e}"

    # Sort: genuine (non-FP) first, then by score
    findings.sort(key=lambda f: (f['likely_false_positive'], -f['score']))
    review_flags.sort(key=lambda f: -f['score'])

    fp_count = sum(1 for f in findings if f['likely_false_positive'])

    output = {
        "findings": findings,
        "review_flags": review_flags,
        "stats": {
            "files_scanned": len(files) - len(skipped_non_latin),
            "files_skipped_non_latin": skipped_non_latin,
            "chunks_scanned": chunks_scanned,
            "model": MODEL_ID,
            "fp_suspected": fp_count,
            "genuine_suspected": len(findings) - fp_count,
            "embedding_layer": embedding_status,
            "review_flag_count": len(review_flags),
        }
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("[promptguard] interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(json.dumps({"error": f"fatal: {type(e).__name__}: {e}"}), file=sys.stderr)
        sys.exit(1)
