# install.ps1 — repo-scanner installer for Windows (PowerShell).
#
# This actually sets things up — it is NOT just a file copy:
#   1. Copies the skill into %USERPROFILE%\.claude\skills\
#   2. Finds Python (>=3.10), creates a dedicated venv
#   3. Installs the ML dependencies (PyTorch CPU + transformers)
#   4. Downloads the injection-detection model (~750MB) — ONLY after you say yes
#   5. Records the venv path so the skill finds it on any machine
#   6. Runs the built-in self-test
#
# Usage:   .\install.ps1            (full setup)
#          .\install.ps1 -SkillOnly (copy the skill, skip the ML setup)
#
# Nothing here needs Administrator. Re-running is safe (idempotent).

param([switch]$SkillOnly)

$ErrorActionPreference = "Stop"
function Say($m, $c = "White") { Write-Host $m -ForegroundColor $c }

$RepoDir      = $PSScriptRoot
$SkillsTarget = Join-Path $env:USERPROFILE ".claude\skills"
$SkillDest    = Join-Path $SkillsTarget "repo-scanner"
$VenvDir      = Join-Path $env:LOCALAPPDATA "repo-scanner\venv"
$VenvPy       = Join-Path $VenvDir "Scripts\python.exe"

Say ""
Say "=== repo-scanner installer (Windows) ===" "Cyan"
Say ""

# --- 1. Copy the skill -------------------------------------------------------
New-Item -ItemType Directory -Force -Path $SkillsTarget | Out-Null
Get-ChildItem -Path (Join-Path $RepoDir "skills") -Directory | ForEach-Object {
    $dest = Join-Path $SkillsTarget $_.Name
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Copy-Item -Recurse -Force $_.FullName $dest
    Say "  installed skill: $($_.Name)" "Green"
}

if ($SkillOnly) {
    Say ""
    Say "Skill copied. ML scanner NOT set up (-SkillOnly)." "Yellow"
    Say "Run /repo-scanner <url> --quick  for static-only audits." "Yellow"
    Say "In Claude Code: /reload-skills" "Cyan"
    return
}

# --- 2. Find Python ----------------------------------------------------------
Say ""
Say "Looking for Python (>=3.10)..." "Cyan"
$PyExe = $null
foreach ($cand in @("python", "py")) {
    try {
        $v = & $cand -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $v) {
            $maj, $min = $v.Split('.')
            if ([int]$maj -ge 3 -and [int]$min -ge 10) { $PyExe = $cand; Say "  found Python $v ($cand)" "Green"; break }
        }
    } catch {}
}
if (-not $PyExe) {
    Say "  Python >=3.10 not found." "Red"
    Say "  Install it, then re-run this script:" "Yellow"
    Say "    winget install Python.Python.3.12" "Yellow"
    Say "  (or download from https://www.python.org/downloads/)" "Yellow"
    Say "  The skill still works without ML: /repo-scanner <url> --quick" "Yellow"
    return
}

# --- 3. Consent before the big download --------------------------------------
Say ""
Say "The ML scanner needs PyTorch + an injection-detection model." "Cyan"
Say "This downloads about 1 GB (one time) and uses ~1 GB disk." "Cyan"
$ans = Read-Host "Set it up now? [Y/n]"
if ($ans -and $ans -notmatch '^[Yy]') {
    Say "Skipped ML setup. Use --quick mode, or re-run this script later." "Yellow"
    return
}

# --- 4. Create venv + install deps -------------------------------------------
Say ""
Say "Creating venv at $VenvDir ..." "Cyan"
New-Item -ItemType Directory -Force -Path (Split-Path $VenvDir) | Out-Null
if (-not (Test-Path $VenvPy)) { & $PyExe -m venv $VenvDir }
& $VenvPy -m pip install --upgrade pip --quiet
Say "  installing PyTorch (CPU)..." "Cyan"
& $VenvPy -m pip install torch --index-url https://download.pytorch.org/whl/cpu --quiet
Say "  installing transformers + deps..." "Cyan"
& $VenvPy -m pip install -r (Join-Path $SkillDest "requirements.txt") --quiet

# --- 5. Download the model + record the venv path ----------------------------
Say ""
Say "Downloading the injection-detection model (~750MB)..." "Cyan"
$dl = @"
from transformers import AutoTokenizer, AutoModelForSequenceClassification
m = 'protectai/deberta-v3-base-prompt-injection-v2'
rev = 'e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5'
AutoTokenizer.from_pretrained(m, revision=rev)
AutoModelForSequenceClassification.from_pretrained(m, revision=rev)
print('model ready')
"@
& $VenvPy -c $dl

Set-Content -Path (Join-Path $SkillDest ".venv-path") -Value $VenvPy -Encoding UTF8 -NoNewline
Say "  recorded venv path -> $SkillDest\.venv-path" "Green"

# --- 6. Self-test ------------------------------------------------------------
Say ""
Say "Running self-test..." "Cyan"
& $VenvPy (Join-Path $SkillDest "tests\run_tests.py")

Say ""
Say "Done. In Claude Code: /reload-skills" "Cyan"
Say "Then try:  /repo-scanner https://github.com/owner/repo" "Cyan"
Say ""
Say "Optional: add multilingual injection review (~120MB) — see README 'Step 5'." "DarkGray"
