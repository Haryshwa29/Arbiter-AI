# Arbiter - local model head-to-head (Qwen vs Gemma)
#
# From PowerShell, in the project folder:
#     powershell -ExecutionPolicy Bypass -File tools\run_comparison.ps1
#
# Optional: compare a different set
#     ... -File tools\run_comparison.ps1 -Models "qwen3.5:4b,gemma4:26b"
#
# Defaults to qwen3.5:4b vs gemma4:12b - the exact pair recorded in
# .claude/settings.local.json, i.e. the original comparison.
#
# Suite is samples/model_gauntlet.jsonl: 22 cases, every one verified
# guardrail-invisible, so the model decides all of them. That is the only
# place "which model is better" is actually measurable.
#
# NOTE: this file must stay pure ASCII. Windows PowerShell 5.1 reads a
# BOM-less .ps1 as Windows-1252, and a UTF-8 em dash decodes to a smart
# quote that the parser treats as a real string delimiter.

param(
    [string]$Models = "qwen3.5:4b,gemma4:12b",
    [string]$Suites = "samples/model_gauntlet.jsonl",
    [int]$Runs = 3
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Stamp  = Get-Date -Format "yyyy-MM-dd-HHmm"
$OutDir = Join-Path $Root "evals\$Stamp"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Log = Join-Path $OutDir "console.log"

function Say($msg) { Write-Host $msg; Add-Content -Path $Log -Value $msg }

Say "=== Arbiter model comparison - $Stamp ==="
Say "repo:   $Root"
Say "models: $Models"
Say "suites: $Suites"
Say "runs:   $Runs"

# --- python ---------------------------------------------------------------
$Py = $null
foreach ($cand in @("python", "py", "python3")) {
    try {
        $v = & $cand --version 2>&1
        if ($LASTEXITCODE -eq 0) { $Py = $cand; Say "python: $cand ($v)"; break }
    } catch { }
}
if (-not $Py) {
    Say "ERROR: no python found on PATH."
    Read-Host "Press Enter to exit"
    exit 1
}

# --- ollama ---------------------------------------------------------------
Say ""
Say "--- ollama list ---"
$list = & ollama list 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Say "ERROR: ollama not on PATH, or the daemon is not running."
    Say "Start the Ollama app, then re-run this script."
    Read-Host "Press Enter to exit"
    exit 1
}
Say $list
Set-Content -Path (Join-Path $OutDir "ollama-list.txt") -Value $list

# --- the run --------------------------------------------------------------
# 3 runs each: a sampling model that is right once may not be right three
# times. A flaky ATTACK case is a latent miss and counts as a failure.
Say ""
Say "--- comparison ($Runs runs each, guardrails on) ---"
Say "Expect roughly 20 minutes. Quiet gaps are inference, not a hang."
Say ""

& $Py "tools\model_compare.py" `
    --models $Models `
    --suites $Suites `
    --runs $Runs `
    --out $OutDir 2>&1 | Tee-Object -FilePath $Log -Append

Say ""
Say "=== done ==="
Say "results in: $OutDir"
Say "  comparison.md   <- the readable table"
Say "  results.json    <- raw, digest-stamped"
Say "  ollama-list.txt <- what was installed at run time"
Say ""
Say "Tell Claude it finished - it can read these from the project folder."
Read-Host "Press Enter to close"
