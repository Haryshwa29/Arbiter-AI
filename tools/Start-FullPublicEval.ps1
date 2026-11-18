param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\output\public-eval\ait-ads-full-2026-11-18')
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$pythonPath = (Get-Command python -ErrorAction Stop).Source
$runnerPath = Join-Path $PSScriptRoot 'full_public_eval.py'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $outputPath "runner-$stamp.log"
$errorPath = Join-Path $outputPath "runner-$stamp-errors.log"
$worker = Start-Process -FilePath $pythonPath -ArgumentList @('-u', ('"' + $runnerPath + '"'), '--out', ('"' + $outputPath + '"')) -WorkingDirectory $repositoryRoot -WindowStyle Hidden -RedirectStandardOutput $logPath -RedirectStandardError $errorPath -PassThru
[pscustomobject]@{Pid=$worker.Id;Output=$outputPath;Log=$logPath;Errors=$errorPath} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputPath 'worker.json')
Write-Output "Full public-data worker started (process $($worker.Id)). Progress: $outputPath\progress.json"
