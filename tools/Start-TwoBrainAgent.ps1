param(
    [string]$StateDirectory = (Join-Path $PSScriptRoot '..\work\qwen-gemma-final-agent'),
    [int]$ReviewSeconds = 180
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$policyFile = Join-Path $repositoryRoot 'samples\two-brain-final-review.policy.json'
Push-Location -LiteralPath $repositoryRoot
try {
    & python -m arbiter agent --state-dir $StateDirectory --backend ollama --model 'qwen3.5:4b' --l2-model 'gemma4:12b' --l2-final-review --l2-review-seconds $ReviewSeconds --l2-policy $policyFile
    if ($LASTEXITCODE -ne 0) { throw 'The two-brain agent stopped with an error.' }
}
finally { Pop-Location }
