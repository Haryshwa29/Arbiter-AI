param([Parameter(Mandatory=$true)][string]$ReleaseDirectory)
$ErrorActionPreference = 'Stop'
$taskRepo = Split-Path $PSScriptRoot
$taskApp = Join-Path $env:USERPROFILE 'Arbiter AI'
$taskPayload = Join-Path $taskApp 'backend-repair'
New-Item -ItemType Directory -Path $taskPayload -Force | Out-Null
foreach ($taskName in @('arbiter-0.1.0.pyz','SHA256SUMS','Repair-Backend.ps1')) {
    Copy-Item -LiteralPath (Join-Path $ReleaseDirectory $taskName) -Destination (Join-Path $taskPayload $taskName) -Force
}
$taskCompiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskExe = Join-Path $taskApp 'Finish Arbiter Update.exe'
& $taskCompiler /nologo /target:exe /platform:x64 /reference:System.Windows.Forms.dll ('/win32manifest:' + (Join-Path $taskRepo 'packaging\BackendRepairLauncher.manifest')) ('/out:' + $taskExe) (Join-Path $taskRepo 'packaging\BackendRepairLauncher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Repair app compilation failed.' }
$taskShell = New-Object -ComObject WScript.Shell
$taskLink = $taskShell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Finish Arbiter Update.lnk'))
$taskLink.TargetPath = $taskExe
$taskLink.Arguments = ''
$taskLink.WorkingDirectory = $taskApp
$taskLink.Description = 'Apply the prepared Arbiter backend repair with a visible progress window'
$taskLink.Save()
Write-Output $taskExe
