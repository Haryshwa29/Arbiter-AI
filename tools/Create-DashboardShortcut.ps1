# LocalAppData writes from the packaged Codex host can be MSIX-virtualized.
# A normal user-profile folder is also visible to Explorer and the launcher.
param([string]$OutputDirectory = (Join-Path $env:USERPROFILE 'Arbiter AI'))
$ErrorActionPreference = 'Stop'
$taskRepo = Split-Path $PSScriptRoot
$taskCompiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $taskCompiler)) { throw 'Windows .NET Framework compiler is unavailable.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$taskExe = Join-Path $OutputDirectory 'Arbiter AI.exe'
& $taskCompiler /nologo /target:winexe /platform:x64 /reference:System.Windows.Forms.dll ('/out:' + $taskExe) (Join-Path $taskRepo 'packaging\DashboardLauncher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Could not build the dashboard application.' }
$taskShell = New-Object -ComObject WScript.Shell
foreach ($taskFolder in @([Environment]::GetFolderPath('Desktop'), (Join-Path ([Environment]::GetFolderPath('Programs')) 'Arbiter AI'))) {
    New-Item -ItemType Directory -Path $taskFolder -Force | Out-Null
    $taskShortcut = $taskShell.CreateShortcut((Join-Path $taskFolder 'Arbiter AI.lnk'))
    $taskShortcut.TargetPath = $taskExe
    $taskShortcut.WorkingDirectory = $OutputDirectory
    $taskShortcut.Description = 'Open your local Arbiter AI security dashboard'
    $taskShortcut.IconLocation = $taskExe + ',0'
    $taskShortcut.Save()
}
Write-Output $taskExe
