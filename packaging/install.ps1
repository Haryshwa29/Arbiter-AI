<#
Arbiter AI Windows installer bootstrap.

Run this downloaded file, or use Install Arbiter.exe. It selects a safe mode
from the computer's RAM and free disk space, shows the choice, verifies the
Arbiter release checksum, and hands installation to the inspectable Python
installer inside the release. When launched from the portable bundle it uses
the bundled Python, Ollama, and model without downloading them.
#>

[CmdletBinding()]
param(
    [string]$Repo = $env:ARBITER_REPO,
    [string]$BaseUrl = $env:ARBITER_BASE_URL,
    [ValidateSet("ask", "auto", "local", "rules")]
    [string]$Mode = "ask",
    [ValidateSet("user", "system")]
    [string]$Scope = "user",
    [int]$Port = 8787,
    [string]$PortableRoot = "",
    [string]$InstallerArgs = ""
)

$ErrorActionPreference = "Stop"
if (-not $Repo) { $Repo = "Haryshwa29/Arbiter-AI" }
if (-not $BaseUrl) { $BaseUrl = "https://github.com/$Repo/releases/latest/download" }

function Find-Python {
    foreach ($candidate in @("python", "python3", "py")) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            & $candidate -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        } catch { }
    }
    $found = Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -Filter python.exe -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

function Find-Ollama {
    $cmd = Get-Command ollama.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $standard = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
    if (Test-Path $standard) { return $standard }
    return $null
}

function Confirm-Step([string]$Question) {
    $answer = Read-Host "$Question [Y/n]"
    return ($answer -eq "" -or $answer -match '^[Yy]')
}

function Get-Sha256([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace("-", "").ToLower()
    } finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Arbiter currently requires 64-bit Windows."
}
$os = [Environment]::OSVersion.Version
if ($os.Major -lt 10 -or ($os.Major -eq 10 -and $os.Build -lt 19045)) {
    throw "Arbiter requires Windows 10 22H2 (build 19045) or newer."
}
try {
    $ramBytes = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
} catch {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $computer = New-Object Microsoft.VisualBasic.Devices.ComputerInfo
    $ramBytes = $computer.TotalPhysicalMemory
}
$ramGB = [math]::Round($ramBytes / 1GB, 1)
$installBase = if ($Scope -eq "system") {
    Join-Path $env:ProgramData "Arbiter"
} else {
    Join-Path $env:LOCALAPPDATA "Arbiter"
}
$drive = New-Object System.IO.DriveInfo([IO.Path]::GetPathRoot($installBase))
$freeGB = [math]::Round($drive.AvailableFreeSpace / 1GB, 1)
$localCompatible = $ramGB -ge 8 -and $freeGB -ge 8
$explicitMode = $Mode -ne "ask" -and $Mode -ne "auto"

Write-Host ""
Write-Host "Arbiter AI Setup"
Write-Host "  Windows       $($os.Major).$($os.Minor) build $($os.Build) (64-bit)"
Write-Host "  Memory        $ramGB GB"
Write-Host "  Free disk     $freeGB GB"
Write-Host "  Install path  $installBase"
Write-Host ""

if ($Mode -eq "ask") {
    if ($localCompatible) {
        Write-Host "  [1] Local AI - Qwen 3.5 4B (recommended for this computer)"
        Write-Host "  [2] Rules only - smaller install, no local-model reasoning"
    } else {
        Write-Host "  [1] Rules only (recommended for this computer)"
        Write-Host "  [2] Local AI - Qwen 3.5 4B (requires at least 8 GB RAM and 8 GB free)"
    }
    $selection = Read-Host "Choose 1 or 2 [1]"
    if (-not $selection) { $selection = "1" }
    $Mode = if ($localCompatible) {
        if ($selection -eq "2") { "rules" } else { "local" }
    } else {
        if ($selection -eq "2") { "local" } else { "rules" }
    }
} elseif ($Mode -eq "auto") {
    $Mode = if ($localCompatible) { "local" } else { "rules" }
}

if ($Mode -eq "local" -and -not $localCompatible -and -not $explicitMode) {
    Write-Warning "This computer is below the recommended local-model requirements."
    if (-not (Confirm-Step "Continue with Local AI anyway?")) { exit 1 }
}

$workdir = Join-Path ([System.IO.Path]::GetTempPath()) ("arbiter-setup-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workdir -Force | Out-Null

try {
    $portable = $PortableRoot -and
        (Test-Path (Join-Path $PortableRoot "app\arbiter.pyz")) -and
        (Test-Path (Join-Path $PortableRoot "runtime\python\python.exe"))

    if ($portable) {
        Write-Host "Using dependencies from the portable drive."
        $build = Get-Content (Join-Path $PortableRoot "BUILD.json") -Raw | ConvertFrom-Json
        $appHash = Get-Sha256 (Join-Path $PortableRoot "app\arbiter.pyz")
        $ollamaHash = Get-Sha256 (Join-Path $PortableRoot "runtime\ollama\ollama.exe")
        if ($appHash -ne $build.release_sha256 -or $ollamaHash -ne $build.ollama_exe_sha256) {
            throw "Portable application or local-AI runtime checksum mismatch."
        }
        Write-Host "Portable application checksums verified."
        $pythonTarget = Join-Path $installBase "runtime\python"
        New-Item -ItemType Directory -Path $pythonTarget -Force | Out-Null
        Copy-Item (Join-Path $PortableRoot "runtime\python\*") $pythonTarget -Recurse -Force
        $python = Join-Path $pythonTarget "python.exe"
        $pyzPath = Join-Path $PortableRoot "app\arbiter.pyz"
    } else {
        $python = Find-Python
        if (-not $python) {
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                throw "Python 3.10+ is missing and Windows Package Manager is unavailable."
            }
            if (-not (Confirm-Step "Install Python 3.12 with Windows Package Manager?")) { exit 1 }
            winget install --id Python.Python.3.12 --exact --source winget --accept-package-agreements --accept-source-agreements
            if ($LASTEXITCODE -ne 0) { throw "Python installation failed." }
            $python = Find-Python
            if (-not $python) { throw "Python installed but could not be located. Restart Windows and run setup again." }
        }

        Write-Host "Downloading Arbiter from $BaseUrl ..."
        $sumsPath = Join-Path $workdir "SHA256SUMS"
        Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
        $pyzLine = Get-Content $sumsPath | Where-Object { $_ -match '\.pyz\s*$' } | Select-Object -First 1
        if (-not $pyzLine) { throw "No Arbiter release is listed in SHA256SUMS." }
        $parts = $pyzLine -split '\s+'
        $expected = $parts[0]
        $pyzName = $parts[-1]
        $pyzPath = Join-Path $workdir $pyzName
        Invoke-WebRequest -Uri "$BaseUrl/$pyzName" -OutFile $pyzPath -UseBasicParsing
        $actual = Get-Sha256 $pyzPath
        if ($actual -ne $expected.ToLower()) {
            throw "Arbiter checksum mismatch. Nothing was installed."
        }
        Write-Host "Checksum verified: $pyzName"
    }

    $arguments = @($pyzPath, "--install", "--scope", $Scope, "--port", $Port, "--yes")
    if ($Mode -eq "local") {
        if ($portable) {
            $ollamaSource = Join-Path $PortableRoot "runtime\ollama"
            $modelsSource = Join-Path $PortableRoot "models"
            if (-not (Test-Path (Join-Path $ollamaSource "ollama.exe")) -or
                -not (Test-Path $modelsSource)) {
                throw "The portable Local AI payload is incomplete."
            }
            $arguments += @("--backend", "ollama", "--model", "qwen3.5:4b",
                            "--bundled-ollama-dir", $ollamaSource,
                            "--bundled-models-dir", $modelsSource)
        } else {
            $ollama = Find-Ollama
            if (-not $ollama) {
                if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                    throw "Ollama is missing and Windows Package Manager is unavailable."
                }
                if (-not (Confirm-Step "Install Ollama for local AI?")) { exit 1 }
                winget install --id Ollama.Ollama --exact --source winget --accept-package-agreements --accept-source-agreements
                if ($LASTEXITCODE -ne 0) { throw "Ollama installation failed." }
                $ollama = Find-Ollama
                if (-not $ollama) { throw "Ollama installed but could not be located. Restart Windows and run setup again." }
            }
            $env:PATH = (Split-Path $ollama) + ";" + $env:PATH
            $arguments += @("--backend", "ollama", "--model", "qwen3.5:4b")
        }
    } else {
        $arguments += @("--backend", "mock")
    }
    if ($InstallerArgs) { $arguments += ($InstallerArgs -split '\s+') }

    & $python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Arbiter installation did not complete." }
    $skipService = $InstallerArgs -match '(^|\s)--no-service(\s|$)'
    if (-not $skipService) {
        $shortcutDir = Join-Path ([Environment]::GetFolderPath("Programs")) "Arbiter AI"
        New-Item -ItemType Directory -Path $shortcutDir -Force | Out-Null
        @("[InternetShortcut]", "URL=http://127.0.0.1:$Port") |
            Set-Content (Join-Path $shortcutDir "Open Arbiter Dashboard.url") -Encoding ASCII
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while ([DateTime]::UtcNow -lt $deadline) {
            $client = New-Object Net.Sockets.TcpClient
            try {
                $client.Connect("127.0.0.1", $Port)
                break
            } catch {
                Start-Sleep -Milliseconds 500
            } finally {
                $client.Dispose()
            }
        }
        Start-Process "http://127.0.0.1:$Port"
    }
    Write-Host "Setup completed. Arbiter will also start automatically when you sign in."
    exit 0
}
finally {
    Remove-Item -Recurse -Force $workdir -ErrorAction SilentlyContinue
}
