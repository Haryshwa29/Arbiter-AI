<#
Arbiter bootstrap installer — Windows

Deliberately short so you can read all of it before running. It:

  1. checks for Python 3.10+ (offers winget if missing)
  2. downloads the release zipapp and SHA256SUMS from GitHub Releases
  3. verifies the checksum
  4. hands over to the real installer inside the zipapp

Do not pipe this from the internet into PowerShell. Arbiter's own triage
engine flags remote-script-execution as an attack pattern; we are not going
to ask you to do what we flag. Download, read, then run:

  Invoke-WebRequest https://github.com/Haryshwa29/arbiter/releases/latest/download/install.ps1 -OutFile install.ps1
  notepad install.ps1
  powershell -ExecutionPolicy Bypass -File install.ps1

Extra arguments pass through to the installer:
  .\install.ps1 -InstallerArgs '--dry-run'
  .\install.ps1 -InstallerArgs '--scope user --port 9000 --backend mock'
#>

[CmdletBinding()]
param(
    [string]$Repo = $env:ARBITER_REPO,
    [string]$BaseUrl = $env:ARBITER_BASE_URL,
    [string]$InstallerArgs = ""
)

$ErrorActionPreference = "Stop"

if (-not $Repo)    { $Repo = "Haryshwa29/arbiter" }
if (-not $BaseUrl) { $BaseUrl = "https://github.com/$Repo/releases/latest/download" }

$workdir = Join-Path ([System.IO.Path]::GetTempPath()) ("arbiter-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workdir -Force | Out-Null

try {
    # --- 1. Python ----------------------------------------------------------
    function Find-Python {
        foreach ($candidate in @("python", "python3", "py")) {
            $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
            if (-not $cmd) { continue }
            try {
                & $candidate -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)" 2>$null
                if ($LASTEXITCODE -eq 0) { return $candidate }
            } catch { }
        }
        return $null
    }

    $python = Find-Python
    if (-not $python) {
        Write-Host "Python 3.10 or newer is required and was not found."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $answer = Read-Host "Install Python now with winget? [Y/n]"
            if ($answer -eq "" -or $answer -match '^[Yy]') {
                winget install --id Python.Python.3.12 --source winget --accept-package-agreements --accept-source-agreements
                Write-Host "Python installed. Close and reopen PowerShell, then re-run this script."
            }
        } else {
            Write-Host "Install it from https://www.python.org/downloads/ and re-run this script."
        }
        exit 1
    }
    Write-Host "Using $(& $python --version)"

    # --- 2. Download --------------------------------------------------------
    Write-Host "Downloading Arbiter from $BaseUrl ..."
    $sumsPath = Join-Path $workdir "SHA256SUMS"
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing

    # Version is discovered from the checksum file, not hardcoded.
    $pyzLine = Get-Content $sumsPath | Where-Object { $_ -match '\.pyz\s*$' } | Select-Object -First 1
    if (-not $pyzLine) { throw "no .pyz listed in SHA256SUMS" }
    $parts    = $pyzLine -split '\s+'
    $expected = $parts[0]
    $pyzName  = $parts[-1]

    $pyzPath = Join-Path $workdir $pyzName
    Invoke-WebRequest -Uri "$BaseUrl/$pyzName" -OutFile $pyzPath -UseBasicParsing

    # --- 3. Verify ----------------------------------------------------------
    $actual = (Get-FileHash -Path $pyzPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        Write-Host "CHECKSUM MISMATCH - refusing to run this file."
        Write-Host "  expected $expected"
        Write-Host "  actual   $actual"
        Write-Host "The download was corrupted or tampered with. Nothing was installed."
        exit 1
    }
    Write-Host "Checksum verified: $pyzName"

    # --- 4. Hand off --------------------------------------------------------
    Write-Host ""
    $argList = @($pyzPath, "--install")
    if ($InstallerArgs) { $argList += ($InstallerArgs -split '\s+') }
    & $python @argList
    exit $LASTEXITCODE
}
finally {
    Remove-Item -Recurse -Force $workdir -ErrorAction SilentlyContinue
}
