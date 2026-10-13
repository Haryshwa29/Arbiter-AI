# Explicit provisioning only. Arbiter's monitoring runtime never downloads tools.
[CmdletBinding()]
param([switch]$InventoryOnly, [switch]$SysmonOnly)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules') + ';' + $env:PSModulePath
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'This setup currently supports Windows x64 only.' }
$toolRoot = Join-Path $env:LOCALAPPDATA 'Arbiter\tools'
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
$expected = '7bd411050ef6b5aae1b23956aec0dc5ce6e800c5656f0cd463ac70a6e1bdf30b'

if (-not $SysmonOnly) {
    $osquery = Join-Path $toolRoot 'osquery\osqueryi.exe'
    if (-not (Test-Path -LiteralPath $osquery)) {
        $archive = Join-Path $toolRoot 'osquery-5.23.1.zip'
        Invoke-WebRequest 'https://github.com/osquery/osquery/releases/download/5.23.1/osquery-5.23.1.windows_x86_64.zip' -OutFile $archive
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'osquery checksum mismatch.' }
        Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $toolRoot 'osquery') -Force
        $payload = Join-Path $toolRoot 'osquery\osquery-5.23.1.windows_x86_64\Program Files\osquery'
        Copy-Item -Path (Join-Path $payload '*') -Destination (Join-Path $toolRoot 'osquery') -Recurse -Force
        if (-not (Test-Path -LiteralPath $osquery)) { throw 'osquery executable missing from verified archive.' }
    }
    & $osquery --json --disable_extensions=true 'SELECT hostname FROM system_info;'
    if ($LASTEXITCODE -ne 0) { throw 'osquery inventory check failed.' }
    Write-Output 'osquery ready. Arbiter discovers this installation automatically.'
}

if (-not $InventoryOnly) {
    $admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        $args = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -SysmonOnly'
        $installer = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $args -Wait -PassThru
        if ($installer.ExitCode -ne 0) { throw 'Elevated monitoring setup failed.' }
        Write-Output 'Monitoring tools installed with Windows administrator approval.'
        exit 0
    }
    # System services require a protected installation rather than user-writable binaries.
    $systemTools = Join-Path $env:ProgramFiles 'Arbiter\tools'
    $systemQuery = Join-Path $systemTools 'osquery\osqueryi.exe'
    if (-not (Test-Path -LiteralPath $systemQuery)) {
        New-Item -ItemType Directory -Force -Path $systemTools | Out-Null
        $systemArchive = Join-Path $systemTools 'osquery-5.23.1.zip'
        Invoke-WebRequest 'https://github.com/osquery/osquery/releases/download/5.23.1/osquery-5.23.1.windows_x86_64.zip' -OutFile $systemArchive
        if ((Get-FileHash -LiteralPath $systemArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'System osquery checksum mismatch.' }
        $stage = Join-Path $systemTools 'osquery'
        Expand-Archive -LiteralPath $systemArchive -DestinationPath $stage -Force
        $payload = Join-Path $stage 'osquery-5.23.1.windows_x86_64\Program Files\osquery'
        Copy-Item -Path (Join-Path $payload '*') -Destination $stage -Recurse -Force
        if (-not (Test-Path -LiteralPath $systemQuery)) { throw 'System osquery executable missing.' }
    }
    $existing = Get-Service -Name 'Sysmon','Sysmon64' -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Output 'Existing Sysmon installation preserved; its administrator configuration is unchanged.'
    } else {
        $directory = Join-Path $systemTools 'sysmon'
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
        $feature = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction SilentlyContinue
        if ($feature) {
            if ($feature.State -ne 'Enabled') {
                $enabled = Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -NoRestart -LimitAccess
                if ($enabled.RestartNeeded) { throw 'Windows requires a restart to finish enabling built-in Sysmon. No restart was performed.' }
            }
            $executable = Join-Path $env:SystemRoot 'System32\Sysmon.exe'
            if (-not (Test-Path -LiteralPath $executable)) { throw 'Built-in Sysmon executable is unavailable after enabling its feature.' }
            Write-Output 'Using Windows built-in Sysmon.'
        } else {
            $archive = Join-Path $systemTools 'Sysmon.zip'
            Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $archive
            Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
            $executable = Join-Path $directory 'Sysmon64.exe'
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $executable
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Sysmon Microsoft signature verification failed.' }
        $config = Join-Path $directory 'arbiter-sysmon.xml'
        @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>sha256</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <NetworkConnect onmatch="exclude">
      <DestinationIp condition="is">127.0.0.1</DestinationIp>
      <DestinationIp condition="is">::1</DestinationIp>
    </NetworkConnect>
    <DnsQuery onmatch="exclude" />
  </EventFiltering>
</Sysmon>
'@ | Set-Content -LiteralPath $config -Encoding UTF8
        $installArgs = '-accepteula -i "' + $config + '"'
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            $install = Start-Process -FilePath $executable -ArgumentList $installArgs -WorkingDirectory $directory -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $directory "install-output-$attempt.log") -RedirectStandardError (Join-Path $directory "install-error-$attempt.log")
            if ($install.ExitCode -eq 0) { break }
            # Some Windows builds fail their first event-manifest registration.
            if (Get-Service -Name 'Sysmon','Sysmon64' -ErrorAction SilentlyContinue) { break }
        }
        if ($install.ExitCode -ne 0) { throw "Sysmon installation failed; inspect logs under $directory." }
        Write-Output 'Sysmon ready: process creation, network connections and DNS queries.'
    }
}
Write-Output 'Microsoft Defender is built in; Arbiter reads detections without changing its settings.'
