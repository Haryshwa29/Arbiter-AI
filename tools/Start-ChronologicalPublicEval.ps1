param(
    [Parameter(Mandatory=$true)][string]$RunDirectory,
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [switch]$Resume,
    [switch]$LeaveDashboardStopped,
    [switch]$Timed,
    [ValidateRange(1,36000)][int]$DurationSeconds = 36000
)
# Run elevated: only the installed Arbiter task needs administrator access.
$ErrorActionPreference = 'Stop'
$taskRun = [System.IO.Path]::GetFullPath($RunDirectory)
$taskRunner = Join-Path $taskRun $(if ($Timed) {'timed_eval.py'} else {'run_eval.py'})
$taskResult = Join-Path $taskRun 'supervisor.json'
$taskChild = $null
$taskPauseAttempted = $false
$taskDisabled = $false
$taskOriginallyEnabled = $false
$taskLogs = Join-Path $taskRun ('attempts\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $taskLogs -Force | Out-Null
$taskState = @{ status = 'checking'; started_utc = [DateTime]::UtcNow.ToString('o'); supervisor_pid = $PID }
function Save-State {
    $taskState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $taskResult -Encoding UTF8
    $taskState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $taskLogs 'supervisor.json') -Encoding UTF8
}
function Invoke-ArbiterTask($taskAction, $taskLog) {
    $taskArguments = @($taskAction,'/TN','Arbiter')
    if ($taskAction -in @('/Disable','/Enable')) { $taskArguments = @('/Change','/TN','Arbiter',$taskAction) }
    if ($taskAction -eq '/Query') { $taskArguments += '/XML' }
    $taskCommand = Start-Process -FilePath 'schtasks.exe' -ArgumentList $taskArguments -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $taskLogs ($taskLog + '.log')) -RedirectStandardError (Join-Path $taskLogs ($taskLog + '-errors.log'))
    return $taskCommand.ExitCode
}
function Dashboard-Listening {
    return @([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object {$_.Port -eq 8787}).Count -gt 0
}
try {
    if (-not (Test-Path -LiteralPath $taskRunner -PathType Leaf)) { throw 'Prepared benchmark is missing' }
    $taskProgress = Join-Path $taskRun 'progress.json'
    if (Test-Path -LiteralPath $taskProgress) {
        $taskPrevious = Get-Content -LiteralPath $taskProgress -Raw | ConvertFrom-Json
        if (-not $Resume -or $taskPrevious.status -notin @('paused','stopped-error')) { throw 'Only a reviewed stopped or paused benchmark may resume' }
        $taskPriorProcess = Get-Process -Id $taskPrevious.pid -ErrorAction SilentlyContinue
        if ($taskPriorProcess -and $taskPriorProcess.StartTime.ToUniversalTime() -le [DateTimeOffset]::Parse($taskPrevious.updated_utc).UtcDateTime) { throw 'Previous worker process still exists; inspect its identity before resuming' }
        $taskState.resumed_from_completed = $taskPrevious.counts.completed
    } elseif ($Resume) { throw 'No checkpoint exists to resume' }
    $taskFrozen = Get-Content -LiteralPath (Join-Path $taskRun 'frozen-files.json') -Raw | ConvertFrom-Json
    foreach ($taskFile in $taskFrozen.PSObject.Properties) {
        $taskActual = (Get-FileHash -LiteralPath (Join-Path $taskRun $taskFile.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($taskActual -ne $taskFile.Value) { throw ('Frozen file changed: ' + $taskFile.Name) }
    }
    @{
        cpu = @(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors)
        ram_bytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        gpu = @(& nvidia-smi.exe --query-gpu=name,memory.total,driver_version --format=csv,noheader)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskRun 'hardware.json') -Encoding UTF8
    if ((Invoke-ArbiterTask '/Query' 'task-before') -ne 0) { throw 'Could not inspect installed task before pausing it' }
    [xml]$taskXml = Get-Content -LiteralPath (Join-Path $taskLogs 'task-before.log') -Raw
    $taskOriginallyEnabled = $taskXml.Task.Settings.Enabled -ne 'false'
    $taskState.dashboard_originally_enabled = $taskOriginallyEnabled
    $taskState.leave_dashboard_stopped = [bool]$LeaveDashboardStopped
    $taskHealthPath = 'C:\ProgramData\Arbiter\data\service-health.json'
    $taskOldPid = if (Test-Path -LiteralPath $taskHealthPath) { (Get-Content -LiteralPath $taskHealthPath -Raw | ConvertFrom-Json).pid } else { $null }
    $taskState.status = 'pausing-dashboard'; Save-State
    $taskPauseAttempted = $true
    # Ending the process alone does not pause its existing five-minute recovery trigger.
    if ((Invoke-ArbiterTask '/Disable' 'dashboard-disable') -ne 0) { throw 'Could not disable automatic dashboard recovery for this benchmark' }
    $taskDisabled = $true
    if ((Invoke-ArbiterTask '/End' 'dashboard-pause') -ne 0) { throw 'Could not pause the installed Arbiter task' }
    $taskDeadline = [DateTime]::UtcNow.AddSeconds(40)
    do {
        $taskRemaining = if ($taskOldPid) { Get-Process -Id $taskOldPid -ErrorAction SilentlyContinue } else { $null }
        if (-not $taskRemaining -and -not (Dashboard-Listening)) { break }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $taskDeadline)
    if ($taskRemaining -or (Dashboard-Listening)) { throw 'Installed service is still running; benchmark was not started' }
    Start-Sleep -Seconds 5
    $taskState.status = 'running'; $taskState.dashboard_paused_utc = [DateTime]::UtcNow.ToString('o')
    $taskGpuLog = Join-Path $taskLogs 'gpu-samples.csv'
    'utc,index,driver_version,memory_total_MiB,memory_used_MiB,utilization_percent,temperature_C' | Set-Content -LiteralPath $taskGpuLog
    $taskNextGpuSample = [DateTime]::MinValue
    $taskArgs = '"' + $taskRunner + '"' + $(if ($Timed) {' --out "' + $taskRun + '" --duration ' + $DurationSeconds} else {' run --out "' + $taskRun + '"'})
    $taskChild = Start-Process -FilePath $PythonPath -ArgumentList $taskArgs -WindowStyle Hidden -PassThru -WorkingDirectory $taskRun -RedirectStandardOutput (Join-Path $taskLogs 'worker.log') -RedirectStandardError (Join-Path $taskLogs 'worker-errors.log')
    $taskHandle = $taskChild.Handle
    $taskState.worker_pid = $taskChild.Id; Save-State
    while (-not $taskChild.WaitForExit(5000)) {
        if ([DateTime]::UtcNow -ge $taskNextGpuSample) {
            $taskGpuUtc = [DateTime]::UtcNow.ToString('o')
            try {
                & nvidia-smi.exe --query-gpu=index,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu --format=csv,noheader,nounits 2>> (Join-Path $taskLogs 'gpu-sample-errors.log') | ForEach-Object { ($taskGpuUtc + ',' + $_) | Add-Content -LiteralPath $taskGpuLog }
                if ($LASTEXITCODE -ne 0) { $taskState.gpu_sampling_error = 'nvidia-smi exit ' + $LASTEXITCODE; Save-State }
            } catch { $taskState.gpu_sampling_error = $_.Exception.Message; Save-State }
            $taskNextGpuSample = [DateTime]::UtcNow.AddSeconds(15)
        }
        if (Dashboard-Listening) {
            $taskState.isolation_lost_utc = [DateTime]::UtcNow.ToString('o')
            Set-Content -LiteralPath (Join-Path $taskRun 'STOP') -Value 'Dashboard reappeared; supervised isolation lost'
            Save-State
        }
    }
    $taskState.worker_exit_code = $taskChild.ExitCode
    $taskState.status = if ($taskChild.ExitCode -eq 0) { 'worker-finished' } else { 'worker-failed' }
} catch {
    $taskState.status = 'supervisor-failed'; $taskState.error = $_.Exception.Message
} finally {
    if ($taskPauseAttempted) {
        try {
            if ($LeaveDashboardStopped) {
                $taskState.dashboard_restart_note = 'Owner requested termination; dashboard and its recovery task remain stopped/disabled'
            } elseif ($taskOriginallyEnabled) {
                if ($taskDisabled) {
                    $taskState.dashboard_enable_exit_code = Invoke-ArbiterTask '/Enable' 'dashboard-enable'
                    if ($taskState.dashboard_enable_exit_code -ne 0) { throw 'Could not restore the enabled dashboard task' }
                }
                $taskState.dashboard_restart_exit_code = Invoke-ArbiterTask '/Run' 'dashboard-resume'
                if ($taskState.dashboard_restart_exit_code -ne 0) { throw 'Could not restart the dashboard task' }
                $taskState.dashboard_restart_requested_utc = [DateTime]::UtcNow.ToString('o')
                $taskState.dashboard_restart_note = 'Task restart requested; dashboard readiness is recorded by its normal health file'
            } else { $taskState.dashboard_restart_note = 'Original task was disabled; its disabled state was preserved' }
        } catch { $taskState.dashboard_restart_error = $_.Exception.Message }
    }
    $taskState.finished_utc = [DateTime]::UtcNow.ToString('o'); Save-State
}
if ($taskState.status -eq 'worker-finished' -and -not $taskState.ContainsKey('dashboard_restart_error')) { exit 0 }
exit 1
