<#
.SYNOPSIS
  One-command, hands-off workstation installer for the SAIP collector. Run once in an elevated PowerShell (or as SYSTEM from GPO / Intune / SCCM).
  It installs Sysmon and proves it logs DNS, makes Chrome/Edge/Brave/Firefox visible to Sysmon (machine policy, no manual registry or browser
  settings), enrolls the PC with SAIP, schedules the collector, and prints a pass/fail summary. Safe to run again (it repairs and updates).
.PARAMETER ServerUrl         SAIP API address, e.g. https://saip.example.com/api/v1 (reachable from this PC; not 127.0.0.1 unless SAIP runs here).
.PARAMETER EnrollmentKey     Company enrollment key (Collectors & Monitoring -> New enrollment key). Omit if collector.config.json already has it.
.PARAMETER InstallDir        Where the collector lives. Default C:\Tools\SaipCollector.
.PARAMETER IntervalMinutes   How often the collector runs. Default 5.
.PARAMETER EnableNetwork     Also log outbound HTTPS network connections (Sysmon Event ID 3). Optional; turn on "Network connections" in the console too.
.PARAMETER SkipSysmon        Do not install/repair Sysmon.
.PARAMETER SkipBrowserPolicy Do not set the browser DNS policies (browsers that bypass Windows DNS will then not be visible).
.PARAMETER RestartBrowsers   Close running browsers so the policy applies immediately. Unsaved browser work is lost; the default is to let it apply at the next browser start.
.PARAMETER AllowInsecureHttp Required to use a plain http:// ServerUrl (lab only).
.EXAMPLE
  .\Install-Collector.ps1 -ServerUrl https://saip.example.com/api/v1 -EnrollmentKey enr_xxxxxxxx
#>
[CmdletBinding()]
param(
    [string]$ServerUrl,
    [string]$EnrollmentKey,
    [string]$InstallDir = 'C:\Tools\SaipCollector',
    [int]$IntervalMinutes = 5,
    [switch]$EnableNetwork,
    [switch]$SkipSysmon,
    [switch]$SkipBrowserPolicy,
    [switch]$RestartBrowsers,
    [switch]$AllowInsecureHttp
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
. (Join-Path $PSScriptRoot 'SaipCommon.ps1')
if (-not (Test-SaipAdmin)) { throw 'Run as Administrator.' }

$summary = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Check, [bool]$Ok, [string]$Detail) { $summary.Add([pscustomobject]@{ Check = $Check; Result = $(if ($Ok) { 'OK' } else { 'ATTENTION' }); Detail = $Detail }) | Out-Null }

Write-Host "[1/7] Copying the collector to $InstallDir"
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
if ((Resolve-Path $PSScriptRoot).Path -ne (Resolve-Path $InstallDir).Path) {
    # An existing installation keeps its configuration (server address and enrollment key); only the scripts are updated.
    $keep = @('Install-Collector.ps1'); if (Test-Path (Join-Path $InstallDir 'collector.config.json')) { $keep += 'collector.config.json' }
    Copy-Item -Path (Join-Path $PSScriptRoot '*') -Destination $InstallDir -Recurse -Force -Exclude $keep
    Copy-Item -Path (Join-Path $PSScriptRoot 'Install-Collector.ps1') -Destination $InstallDir -Force
}

Write-Host '[2/7] Writing the configuration'
$cfgPath = Join-Path $InstallDir 'collector.config.json'
$cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
if ($ServerUrl) { $cfg.serverUrl = $ServerUrl.Trim().TrimEnd('/') }
if ($EnrollmentKey) { $cfg.enrollmentKey = $EnrollmentKey.Trim() }
if ($cfg.serverUrl -like '*YOUR-SERVER*' -or [string]::IsNullOrWhiteSpace($cfg.serverUrl)) { throw 'ServerUrl is not set. Pass -ServerUrl or edit collector.config.json.' }
if ($cfg.enrollmentKey -like 'CHANGE-ME*' -or [string]::IsNullOrWhiteSpace($cfg.enrollmentKey)) { throw 'EnrollmentKey is not set. Pass -EnrollmentKey or edit collector.config.json.' }
if ($cfg.serverUrl -like 'http://*') {
    if (-not $AllowInsecureHttp) { throw 'ServerUrl uses plain http://. Use https://, or pass -AllowInsecureHttp for a lab.' }
    $cfg.allowInsecureHttp = $true
} else { $cfg.allowInsecureHttp = $false }
$cfg.intervalMinutes = $IntervalMinutes
$cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfgPath -Encoding UTF8
& icacls.exe $cfgPath /inheritance:r /grant:r 'SYSTEM:(F)' 'BUILTIN\Administrators:(F)' | Out-Null   # holds the enrollment key
if (-not (Test-Path $cfg.dataDir)) { New-Item -ItemType Directory -Path $cfg.dataDir -Force | Out-Null }

Write-Host '[3/7] Checking that the server is reachable'
$base = $cfg.serverUrl.TrimEnd('/')
try {
    Invoke-WebRequest -Uri "$base/collector/config" -UseBasicParsing -TimeoutSec 15 | Out-Null
    Add-Result 'SAIP server reachable' $true $base
} catch {
    $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    if ($code -in 401, 403) { Add-Result 'SAIP server reachable' $true "$base (HTTP $code is expected before enrollment)" }
    else { throw "Cannot reach $base ($($_.Exception.Message)). Check the address, DNS, firewall and proxy, then run again." }
}

if (-not $SkipSysmon) {
    Write-Host '[4/7] Installing Sysmon and verifying DNS logging'
    try {
        if ($EnableNetwork) { & (Join-Path $InstallDir 'Install-Sysmon.ps1') -EnableNetwork } else { & (Join-Path $InstallDir 'Install-Sysmon.ps1') }
        Add-Result 'Sysmon running and logging DNS' $true 'a test lookup was recorded'
    } catch {
        Add-Result 'Sysmon running and logging DNS' $false $_.Exception.Message
        Write-Warning $_.Exception.Message
    }
} else {
    Write-Host '[4/7] Skipping Sysmon'
    Add-Result 'Sysmon running and logging DNS' ((Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status -eq 'Running') 'Sysmon install skipped'
}

if (-not $SkipBrowserPolicy) {
    Write-Host '[5/7] Making browser lookups visible (Chrome, Edge, Brave, Firefox machine policy)'
    try {
        $statePath = Join-Path $cfg.dataDir 'browser-policy.json'
        $done = Set-SaipBrowserDnsPolicy -StatePath $statePath
        $running = @(Get-Process -Name chrome, msedge, brave, firefox -ErrorAction SilentlyContinue)
        if ($RestartBrowsers -and $running.Count) {
            Write-Host "      Closing $($running.Count) browser process(es) so the policy applies now"
            $running | Stop-Process -Force -ErrorAction SilentlyContinue
            Add-Result 'Browser DNS policy' $true ("set for $($done -join ', '); browsers restarted")
        } elseif ($running.Count) {
            Add-Result 'Browser DNS policy' $true ("set for $($done -join ', '); restart the open browsers (fully quit, then reopen) to apply it")
        } else {
            Add-Result 'Browser DNS policy' $true ("set for $($done -join ', '); applies at the next browser start")
        }
    } catch {
        Add-Result 'Browser DNS policy' $false $_.Exception.Message
        Write-Warning $_.Exception.Message
    }
} else {
    Write-Host '[5/7] Skipping browser DNS policy'
    Add-Result 'Browser DNS policy' $true 'skipped by request: browsers using their own resolver will not be visible'
}

Write-Host '[6/7] Enrolling this PC and running the collector once'
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $InstallDir 'Collect-AiUsage.ps1') -ConfigPath $cfgPath
Add-Result 'Collector enrolled and ran' ($LASTEXITCODE -eq 0) $(if ($LASTEXITCODE -eq 0) { 'registered with SAIP' } else { "exit code $LASTEXITCODE; see $($cfg.dataDir)\collector-error.log" })

Write-Host "[7/7] Scheduling the collector every $IntervalMinutes minute(s)"
try {
    & (Join-Path $InstallDir 'Register-ScheduledTask.ps1') -ConfigPath $cfgPath -IntervalMinutes $IntervalMinutes
    Add-Result 'Scheduled task' ([bool](Get-ScheduledTask -TaskName 'SAIP-AI-Usage-Collector' -ErrorAction SilentlyContinue)) "SAIP-AI-Usage-Collector every $IntervalMinutes min as SYSTEM"
} catch { Add-Result 'Scheduled task' $false $_.Exception.Message }

Write-Host ''
Write-Host 'Installation summary'
$summary | Format-Table -AutoSize -Wrap | Out-Host
if ($summary | Where-Object Result -eq 'ATTENTION') { Write-Warning 'Some checks need attention (see above). Fix the cause and run this script again; it is safe to repeat.' }
else { Write-Host 'All checks passed.' -ForegroundColor Green }
Write-Host 'In the SAIP console open Collectors & Monitoring: this PC should be listed (click Authorize if it shows PENDING).'
Write-Host "Logs and state: $($cfg.dataDir)   |   See recent lookups: $InstallDir\Show-SysmonDns.ps1 -Match 'chrome|msedge'"
