<#
.SYNOPSIS
  Installs, repairs or updates Sysmon with the SAIP configuration and PROVES it works (writes a test DNS lookup and waits for the Sysmon event).
  Run as Administrator. Safe to run again.
.PARAMETER SysmonExe       Path to Sysmon64.exe. If missing it is downloaded from Microsoft Sysinternals.
.PARAMETER EnableNetwork   Also log outbound HTTPS network connections (Event ID 3, sysmon-config-network.xml).
.PARAMETER SkipTest        Do not run the self-test.
#>
[CmdletBinding()]
param(
    [string]$SysmonExe = (Join-Path $PSScriptRoot 'Sysmon64.exe'),
    [string]$SysmonConfig = (Join-Path $PSScriptRoot 'sysmon-config.xml'),
    [switch]$EnableNetwork,
    [switch]$SkipTest
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SaipCommon.ps1')
if (-not (Test-SaipAdmin)) { throw 'Run as Administrator.' }
if ($EnableNetwork) { $SysmonConfig = Join-Path $PSScriptRoot 'sysmon-config-network.xml' }
if (-not (Test-Path $SysmonConfig)) { throw "Sysmon configuration not found: $SysmonConfig" }

if (-not (Test-Path $SysmonExe)) {
    Write-Host 'Downloading Sysmon from https://live.sysinternals.com/Sysmon64.exe ...'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri 'https://live.sysinternals.com/Sysmon64.exe' -OutFile $SysmonExe -UseBasicParsing
}

function Invoke-Sysmon([string[]]$SysmonArgs) {
    & $SysmonExe -accepteula @SysmonArgs | Out-Host
    return $LASTEXITCODE
}

$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host 'Sysmon is installed: loading the SAIP configuration.'
    $rc = Invoke-Sysmon @('-c', $SysmonConfig)
    if ($rc -ne 0) { throw "Sysmon could not load the configuration (exit $rc)." }
} else {
    Write-Host 'Installing Sysmon with the SAIP configuration.'
    $rc = Invoke-Sysmon @('-i', $SysmonConfig)
    if ($rc -eq 32 -or $rc -eq 1) {
        # A previous Sysmon was removed but Windows still holds its file. Clean up and try once more.
        Write-Warning 'The old Sysmon file is still in use; clearing leftovers and retrying once.'
        Invoke-Sysmon @('-u', 'force') | Out-Null
        Start-Sleep -Seconds 2
        $rc = Invoke-Sysmon @('-i', $SysmonConfig)
    }
    if ($rc -ne 0) {
        throw "Sysmon could not be installed (exit $rc). If the message says the file is in use, RESTART WINDOWS and run this script again."
    }
}
& wevtutil.exe sl 'Microsoft-Windows-Sysmon/Operational' /ms:67108864   # 64 MB log
Start-Sleep -Seconds 2

if ($SkipTest) { Write-Host 'Sysmon ready (self-test skipped).'; return }

Write-Host 'Self-test: checking that Sysmon records a DNS lookup ...'
$ok = Test-SaipSysmonDns
if (-not $ok) {
    Write-Warning 'No DNS event was recorded. Reloading the configuration and trying again.'
    Invoke-Sysmon @('-c', $SysmonConfig) | Out-Null
    Start-Sleep -Seconds 3
    $ok = Test-SaipSysmonDns -WaitSeconds 15
}
if (-not $ok) {
    Write-Warning 'Sysmon is installed but is not logging DNS. Reinstalling it (this clears the stuck state).'
    Invoke-Sysmon @('-u', 'force') | Out-Null
    Start-Sleep -Seconds 3
    $rc = Invoke-Sysmon @('-i', $SysmonConfig)
    if ($rc -ne 0) { throw "Sysmon could not be reinstalled (exit $rc). Restart Windows and run this script again." }
    Start-Sleep -Seconds 3
    $ok = Test-SaipSysmonDns -WaitSeconds 15
}
if ($ok) { Write-Host 'Sysmon ready: DNS logging verified.' }
else { throw 'Sysmon still does not log DNS. Restart Windows and run this script again; if it persists, check Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5.' }
