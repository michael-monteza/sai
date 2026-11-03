<#
.SYNOPSIS  Registers the collector as a scheduled task running as SYSTEM. Run as Administrator.
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'SAIP-AI-Usage-Collector',
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'collector.config.json'),
    [int]$IntervalMinutes = 5
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) { throw 'Run as Administrator.' }

$script = Join-Path $PSScriptRoot 'Collect-AiUsage.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" -ConfigPath `"$ConfigPath`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "Task '$TaskName' registered; runs every $IntervalMinutes min as SYSTEM. First run in ~1 minute."
