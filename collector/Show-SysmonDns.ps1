<#
.SYNOPSIS
  Shows recent Sysmon DNS events (Event ID 22) as time, process and queried name, plus which programs make lookups.
  Use it to check that browsers (chrome.exe / msedge.exe) are visible to Sysmon. Run in an elevated PowerShell.
.PARAMETER Match    Regular expression applied to "process name + query" (default: everything).
.PARAMETER Max      How many of the newest events to read (default 500).
.PARAMETER Minutes  Only events from the last N minutes (default: no limit).
.EXAMPLE
  .\Show-SysmonDns.ps1 -Match 'chrome|msedge'
.EXAMPLE
  .\Show-SysmonDns.ps1 -Match 'gemini|chatgpt' -Minutes 30
#>
[CmdletBinding()]
param(
    [string]$Match = '.',
    [int]$Max = 500,
    [int]$Minutes = 0
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) { throw 'Run as Administrator (the Sysmon log is not readable otherwise).' }

$filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 22 }
if ($Minutes -gt 0) { $filter.StartTime = (Get-Date).AddMinutes(-$Minutes) }
try {
    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { Write-Host 'Sysmon has recorded no DNS events in that period.'; return }
    throw
}

$rows = foreach ($e in $events) {
    $d = @{}
    foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [pscustomobject]@{ Time = $e.TimeCreated; Process = (Split-Path ([string]$d['Image']) -Leaf); Query = $d['QueryName'] }
}

Write-Host "Read $($rows.Count) DNS events (newest first). Showing those matching '$Match':"
$shown = @($rows | Where-Object { "$($_.Process) $($_.Query)" -match $Match })
if ($shown.Count) { $shown | Format-Table -AutoSize } else { Write-Host '  (none)' }

Write-Host 'Programs that made DNS lookups:'
$rows | Group-Object Process | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize
if (-not ($rows | Where-Object { $_.Process -match '^(chrome|msedge|firefox)\.exe$' })) {
    Write-Warning 'No browser appears in the list: the browsers are not using the Windows DNS client. Fully close them (taskkill /F /IM chrome.exe /IM msedge.exe), reopen, and check chrome://policy.'
}
