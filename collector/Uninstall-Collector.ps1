<#
.SYNOPSIS  Removes the scheduled task and restores the browser DNS policies SAIP set; optionally removes Sysmon and local data. Run as Administrator.
.PARAMETER KeepBrowserPolicy  Leave the Chrome/Edge/Brave/Firefox DNS policies in place.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TaskName = 'SAIP-AI-Usage-Collector',
    [string]$DataDir = 'C:\ProgramData\SaipCollector',
    [switch]$RemoveSysmon,
    [switch]$RemoveData,
    [switch]$KeepBrowserPolicy
)
. (Join-Path $PSScriptRoot 'SaipCommon.ps1')
if (-not (Test-SaipAdmin)) { throw 'Run as Administrator.' }

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed task $TaskName"
}
if (-not $KeepBrowserPolicy) {
    $r = @(Remove-SaipBrowserDnsPolicy -StatePath (Join-Path $DataDir 'browser-policy.json'))
    if ($r.Count) { Write-Host "Restored $($r.Count) browser policy value(s). Restart the browsers to apply." }
}
if ($RemoveSysmon) {
    $exe = Join-Path $PSScriptRoot 'Sysmon64.exe'
    if (Test-Path $exe) { & $exe -accepteula -u force } else { Write-Warning 'Sysmon64.exe not found next to this script.' }
}
if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item -LiteralPath $DataDir -Recurse -Force
    Write-Host "Removed $DataDir (credential, checkpoint, logs). Ask an administrator to revoke this collector on the server."
}
