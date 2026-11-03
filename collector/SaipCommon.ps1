# Shared helpers for the SAIP collector scripts. Dot-source it:  . (Join-Path $PSScriptRoot 'SaipCommon.ps1')

function Test-SaipAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
}

<#
  Makes browser lookups visible to Sysmon. Chrome, Edge and Brave resolve names with their own built-in resolver or DNS-over-HTTPS, which bypasses
  the Windows DNS client that Sysmon watches; Firefox may use DNS-over-HTTPS. This writes the machine policies that switch both off
  (they take effect the next time the browser starts). The previous values are saved so Remove-SaipBrowserDnsPolicy can put them back.
  -Root is only overridden by tests.
#>
function Set-SaipBrowserDnsPolicy {
    [CmdletBinding()]
    param(
        [string]$Root = 'HKLM:\SOFTWARE\Policies',
        [string]$StatePath = 'C:\ProgramData\SaipCollector\browser-policy.json'
    )
    $targets = @(
        @{ Name = 'Chrome';  Key = 'Google\Chrome';             Values = [ordered]@{ BuiltInDnsClientEnabled = @(0, 'DWord'); DnsOverHttpsMode = @('off', 'String') } },
        @{ Name = 'Edge';    Key = 'Microsoft\Edge';            Values = [ordered]@{ BuiltInDnsClientEnabled = @(0, 'DWord'); DnsOverHttpsMode = @('off', 'String') } },
        @{ Name = 'Brave';   Key = 'BraveSoftware\Brave';       Values = [ordered]@{ BuiltInDnsClientEnabled = @(0, 'DWord'); DnsOverHttpsMode = @('off', 'String') } },
        @{ Name = 'Firefox'; Key = 'Mozilla\Firefox\DNSOverHTTPS'; Values = [ordered]@{ Enabled = @(0, 'DWord'); Locked = @(1, 'DWord') } }
    )
    $saved = @()
    if (Test-Path -LiteralPath $StatePath) { try { $saved = @(Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json | ForEach-Object { $_ }) } catch { $saved = @() } }   # ForEach unrolls the array (Windows PowerShell 5.1 returns it as one object)
    $applied = @()
    foreach ($t in $targets) {
        $path = "$Root\$($t.Key)"
        if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
        foreach ($name in $t.Values.Keys) {
            $want, $type = $t.Values[$name]
            $known = $saved | Where-Object { $_.Path -eq $path -and $_.Name -eq $name }
            if (-not $known) {   # remember what was there before we touched it (first run only)
                $prev = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue).$name
                $saved += [pscustomobject]@{ Path = $path; Name = $name; Previous = $prev }
            }
            New-ItemProperty -LiteralPath $path -Name $name -Value $want -PropertyType $type -Force | Out-Null
        }
        $applied += $t.Name
    }
    $dir = Split-Path -Parent $StatePath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ConvertTo-Json -InputObject @($saved) -Depth 4 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    return $applied
}

function Remove-SaipBrowserDnsPolicy {
    [CmdletBinding()]
    param([string]$StatePath = 'C:\ProgramData\SaipCollector\browser-policy.json')
    if (-not (Test-Path -LiteralPath $StatePath)) { return @() }
    $restored = @()
    foreach ($e in @(Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json | ForEach-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $e.Path)) { continue }
        if ($null -eq $e.Previous) { Remove-ItemProperty -LiteralPath $e.Path -Name $e.Name -ErrorAction SilentlyContinue }
        else { Set-ItemProperty -LiteralPath $e.Path -Name $e.Name -Value $e.Previous }
        $restored += "$($e.Path)\$($e.Name)"
    }
    Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
    return $restored
}

<# Proves Sysmon is logging DNS: looks up a unique made-up name and waits for its Event ID 22. Returns $true / $false. Needs Administrator. #>
function Test-SaipSysmonDns {
    [CmdletBinding()]
    param([int]$WaitSeconds = 10)
    $name = 'saip-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 10) + '.example.com'
    $since = (Get-Date).AddSeconds(-2)
    Resolve-DnsName -Name $name -ErrorAction SilentlyContinue | Out-Null
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        Start-Sleep -Milliseconds 800
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 22; StartTime = $since } -ErrorAction SilentlyContinue)
        if ($ev | Where-Object { $_.Message -like "*$name*" }) { return $true }
    } while ((Get-Date) -lt $deadline)
    return $false
}
