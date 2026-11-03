<#
.SYNOPSIS
  Reads Sysmon DNS (EID 22) and, if enabled centrally, network-connection (EID 3) events and reports registry matches to the SAIP API.
.DESCRIPTION
  Run via Task Scheduler as SYSTEM. There is NO domain list in this script or its config: the AI registry and monitoring
  options are pulled from the server (GET collector/config), cached locally, and re-synced when the server's config version changes.
  Without a cached or fetched config nothing is collected.
  Collects: record id, UTC time, queried domain, status, process image/GUID/PID (+ destination IP/port/protocol for EID 3).
  Does NOT collect prompts, page content, credentials, keystrokes or Windows usernames.
  If the server is unreachable, batches are buffered in a local spool folder and replayed in order on the next successful run.
.PARAMETER SetApiKey
  Store an API key issued by an administrator (e.g. after rotating the credential in the console).
.PARAMETER DryRun
  Read and filter events but send nothing and do not move the checkpoint.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'collector.config.json'),
    [string]$SetApiKey,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$CollectorVersion = '2.0.0'
Add-Type -AssemblyName System.Security
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$base = $cfg.serverUrl.TrimEnd('/')
if ($base -like 'http://*' -and -not $cfg.allowInsecureHttp) { throw 'HTTP is disabled (allowInsecureHttp=false). Use HTTPS.' }
$dir = $cfg.dataDir
$spoolDir = Join-Path $dir 'spool'
New-Item -ItemType Directory -Force -Path $dir, $spoolDir | Out-Null
$logFile   = Join-Path $dir 'collector-error.log'
$stateFile = Join-Path $dir 'state.json'
$credFile  = Join-Path $dir 'credential.dat'
$cacheFile = Join-Path $dir 'config-cache.json'
$spoolMax  = if ($cfg.spoolMaxFiles) { [int]$cfg.spoolMaxFiles } else { 500 }

function Write-Log([string]$Level, [string]$Msg) {
    if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 5MB) { Move-Item $logFile "$logFile.1" -Force }
    "{0:u} [{1}] {2}" -f (Get-Date).ToUniversalTime(), $Level, $Msg | Add-Content -LiteralPath $logFile
    if ($VerbosePreference -eq 'Continue' -or $Level -eq 'ERROR') { Write-Host "[$Level] $Msg" }
}

# --- state / credential (DPAPI LocalMachine scope; file ACL restricted to SYSTEM + Administrators) ---
function Get-State {
    $s = $null
    if (Test-Path $stateFile) { $s = Get-Content $stateFile -Raw | ConvertFrom-Json }
    if (-not $s) { $s = [pscustomobject]@{ collectorUuid = [guid]::NewGuid().ToString(); lastRecordId = 0; lastTimestampUtc = $null } }
    foreach ($k in 'configVersion', 'failedSubmissions', 'lastError') { if (-not ($s.PSObject.Properties.Name -contains $k)) { $s | Add-Member -NotePropertyName $k -NotePropertyValue $null } }
    if (-not $s.failedSubmissions) { $s.failedSubmissions = 0 }
    return $s
}
function Save-State($s) { $s | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8 }
function Save-ApiKey([string]$key) {
    $enc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($key), $null, 'LocalMachine')
    [IO.File]::WriteAllBytes($credFile, $enc)
    & icacls.exe $credFile /inheritance:r /grant:r 'SYSTEM:(F)' 'BUILTIN\Administrators:(F)' | Out-Null
}
function Get-ApiKey {
    if (-not (Test-Path $credFile)) { return $null }
    $b = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($credFile), $null, 'LocalMachine')
    return [Text.Encoding]::UTF8.GetString($b)
}

# --- HTTP with retry (no retry on 4xx other than 429) ---
function Invoke-Saip([string]$Method, [string]$Path, $Body, [hashtable]$Headers) {
    $uri = "$base/$Path"
    $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 6 -Compress } else { $null }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $p = @{ Uri = $uri; Method = $Method; Headers = $Headers; TimeoutSec = 30; UseBasicParsing = $true }
            if ($json) { $p.Body = [Text.Encoding]::UTF8.GetBytes($json); $p.ContentType = 'application/json' }
            return Invoke-RestMethod @p
        } catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            $detail = $_.Exception.Message
            if ($_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
            $retryable = ($code -eq 0 -or $code -eq 429 -or $code -ge 500)
            if (-not $retryable -or $attempt -ge $cfg.retryAttempts) {
                $ex = New-Object System.Exception("HTTP $code $Method $Path : $detail")
                $ex.Data['StatusCode'] = $code
                throw $ex
            }
            $delay = [int]$cfg.retryBaseDelaySeconds * [math]::Pow(2, $attempt - 1)
            Write-Log 'WARN' "Attempt $attempt failed (HTTP $code); retrying in ${delay}s"
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-Mac {
    if (-not $cfg.collectMacAddress) { return $null }
    try {
        $a = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up' | Select-Object -First 1
        if ($a) { return ($a.MacAddress -replace '-', ':') }
    } catch { }
    return $null
}
function Get-WorkstationIp {
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
        if ($ip) { return $ip.IPAddress }
    } catch { }
    return $null
}

# --- registry matching: exact rules match the host itself; subdomain rules match the host or any parent ---
function New-RuleIndex($rules) {
    $idx = @{}
    foreach ($r in @($rules)) { $idx[$r.domain.ToLower()] = $r }
    return $idx
}
function Find-Rule($idx, [string]$h) {
    if ($idx.ContainsKey($h)) { return $idx[$h] }
    $parts = $h.Split('.')
    for ($i = 1; $i -le $parts.Length - 2; $i++) {
        $c = $parts[$i..($parts.Length - 1)] -join '.'
        if ($idx.ContainsKey($c) -and $idx[$c].matching_rule -eq 'subdomain') { return $idx[$c] }
    }
    return $null
}

# --- spool: failed batches are written to disk and replayed oldest-first ---
function Get-SpoolFiles { @(Get-ChildItem -LiteralPath $spoolDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name) }
function Add-Spool($payload) {
    if ((Get-SpoolFiles).Count -ge $spoolMax) { Write-Log 'ERROR' "Spool full ($spoolMax files); dropping oldest batch."; (Get-SpoolFiles | Select-Object -First 1) | Remove-Item -Force }
    $name = '{0:D19}-{1}.json' -f (Get-Date).ToUniversalTime().Ticks, ([guid]::NewGuid().ToString('N').Substring(0, 6))
    $payload | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath (Join-Path $spoolDir $name) -Encoding UTF8
}
function Invoke-SpoolReplay($auth) {
    foreach ($f in Get-SpoolFiles) {
        $body = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
        Invoke-Saip 'POST' 'events/ingest' $body $auth | Out-Null    # throws (and stops the replay) on failure
        Remove-Item -LiteralPath $f.FullName -Force
        Write-Log 'INFO' "Replayed spooled batch $($f.Name)."
    }
}

$auth = $null
try {
    $state = Get-State
    if ($SetApiKey) { Save-ApiKey $SetApiKey; Save-State $state; Write-Log 'INFO' 'API key stored.'; return }

    # --- registration (first run) ---
    $apiKey = Get-ApiKey
    if (-not $apiKey) {
        $reg = @{ computer_name = $env:COMPUTERNAME; collector_uuid = $state.collectorUuid; collector_version = $CollectorVersion }
        $mac = Get-Mac; if ($mac) { $reg.mac_address = $mac }
        $r = Invoke-Saip 'POST' 'collector/register' $reg @{ 'X-Enrollment-Key' = $cfg.enrollmentKey }
        Save-ApiKey $r.api_key; Save-State $state
        $apiKey = $r.api_key
        Write-Log 'INFO' "Registered as $($state.collectorUuid) (status: $($r.status))."
    }
    $auth = @{ 'X-Collector-Id' = $state.collectorUuid; 'X-Api-Key' = $apiKey }

    # --- central configuration (cached; the server is the only source of domain rules) ---
    $conf = $null
    if (Test-Path $cacheFile) { try { $conf = Get-Content $cacheFile -Raw | ConvertFrom-Json } catch { Write-Log 'WARN' 'Config cache unreadable; ignoring.' } }
    try {
        $since = if ($conf) { "?since=$($conf.config_version)" } else { '' }
        $fresh = Invoke-Saip 'GET' "collector/config$since" $null $auth
        if (-not $fresh.unchanged) {
            $conf = $fresh
            $conf | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $cacheFile -Encoding UTF8
            Write-Log 'INFO' "Config synced: version $($conf.config_version), $(@($conf.rules).Count) rules."
        }
    } catch {
        if ($_.Exception.Data['StatusCode'] -eq 403) { Write-Log 'INFO' 'Collector not authorized yet; waiting.'; return }
        Write-Log 'WARN' "Config sync failed: $($_.Exception.Message)"
        $state.lastError = "config sync: $($_.Exception.Message)"
    }
    if (-not $conf) { Write-Log 'WARN' 'No configuration available (never synced); collecting nothing.'; throw 'No configuration available from the server yet.' }
    $state.configVersion = [int]$conf.config_version
    $mon = $conf.monitoring
    $idx = New-RuleIndex $conf.rules
    # Dedicated addresses of registered services (server-provided). Lets browser connections that have no host name still be recognised.
    $ipIdx = @{}
    foreach ($r in @($conf.ip_rules)) { if ($r.ip) { try { $ipIdx[[Net.IPAddress]::Parse([string]$r.ip).ToString()] = [int]$r.service_id } catch { } } }
    $wsIp = Get-WorkstationIp

    # --- replay anything buffered while the server was unreachable ---
    if (-not $DryRun) { Invoke-SpoolReplay $auth }

    # --- read Sysmon: EID 22 always; EID 3 only when enabled centrally ---
    $ids = @(22); if ($mon.network_events) { $ids += 3 }
    $start = if ($state.lastTimestampUtc) { ([datetime]$state.lastTimestampUtc).AddSeconds(-2) } else { (Get-Date).AddMinutes(-[int]$cfg.firstRunLookbackMinutes) }
    $raw = @()
    try {
        $raw = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = $ids; StartTime = $start } -Oldest -MaxEvents ([int]$cfg.maxEventsPerRun) -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }

    $hints = @($mon.discovery_hints | ForEach-Object { $_.ToLower() })
    $maxRecord = [long]$state.lastRecordId; $maxTime = $state.lastTimestampUtc
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $raw) {
        $when = $e.TimeCreated.ToUniversalTime()
        if ($e.RecordId -le $state.lastRecordId -and $state.lastTimestampUtc -and $when -le ([datetime]$state.lastTimestampUtc)) { continue }
        if ($e.RecordId -gt $maxRecord) { $maxRecord = $e.RecordId }
        if (-not $maxTime -or $when -gt [datetime]$maxTime) { $maxTime = $when.ToString('o') }

        $f = @{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $f[$n.Name] = $n.'#text' }
        $ts = $when
        if ($f['UtcTime']) { try { $ts = [datetime]::SpecifyKind([datetime]::ParseExact($f['UtcTime'], 'yyyy-MM-dd HH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture), 'Utc') } catch { } }
        $stamp = $ts.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
        $pid_ = if ($f['ProcessId']) { [int]$f['ProcessId'] } else { $null }

        if ($e.Id -eq 22) {
            $q = ([string]$f['QueryName']).TrimEnd('.').ToLower()
            if (-not $q) { continue }
            $rule = Find-Rule $idx $q
            if ($rule) { if ($rule.classification -eq 'excluded') { continue } }
            else {
                # Not registered. Only hostnames containing a server-supplied hint go to the discovery review list.
                if (-not $mon.discovery) { continue }
                # Short hints (3 letters or fewer, e.g. "ai") must be a whole word of the host name (chat.ai, my-ai-tool.com), not a fragment of another word (mail, saip).
                $hit = $false; $words = $q -split '[.\-_]'
                foreach ($h in $hints) {
                    if (-not $h) { continue }
                    if ($h.Length -le 3) { if ($words -contains $h) { $hit = $true; break } }
                    elseif ($q.Contains($h)) { $hit = $true; break }
                }
                if (-not $hit) { continue }            # unrelated DNS never leaves the machine
            }
            $out.Add([ordered]@{
                sysmon_record_id = [long]$e.RecordId; event_timestamp = $stamp; query_domain = $q
                query_status = $f['QueryStatus']; process_image = $f['Image']; process_id = $pid_
                process_guid = $f['ProcessGuid']; event_type = 'dns_query'
            })
        }
        elseif ($e.Id -eq 3) {
            if ($f['Initiated'] -ne 'true') { continue }
            $dh = ([string]$f['DestinationHostname']).TrimEnd('.').ToLower()
            $dip = [string]$f['DestinationIp']
            try { $dipN = [Net.IPAddress]::Parse($dip).ToString() } catch { continue }
            $rule = if ($dh) { Find-Rule $idx $dh } else { $null }
            if ($rule) { if ($rule.classification -eq 'excluded') { continue } }
            elseif (-not $ipIdx.ContainsKey($dipN)) { continue }       # neither a registered host nor a dedicated address of a registered service
            $out.Add([ordered]@{
                sysmon_record_id = [long]$e.RecordId; event_timestamp = $stamp; event_type = 'network_connection'
                destination_host = $(if ($dh) { $dh } else { $null }); destination_ip = $dip
                destination_port = if ($f['DestinationPort']) { [int]$f['DestinationPort'] } else { $null }
                protocol = $f['Protocol']; process_image = $f['Image']; process_guid = $f['ProcessGuid']
            })
        }
    }
    Write-Log 'INFO' "Scanned $($raw.Count) Sysmon events; $($out.Count) relevant."

    if ($DryRun) { $out | ForEach-Object { $_ | ConvertTo-Json -Compress }; return }

    # --- send in batches; a failed batch is spooled, then the checkpoint still advances (data is safe on disk) ---
    for ($i = 0; $i -lt $out.Count; $i += [int]$cfg.batchSize) {
        $batch = $out.GetRange($i, [math]::Min([int]$cfg.batchSize, $out.Count - $i))
        $payload = @{ events = $batch }; if ($wsIp) { $payload.workstation_ip = $wsIp }
        try {
            $res = Invoke-Saip 'POST' 'events/ingest' $payload $auth
            Write-Log 'INFO' "Sent $($batch.Count): accepted=$($res.accepted) duplicates=$($res.duplicates) unmatched=$($res.unmatched) rejected=$(@($res.rejected).Count)"
        } catch {
            $code = $_.Exception.Data['StatusCode']
            if ($code -ge 400 -and $code -lt 500 -and $code -ne 429) { throw }       # permanent error: do not spool, do not advance
            Add-Spool $payload
            $state.failedSubmissions = [int]$state.failedSubmissions + 1
            $state.lastError = $_.Exception.Message
            Write-Log 'WARN' "Send failed; batch of $($batch.Count) buffered in spool."
        }
    }
    $state.lastRecordId = $maxRecord; $state.lastTimestampUtc = $maxTime

    $hb = @{ collector_version = $CollectorVersion; status = 'ok'; config_version = [int]$state.configVersion
             spool_depth = (Get-SpoolFiles).Count; failed_submissions = [int]$state.failedSubmissions }
    if ($state.lastError) { $hb.last_error = [string]$state.lastError; $hb.status = 'degraded' }
    if ($wsIp) { $hb.workstation_ip = $wsIp }
    Invoke-Saip 'POST' 'collector/heartbeat' $hb $auth | Out-Null
    if ((Get-SpoolFiles).Count -eq 0) { $state.lastError = $null }      # healthy again
    Save-State $state
}
catch {
    Write-Log 'ERROR' $_.Exception.Message
    try {
        if ($auth) {
            $state.failedSubmissions = [int]$state.failedSubmissions + 1; $state.lastError = $_.Exception.Message; Save-State $state
            Invoke-Saip 'POST' 'collector/heartbeat' @{ collector_version = $CollectorVersion; status = 'error'; last_error = $_.Exception.Message
                config_version = [int]$state.configVersion; spool_depth = (Get-SpoolFiles).Count; failed_submissions = [int]$state.failedSubmissions } $auth | Out-Null
        }
    } catch { }
    exit 1
}
