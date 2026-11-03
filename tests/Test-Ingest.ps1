<#
.SYNOPSIS  End-to-end API test without Sysmon: registers a fake collector, sends events twice (duplicate check).
#>
param(
    [string]$BaseUrl = 'http://localhost:8080/2026/saip/api/v1',
    [string]$EnrollmentKey = 'CHANGE-ME-enrollment-key'
)
$ErrorActionPreference = 'Stop'
$uuid = [guid]::NewGuid().ToString()
$reg = Invoke-RestMethod "$BaseUrl/collector/register" -Method Post -ContentType 'application/json' `
    -Headers @{ 'X-Enrollment-Key' = $EnrollmentKey } `
    -Body (@{ computer_name = 'WS-TEST-01'; collector_uuid = $uuid; mac_address = '00:1A:2B:3C:4D:5E'; collector_version = '1.0.0' } | ConvertTo-Json)
"Register  -> status=$($reg.status)"
if ($reg.status -ne 'authorized') { "Authorize it first:  php tools\collector-admin.php authorize $uuid"; return }

$h = @{ 'X-Collector-Id' = $uuid; 'X-Api-Key' = $reg.api_key }
$now = (Get-Date).ToUniversalTime()
$events = @(
    @{ sysmon_record_id = 1001; event_timestamp = $now.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"); query_domain = 'chatgpt.com'; process_image = 'C:\Program Files\Google\Chrome\Application\chrome.exe'; process_id = 4242 },
    @{ sysmon_record_id = 1002; event_timestamp = $now.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"); query_domain = 'cdn.oaistatic.com'; process_id = 4242 },
    @{ sysmon_record_id = 1003; event_timestamp = $now.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"); query_domain = 'a.b.claude.ai'; process_image = 'C:\Program Files\Microsoft\Edge\msedge.exe'; process_id = 999 },
    @{ sysmon_record_id = 0;    event_timestamp = 'garbage'; query_domain = 'bad domain' }
)
$body = @{ events = $events } | ConvertTo-Json -Depth 4
foreach ($pass in 1, 2) {
    $r = Invoke-RestMethod "$BaseUrl/events/ingest" -Method Post -ContentType 'application/json' -Headers $h -Body $body
    "Ingest #$pass -> accepted=$($r.accepted) duplicates=$($r.duplicates) unmatched=$($r.unmatched) rejected=$(@($r.rejected).Count)"
}
"Expected: #1 accepted=2 unmatched=1 rejected=1 ; #2 duplicates=2"
$hb = Invoke-RestMethod "$BaseUrl/collector/heartbeat" -Method Post -ContentType 'application/json' -Headers $h -Body '{"collector_version":"1.0.0","status":"ok"}'
"Heartbeat -> $($hb.status)"
try { Invoke-RestMethod "$BaseUrl/events/ingest" -Method Post -ContentType 'application/json' -Headers @{ 'X-Collector-Id' = $uuid; 'X-Api-Key' = 'wrong' } -Body $body } catch { "Bad key   -> HTTP $([int]$_.Exception.Response.StatusCode) (expected 401)" }
