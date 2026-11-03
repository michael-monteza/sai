<?php
declare(strict_types=1);

namespace Saip;

/** What Sysmon can track, what SAIP collects from it, and the JSON that carries it. Reference data shown under Collectors & Monitoring. */
final class SysmonCatalog
{
    /** status: collected (always), optional (switchable in Monitoring options), not_collected (deliberately out of scope) */
    public static function events(): array
    {
        $e = static fn (int $id, string $name, string $status, string $what, string $fields, string $why) => ['id' => $id, 'name' => $name, 'status' => $status, 'what' => $what, 'fields' => $fields, 'saip' => $why];
        return [
            $e(22, 'DNS query', 'collected', 'A process resolved a host name.', 'QueryName, QueryStatus, QueryResults, Image, ProcessId, ProcessGuid, UtcTime', 'Primary signal: which AI hostnames a workstation looked up, and which program asked. Matched centrally against the registry.'),
            $e(3, 'Network connection', 'optional', 'A process opened a TCP/UDP connection.', 'DestinationIp, DestinationHostname, DestinationPort, Protocol, Image, ProcessGuid, UtcTime', 'Optional. Sees the connection itself, so it works for browsers that bypass the Windows DNS client. Matched by host name when Sysmon has one, otherwise by a dedicated service address (CDN / shared addresses are ignored). Only matches are sent.'),
            $e(1, 'Process create', 'not_collected', 'A process started.', 'Image, CommandLine, ParentImage, Hashes, User, ProcessGuid', 'Not collected: command lines and user names add privacy exposure without improving AI-service identification.'),
            $e(5, 'Process terminated', 'not_collected', 'A process ended.', 'Image, ProcessGuid', 'Not collected: session duration is out of scope.'),
            $e(7, 'Image loaded', 'not_collected', 'A DLL/module was loaded.', 'ImageLoaded, Image, Hashes, Signed', 'Not collected: very high volume.'),
            $e(11, 'File create', 'not_collected', 'A file was created or overwritten.', 'TargetFilename, Image, CreationUtcTime', 'Not collected: file names can be sensitive.'),
            $e(12, 'Registry object create/delete', 'not_collected', 'A registry key or value was created/deleted.', 'EventType, TargetObject, Image', 'Not collected.'),
            $e(13, 'Registry value set', 'not_collected', 'A registry value was modified.', 'TargetObject, Details, Image', 'Not collected.'),
            $e(15, 'File stream created', 'not_collected', 'An alternate data stream was created (downloads).', 'TargetFilename, Hash', 'Not collected.'),
            $e(23, 'File delete (archived)', 'not_collected', 'A file was deleted and archived.', 'TargetFilename, Hashes, IsExecutable', 'Not collected.'),
            $e(26, 'File delete (logged)', 'not_collected', 'A file deletion was logged.', 'TargetFilename, Hashes', 'Not collected.'),
            $e(25, 'Process tampering', 'not_collected', 'Process hollowing/herpaderping detected.', 'Image, Type', 'Security detection, not an AI-usage signal.'),
        ];
    }

    /** Sysmon event field -> SAIP JSON field. */
    public static function mapping(): array
    {
        $m = static fn (string $eid, string $sysmon, string $json, string $note) => ['eid' => $eid, 'sysmon' => $sysmon, 'json' => $json, 'note' => $note];
        return [
            $m('22', 'QueryName', 'query_domain', 'Lower-cased; must be a valid hostname (IPs rejected).'),
            $m('22', 'QueryStatus', 'query_status', 'Optional, e.g. "0" or "NAME_ERROR".'),
            $m('22', 'Image', 'process_image', 'Full path; the console shows the file name.'),
            $m('22', 'ProcessId', 'process_id', 'Integer.'),
            $m('22', 'ProcessGuid', 'process_guid', 'GUID without braces.'),
            $m('22/3', 'UtcTime', 'event_timestamp', 'ISO-8601 UTC. Rejected if in the far future.'),
            $m('22/3', 'Event RecordId', 'sysmon_record_id', 'With the timestamp this de-duplicates re-sent batches.'),
            $m('3', 'DestinationHostname', 'destination_host', 'Optional (often empty). Matched against the registry when present.'),
            $m('3', 'DestinationIp', 'destination_ip', 'Required (IPv4/IPv6). With no usable host name it is matched against dedicated service addresses (match basis "ip").'),
            $m('3', 'DestinationPort', 'destination_port', '0-65535.'),
            $m('3', 'Protocol', 'protocol', 'tcp / udp.'),
            $m('-', '(authenticated collector)', 'computer_name', 'Taken from the collector record, never from the payload.'),
        ];
    }

    /** Example payloads, exactly as sent and returned. */
    public static function samples(): array
    {
        $raw22 = <<<'XML'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>22</EventID><TimeCreated SystemTime="2026-10-30T09:15:02.123456Z"/><EventRecordID>1001</EventRecordID><Computer>WS-FIN-03.corp.local</Computer></System>
  <EventData>
    <Data Name="UtcTime">2026-10-30 09:15:02.123</Data><Data Name="ProcessGuid">{4f8b2f1c-2c1d-6540-9a01-000000002900}</Data><Data Name="ProcessId">4242</Data>
    <Data Name="QueryName">chatgpt.com</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">type: 5 chatgpt.com.cdn.cloudflare.net;::ffff:104.18.32.47;</Data>
    <Data Name="Image">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
  </EventData>
</Event>
XML;
        $ingest = [
            'workstation_ip' => '10.20.30.41',
            'events' => [
                ['sysmon_record_id' => 1001, 'event_timestamp' => '2026-10-30T09:15:02.123Z', 'event_type' => 'dns_query', 'query_domain' => 'chatgpt.com', 'query_status' => '0',
                 'process_image' => 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'process_id' => 4242, 'process_guid' => '4f8b2f1c-2c1d-6540-9a01-000000002900'],
                ['sysmon_record_id' => 1002, 'event_timestamp' => '2026-10-30T09:15:03.480Z', 'event_type' => 'network_connection', 'destination_host' => 'chatgpt.com', 'destination_ip' => '104.18.32.47',
                 'destination_port' => 443, 'protocol' => 'tcp', 'process_image' => 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'process_guid' => '4f8b2f1c-2c1d-6540-9a01-000000002900'],
            ],
        ];
        return [
            ['key' => 'sysmon_dns_xml', 'title' => 'Sysmon Event ID 22 (raw XML as read from the Windows event log)', 'lang' => 'xml', 'body' => $raw22],
            ['key' => 'ingest_request', 'title' => 'Collector → SAIP: POST /api/v1/events/ingest (headers X-Collector-Id, X-Api-Key)', 'lang' => 'json', 'body' => json_encode($ingest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)],
            ['key' => 'ingest_response', 'title' => 'SAIP response', 'lang' => 'json', 'body' => json_encode(['status' => 'ok', 'received' => 2, 'accepted' => 2, 'duplicates' => 0, 'unmatched' => 0, 'excluded' => 0, 'rejected' => [], 'config_version' => 14], JSON_PRETTY_PRINT)],
            ['key' => 'config', 'title' => 'Central rules: GET /api/v1/collector/config?since=N', 'lang' => 'json', 'body' => json_encode(['config_version' => 14, 'rules' => [['domain' => 'chatgpt.com', 'matching_rule' => 'subdomain', 'domain_type' => 'primary', 'service_id' => 1, 'service' => 'ChatGPT', 'classification' => 'unsanctioned']], 'monitoring' => ['dns_events' => true, 'network_events' => false, 'discovery' => true, 'discovery_hints' => ['ai', 'gpt', 'llm'], 'interval_minutes' => 5]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)],
            ['key' => 'heartbeat', 'title' => 'Collector health: POST /api/v1/collector/heartbeat', 'lang' => 'json', 'body' => json_encode(['collector_version' => '2.0.0', 'status' => 'ok', 'config_version' => 14, 'spool_depth' => 0, 'failed_submissions' => 0, 'workstation_ip' => '10.20.30.41'], JSON_PRETTY_PRINT)],
            ['key' => 'siem_json', 'title' => 'SIEM / webhook event (JSON envelope; webhooks add X-SAIP-Signature = sha256 HMAC of "timestamp.body")', 'lang' => 'json', 'body' => json_encode(['delivery_id' => 'a1b2c3d4e5f60718', 'sent_at' => '2026-10-30T09:16:00Z', 'tenant' => 'acme', 'events' => [['id' => 'o5521', 'type' => 'shadow_ai.detected', 'time' => '2026-10-30T09:15:02Z', 'tenant' => 'acme', 'data' => ['service' => 'ChatGPT', 'classification' => 'unsanctioned', 'computer' => 'WS-FIN-03', 'host' => 'chatgpt.com', 'process' => 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe']]]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)],
            ['key' => 'siem_cef', 'title' => 'Same event as CEF (syslog / ArcSight / QRadar)', 'lang' => 'text', 'body' => 'CEF:0|SAIP|Shadow AI Platform|1.0|shadow_ai.detected|Shadow AI detected: ChatGPT|7|rt=1793351702000 cs1Label=tenant cs1=acme externalId=o5521 shost=WS-FIN-03 dhost=chatgpt.com sproc=C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe cs2Label=service cs2=ChatGPT cs3Label=classification cs3=unsanctioned'],
        ];
    }
}
