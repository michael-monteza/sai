<?php
declare(strict_types=1);

namespace Saip;

use Saip\Security\Secrets;

/**
 * Delivers outbox events (and, optionally, the raw usage stream) to each active integration: HTTPS webhooks (HMAC-signed JSON or CEF),
 * Splunk HTTP Event Collector, and syslog (UDP/TCP, RFC 5424 with CEF or JSON). Cursors only advance after a successful delivery, so
 * nothing is lost; failures back off exponentially. Run `php tools/dispatch-integrations.php` every minute (Task Scheduler / cron).
 */
final class IntegrationDispatcher
{
    private const OUTBOX_BATCH = 200;
    private const USAGE_BATCH = 500;

    /** @return list<array<string,mixed>> one summary per integration processed */
    public static function run(?int $only = null, bool $force = false): array
    {
        $out = [];
        $where = 'active = 1' . ($force ? '' : ' AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())') . ($only ? ' AND id = ' . (int)$only : '');
        foreach (Db::all("SELECT * FROM integrations WHERE $where ORDER BY id") as $i) $out[] = self::deliver($i);
        return $out;
    }

    /** @return array<string,mixed> */
    private static function deliver(array $i): array
    {
        $tid = (int)$i['tenant_id'];
        $types = array_filter(explode(',', (string)$i['events']));
        $batch = []; $maxOut = (int)$i['cursor_outbox']; $maxUse = (int)$i['cursor_usage'];
        foreach (Db::all('SELECT id, type, payload, created_at FROM event_outbox WHERE tenant_id = ? AND id > ? ORDER BY id LIMIT ' . self::OUTBOX_BATCH, [$tid, $maxOut]) as $r) {
            $maxOut = (int)$r['id'];
            if (in_array($r['type'], $types, true)) $batch[] = ['id' => 'o' . $r['id'], 'type' => $r['type'], 'time' => gmdate('Y-m-d\TH:i:s\Z', strtotime($r['created_at'] . ' UTC')), 'data' => json_decode($r['payload'], true) ?: []];
        }
        if (in_array('usage.event', $types, true)) {
            foreach (Db::all('SELECT e.id, e.computer_name, e.event_timestamp, e.query_domain, e.process_image, e.workstation_ip, s.service_name, s.sanction_status
                              FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id WHERE e.tenant_id = ? AND e.id > ? ORDER BY e.id LIMIT ' . self::USAGE_BATCH, [$tid, $maxUse]) as $r) {
                $maxUse = (int)$r['id'];
                $batch[] = ['id' => 'u' . $r['id'], 'type' => 'usage.event', 'time' => gmdate('Y-m-d\TH:i:s\Z', strtotime($r['event_timestamp'] . ' UTC')),
                            'data' => ['computer' => $r['computer_name'], 'service' => $r['service_name'], 'classification' => $r['sanction_status'], 'host' => $r['query_domain'], 'process' => $r['process_image'], 'workstation_ip' => $r['workstation_ip']]];
            }
        }
        if (!$batch) {
            Db::run('UPDATE integrations SET cursor_outbox = ?, cursor_usage = ?, next_attempt_at = NULL WHERE id = ?', [$maxOut, $maxUse, $i['id']]);
            return ['id' => (int)$i['id'], 'name' => $i['name'], 'sent' => 0, 'status' => 'idle'];
        }
        $slug = (string)Db::val('SELECT slug FROM tenants WHERE id = ?', [$tid]);
        $res = self::send($i, $batch, $slug);
        if ($res['ok']) {
            Db::run('UPDATE integrations SET cursor_outbox = ?, cursor_usage = ?, failures = 0, last_status = "ok", last_error = NULL, last_success_at = UTC_TIMESTAMP(), next_attempt_at = NULL WHERE id = ?', [$maxOut, $maxUse, $i['id']]);
        } else {
            $f = (int)$i['failures'] + 1;
            Db::run('UPDATE integrations SET failures = ?, last_status = "failed", last_error = ?, next_attempt_at = UTC_TIMESTAMP() + INTERVAL ? SECOND WHERE id = ?', [$f, mb_substr((string)$res['error'], 0, 300), min(3600, 30 * (2 ** min($f, 7))), $i['id']]);
        }
        Db::run('INSERT INTO integration_deliveries (integration_id, event_count, status, http_status, error, duration_ms) VALUES (?,?,?,?,?,?)',
            [$i['id'], count($batch), $res['ok'] ? 'ok' : 'failed', $res['http'], $res['ok'] ? null : mb_substr((string)$res['error'], 0, 300), $res['ms']]);
        return ['id' => (int)$i['id'], 'name' => $i['name'], 'sent' => $res['ok'] ? count($batch) : 0, 'status' => $res['ok'] ? 'ok' : 'failed', 'error' => $res['error']];
    }

    /** Sends one synthetic event without touching cursors (the "Send test" button). @return array{ok:bool,http:?int,error:?string,ms:int} */
    public static function test(array $i): array
    {
        $slug = (string)Db::val('SELECT slug FROM tenants WHERE id = ?', [(int)$i['tenant_id']]);
        return self::send($i, [['id' => 'test-' . bin2hex(random_bytes(4)), 'type' => 'test.ping', 'time' => gmdate('Y-m-d\TH:i:s\Z'), 'data' => ['message' => 'SAIP test event', 'integration' => $i['name']]]], $slug);
    }

    /** @param list<array<string,mixed>> $events @return array{ok:bool,http:?int,error:?string,ms:int} */
    private static function send(array $i, array $events, string $tenantSlug): array
    {
        $secret = Secrets::decrypt($i['secret_enc'] ?? null);
        $t0 = microtime(true);
        try {
            if ($i['kind'] === 'syslog') return self::syslog($i, $events, $tenantSlug, $t0);
            $now = time();
            if ($i['kind'] === 'splunk_hec') {
                $body = '';
                foreach ($events as $e) $body .= json_encode(['time' => strtotime($e['time']), 'host' => 'saip', 'source' => 'saip:' . $tenantSlug, 'sourcetype' => 'saip:' . $e['type'], 'event' => $e + ['tenant' => $tenantSlug]], JSON_UNESCAPED_SLASHES) . "\n";
                $h = ['Content-Type' => 'application/json', 'Authorization' => 'Splunk ' . $secret];
            } elseif ($i['format'] === 'cef') {
                $body = implode("\n", array_map(static fn ($e) => self::cef($e, $tenantSlug), $events)) . "\n";
                $h = ['Content-Type' => 'text/plain; charset=utf-8'];
            } else {
                $body = json_encode(['delivery_id' => bin2hex(random_bytes(8)), 'sent_at' => gmdate('Y-m-d\TH:i:s\Z', $now), 'tenant' => $tenantSlug, 'events' => array_map(static fn ($e) => $e + ['tenant' => $tenantSlug], $events)], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                $h = ['Content-Type' => 'application/json'];
            }
            if ($i['kind'] === 'webhook' && $secret) { $h['X-SAIP-Timestamp'] = (string)$now; $h['X-SAIP-Signature'] = 'sha256=' . hash_hmac('sha256', $now . '.' . $body, $secret); }
            $h['X-SAIP-Event-Count'] = (string)count($events);
            $r = HttpClient::request('POST', (string)$i['url'], $h, $body, 10);
            $ok = $r['error'] === null && $r['status'] >= 200 && $r['status'] < 300;
            return ['ok' => $ok, 'http' => $r['status'] ?: null, 'error' => $ok ? null : ($r['error'] ?? 'HTTP ' . $r['status']), 'ms' => $r['ms']];
        } catch (\Throwable $e) {
            return ['ok' => false, 'http' => null, 'error' => $e instanceof ApiException ? $e->getMessage() : $e->getMessage(), 'ms' => (int)((microtime(true) - $t0) * 1000)];
        }
    }

    private static function syslog(array $i, array $events, string $tenantSlug, float $t0): array
    {
        $proto = $i['protocol'] === 'udp' ? 'udp' : 'tcp';
        $sock = @stream_socket_client("$proto://{$i['host']}:{$i['port']}", $errno, $errstr, 5);
        if (!$sock) return ['ok' => false, 'http' => null, 'error' => "connect failed: $errstr ($errno)", 'ms' => (int)((microtime(true) - $t0) * 1000)];
        stream_set_timeout($sock, 5);
        foreach ($events as $e) {
            $msg = $i['format'] === 'cef' ? self::cef($e, $tenantSlug) : json_encode($e + ['tenant' => $tenantSlug], JSON_UNESCAPED_SLASHES);
            $pri = $e['type'] === 'shadow_ai.detected' ? 12 : 14;   // facility 1 (user), severity warning/info -> <PRI> = 8*1 + sev
            $line = '<' . (8 + ($pri === 12 ? 4 : 6)) . '>1 ' . gmdate('Y-m-d\TH:i:s\Z', strtotime($e['time'])) . ' saip SAIP - ' . preg_replace('/[^A-Za-z0-9._-]/', '_', $e['type']) . ' - ' . substr($msg, 0, 8000);
            if (@fwrite($sock, $line . "\n") === false) { fclose($sock); return ['ok' => false, 'http' => null, 'error' => 'write failed', 'ms' => (int)((microtime(true) - $t0) * 1000)]; }
        }
        fclose($sock);
        return ['ok' => true, 'http' => null, 'error' => null, 'ms' => (int)((microtime(true) - $t0) * 1000)];
    }

    /** ArcSight Common Event Format line. */
    public static function cef(array $e, string $tenant): string
    {
        $d = $e['data'] ?? [];
        $hdr = static fn (string $s): string => str_replace(['\\', '|', "\n", "\r"], ['\\\\', '\\|', ' ', ' '], $s);
        $ext = static fn (string $s): string => str_replace(['\\', '=', "\n", "\r"], ['\\\\', '\\=', '\\n', '\\n'], $s);
        [$name, $sev] = match ($e['type']) {
            'shadow_ai.detected' => ['Shadow AI detected: ' . ($d['service'] ?? ''), 7],
            'discovery.new_domain' => ['New AI-like domain discovered', 5],
            'usage.event' => ['AI service usage', 3],
            'audit.event' => [(string)($d['action'] ?? 'Audit event'), preg_match('/denied|failed|blocked|delete|csrf/', (string)($d['action'] ?? '')) ? 6 : 3],
            default => ['SAIP event', 1],
        };
        $kv = ['rt' => (string)(strtotime($e['time']) * 1000), 'cs1Label' => 'tenant', 'cs1' => $tenant, 'externalId' => (string)$e['id']];
        foreach (['actor' => 'suser', 'ip' => 'src', 'computer' => 'shost', 'host' => 'dhost', 'domain' => 'dhost', 'process' => 'sproc', 'record' => 'fname', 'workstation_ip' => 'src'] as $k => $cefKey) {
            if (isset($d[$k]) && $d[$k] !== '') $kv[$cefKey] = (string)$d[$k];
        }
        if (isset($d['service'])) { $kv['cs2Label'] = 'service'; $kv['cs2'] = (string)$d['service']; }
        if (isset($d['classification'])) { $kv['cs3Label'] = 'classification'; $kv['cs3'] = (string)$d['classification']; }
        if (isset($d['details'])) $kv['msg'] = is_string($d['details']) ? $d['details'] : json_encode($d['details'], JSON_UNESCAPED_SLASHES);
        $extStr = implode(' ', array_map(static fn ($k, $v) => $k . '=' . $ext($v), array_keys($kv), $kv));
        return 'CEF:0|SAIP|Shadow AI Platform|1.0|' . $hdr($e['type']) . '|' . $hdr($name) . '|' . $sev . '|' . $extStr;
    }
}
