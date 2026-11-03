<?php
declare(strict_types=1);

/**
 * Retention purge. Schedule daily (Task Scheduler: php tools\purge.php).
 * Per-company settings (table settings): retention_events_days (usage + network events), retention_discovery_days (excluded discoveries),
 * retention_heartbeat_days. 0 or missing = keep forever, except heartbeats which default to 90 days.
 *   php tools/purge.php [--dry-run]
 */
require __DIR__ . '/../app/bootstrap.php';

use Saip\{Audit, Db};

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$dry = in_array('--dry-run', $argv, true);

// Integration plumbing is short-lived: delivered outbox events after 14 days, delivery log after 30.
$ob = (int)Db::val('SELECT COUNT(*) FROM event_outbox WHERE created_at < UTC_TIMESTAMP() - INTERVAL 14 DAY');
$dl = (int)Db::val('SELECT COUNT(*) FROM integration_deliveries WHERE created_at < UTC_TIMESTAMP() - INTERVAL 30 DAY');
if (!$dry) { Db::run('DELETE FROM event_outbox WHERE created_at < UTC_TIMESTAMP() - INTERVAL 14 DAY'); Db::run('DELETE FROM integration_deliveries WHERE created_at < UTC_TIMESTAMP() - INTERVAL 30 DAY'); }
echo "event_outbox older than 14d -> $ob row(s); integration_deliveries older than 30d -> $dl row(s)" . ($dry ? " (dry run)\n" : " deleted\n");
foreach (Db::all('SELECT id, slug FROM tenants') as $t) {
    $s = [];
    foreach (Db::all("SELECT setting_key, setting_value FROM settings WHERE tenant_id = ? AND setting_key LIKE 'retention\\_%'", [$t['id']]) as $r) $s[$r['setting_key']] = (int)$r['setting_value'];
    $ev = $s['retention_events_days'] ?? 0;
    $dc = $s['retention_discovery_days'] ?? 0;
    $hb = $s['retention_heartbeat_days'] ?? 90;
    $plan = [
        ['ai_usage_events',            $ev, 'tenant_id = ? AND event_timestamp < UTC_TIMESTAMP() - INTERVAL ? DAY'],
        ['network_connection_events',  $ev, 'tenant_id = ? AND event_timestamp < UTC_TIMESTAMP() - INTERVAL ? DAY'],
        ['discovered_domains',         $dc, "tenant_id = ? AND status = 'excluded' AND last_seen < UTC_TIMESTAMP() - INTERVAL ? DAY"],
    ];
    foreach ($plan as [$table, $days, $where]) {
        if ($days <= 0) continue;
        $n = (int)Db::val("SELECT COUNT(*) FROM $table WHERE $where", [$t['id'], $days]);
        if (!$dry && $n > 0) Db::run("DELETE FROM $table WHERE $where", [$t['id'], $days]);
        echo "{$t['slug']}: $table older than {$days}d -> $n row(s)" . ($dry ? ' (dry run)' : ' deleted') . "\n";
        if (!$dry && $n > 0) Audit::log('system:purge', 'retention_purge', $table, ['days' => $days, 'rows' => $n], (int)$t['id']);
    }
    if ($hb > 0) {
        $n = (int)Db::val('SELECT COUNT(*) FROM collector_heartbeats h JOIN collectors c ON c.id = h.collector_id WHERE c.tenant_id = ? AND h.heartbeat_timestamp < UTC_TIMESTAMP() - INTERVAL ? DAY', [$t['id'], $hb]);
        if (!$dry && $n > 0) Db::run('DELETE h FROM collector_heartbeats h JOIN collectors c ON c.id = h.collector_id WHERE c.tenant_id = ? AND h.heartbeat_timestamp < UTC_TIMESTAMP() - INTERVAL ? DAY', [$t['id'], $hb]);
        echo "{$t['slug']}: collector_heartbeats older than {$hb}d -> $n row(s)" . ($dry ? ' (dry run)' : ' deleted') . "\n";
    }
}
