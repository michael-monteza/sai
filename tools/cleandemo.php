<?php
declare(strict_types=1);

/**
 * Clean sample / test data. KEEPS the AI services, the DNS registry (domains), the catalogue, policies, users, settings, integrations and the audit log.
 * Removes: usage events, network events, collector heartbeats, workstations (collectors + department mapping), discovered/unknown domains,
 * access requests, the sample ISO evidence written by loaddemodata.php, and queued/delivered integration events.
 *
 *   php tools\cleandemo.php <company-slug | --all>            preview only: shows what would be deleted
 *   php tools\cleandemo.php <company-slug | --all> --yes      delete
 *   add --demo-only to touch only DEMO-* workstations and their events (safe on a company that also has real collectors)
 */
require __DIR__ . '/../app/bootstrap.php';

use Saip\{Audit, Db, Risk};

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$args = array_slice($argv, 1);
$yes = in_array('--yes', $args, true);
$demoOnly = in_array('--demo-only', $args, true);
$target = array_values(array_filter($args, static fn ($a) => !str_starts_with($a, '--')))[0] ?? ($args && in_array('--all', $args, true) ? '--all' : null);
if ($target === null) { fwrite(STDERR, "Usage: php tools\cleandemo.php <company-slug | --all> [--yes] [--demo-only]\n"); exit(2); }
$tenants = $target === '--all' ? Db::all('SELECT id, slug FROM tenants') : Db::all('SELECT id, slug FROM tenants WHERE slug = ?', [$target]);
if (!$tenants) { fwrite(STDERR, "No such company: $target\n"); exit(2); }

$like = $demoOnly ? " AND computer_name LIKE 'DEMO-%'" : '';
foreach ($tenants as $tn) {
    $t = (int)$tn['id'];
    // [label, count SQL, delete SQL] - events first, then the workstations they point to.
    $plan = [
        ['usage events',       "SELECT COUNT(*) FROM ai_usage_events WHERE tenant_id = ?$like",              "DELETE FROM ai_usage_events WHERE tenant_id = ?$like"],
        ['network events',     "SELECT COUNT(*) FROM network_connection_events WHERE tenant_id = ?$like",    "DELETE FROM network_connection_events WHERE tenant_id = ?$like"],
        ['heartbeats',         "SELECT COUNT(*) FROM collector_heartbeats h JOIN collectors c ON c.id = h.collector_id WHERE c.tenant_id = ?" . ($demoOnly ? " AND c.computer_name LIKE 'DEMO-%'" : ''),
                               "DELETE h FROM collector_heartbeats h JOIN collectors c ON c.id = h.collector_id WHERE c.tenant_id = ?" . ($demoOnly ? " AND c.computer_name LIKE 'DEMO-%'" : '')],
        ['workstations',       "SELECT COUNT(*) FROM collectors WHERE tenant_id = ?$like",                   "DELETE FROM collectors WHERE tenant_id = ?$like"],
        ['department mapping', "SELECT COUNT(*) FROM employee_inventory WHERE tenant_id = ?$like",           "DELETE FROM employee_inventory WHERE tenant_id = ?$like"],
    ];
    if ($demoOnly) {
        $plan[] = ['discovered domains', "SELECT COUNT(DISTINCT d.id) FROM discovered_domains d JOIN discovered_domain_hosts h ON h.discovered_id = d.id WHERE d.tenant_id = ? AND h.computer_name LIKE 'DEMO-%'",
                                         "DELETE d FROM discovered_domains d JOIN discovered_domain_hosts h ON h.discovered_id = d.id WHERE d.tenant_id = ? AND h.computer_name LIKE 'DEMO-%'"];
    } else {
        $plan[] = ['discovered domains', 'SELECT COUNT(*) FROM discovered_domains WHERE tenant_id = ?', 'DELETE FROM discovered_domains WHERE tenant_id = ?'];
        $plan[] = ['unknown domains',    'SELECT COUNT(*) FROM unknown_domains WHERE tenant_id = ?',    'DELETE FROM unknown_domains WHERE tenant_id = ?'];
        $plan[] = ['access requests',    'SELECT COUNT(*) FROM access_requests WHERE tenant_id = ?',    'DELETE FROM access_requests WHERE tenant_id = ?'];
        $plan[] = ['sample ISO evidence', "SELECT COUNT(*) FROM iso_controls WHERE tenant_id = ? AND notes = 'Demo data - not a real assessment'",
                                          "UPDATE iso_controls SET compliant = 0, evidence = NULL, notes = NULL, updated_at = NULL, updated_by = NULL WHERE tenant_id = ? AND notes = 'Demo data - not a real assessment'"];
        $plan[] = ['integration events', 'SELECT COUNT(*) FROM event_outbox WHERE tenant_id = ?',    'DELETE FROM event_outbox WHERE tenant_id = ?'];
    }
    echo ($yes ? 'Cleaning' : 'Would clean') . " '{$tn['slug']}'" . ($demoOnly ? ' (DEMO-* only)' : '') . ":\n";
    $removed = [];
    foreach ($plan as [$label, $count, $delete]) {
        try {
            $n = (int)Db::val($count, [$t]);
            if ($yes && $n > 0) Db::run($delete, [$t]);
            $removed[$label] = $n;
            printf("  %-20s %d\n", $label, $n);
        } catch (\Throwable $e) {   // a table that this install does not have (older schema) is skipped
            printf("  %-20s skipped (%s)\n", $label, $e->getMessage());
        }
    }
    if ($yes) {
        Risk::recalculate($t);
        Audit::log('system:cleandemo', 'demo_data_cleaned', $tn['slug'], $removed + ['demo_only' => $demoOnly], $t);
    }
}
echo $yes ? "Done. AI services, the DNS registry and everything else were left untouched.\n" : "Nothing was deleted. Run again with --yes to delete.\n";
