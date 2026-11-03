<?php
declare(strict_types=1);

/**
 * Loads the "Top 100 AI Services, FQDNs, DNS Registrars & Functional Purposes" directory (sql/top100_ai_services.php)
 * into the AI Asset Inventory Register and the DNS registry of one or all companies, and into the template catalogue for new companies.
 *   php tools/load-top100.php [company-slug | --all] [--dry-run]
 * Services start Unsanctioned (shadow); broad shared domains (notion.so, canva.com, ...) start Under Review and are flagged shared.
 * Safe to re-run. Manage the result in the console under "FQDN Directory" (AI Services & DNS).
 */
require_once __DIR__ . '/../app/bootstrap.php';

use Saip\{AiCatalogImporter, Db};

if (PHP_SAPI !== 'cli' && !defined('SAIP_INSTALLER')) { http_response_code(404); exit; }
$args = array_slice($argv, 1);
$dry = in_array('--dry-run', $args, true);
$target = array_values(array_filter($args, static fn ($a) => !str_starts_with($a, '--')))[0] ?? '--all';
$data = require __DIR__ . '/../sql/top100_ai_services.php';
$rows = array_map(static fn ($r) => ['service' => $r[0], 'endpoint' => $r[1], 'fqdn' => $r[2], 'root' => $r[3], 'registrar' => $r[4], 'purpose' => $r[5], 'category' => $r[6]], $data['rows']);

$tenants = $target === '--all' ? Db::all('SELECT id, slug FROM tenants') : Db::all('SELECT id, slug FROM tenants WHERE slug = ?', [$target]);
if (!$tenants) { fwrite(STDERR, "No such company.\n"); exit(2); }

if (!$dry) {   // template catalogue: new companies start with these services
    $svc = 0;
    $seen = [];
    foreach ($rows as $r) {
        $cid = $seen[$r['service']] ??= (int)Db::val('SELECT id FROM catalog_services WHERE service_name = ?', [$r['service']]);
        if (!$cid) {
            [$dc, $tr, $vr, $ir] = AiCatalogImporter::profile($r['category'], $r['registrar']);
            Db::run('INSERT INTO catalog_services (service_name, provider, primary_domain, category, description, data_class, training_exposure, vendor_risk, identity_risk) VALUES (?,?,?,?,?,?,?,?,?)',
                [$r['service'], 'Unknown', ltrim($r['fqdn'], '*.'), mb_substr($r['category'], 0, 60), mb_substr($r['purpose'], 0, 500), $dc, $tr, $vr, $ir]);
            $cid = $seen[$r['service']] = Db::insertId(); $svc++;
        }
        $d = ltrim($r['fqdn'], '*.');
        if (!str_contains($d, '*')) Db::run('INSERT IGNORE INTO catalog_domains (catalog_service_id, domain) VALUES (?, ?)', [$cid, $d]);
    }
    echo "Template catalogue: $svc service(s) added.\n";
}
foreach ($tenants as $t) {
    $r = AiCatalogImporter::import((int)$t['id'], $rows, 'cli:load-top100', $data['shared'], $dry);
    echo "{$t['slug']}: services +{$r['services_created']} (existing matched {$r['services_matched']}), domains +{$r['domains_added']} (enriched {$r['domains_updated']}), skipped " . count($r['skipped']) . ", errors " . count($r['errors']) . ($dry ? "  [dry run]\n" : "\n");
    foreach (array_slice($r['errors'], 0, 10) as $e) echo "   error row {$e['row']}: {$e['reason']}\n";
}
