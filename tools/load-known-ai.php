<?php
declare(strict_types=1);

/**
 * Loads well-known AI services (sql/known_ai_services.php) into the template catalogue (so new companies get them)
 * and into existing companies' AI Asset Inventory Register / DNS registry. Safe to re-run: existing names and domains are skipped.
 *   php tools/load-known-ai.php [company-slug | --all] [--dry-run]
 * New services start as Unsanctioned (shadow) until a governance decision is made.
 */
require_once __DIR__ . '/../app/bootstrap.php';

use Saip\{Audit, Db, DomainRegistry, Risk};

if (PHP_SAPI !== 'cli' && !defined('SAIP_INSTALLER')) { http_response_code(404); exit; }
$args = array_slice($argv, 1);
$dry = in_array('--dry-run', $args, true);
$target = array_values(array_filter($args, static fn ($a) => !str_starts_with($a, '--')))[0] ?? '--all';
$list = require __DIR__ . '/../sql/known_ai_services.php';

$tenants = $target === '--all' ? Db::all('SELECT id, slug FROM tenants') : Db::all('SELECT id, slug FROM tenants WHERE slug = ?', [$target]);
if (!$tenants) { fwrite(STDERR, "No such company.\n"); exit(2); }
$split = static function (string $d): array { [$h, $t] = array_pad(explode('|', $d, 2), 2, null); return [strtolower($h), $t]; };

// 1) template catalogue
$cat = 0;
foreach ($list as [$name, $prov, $category, $dc, [$tr, $vr, $ir], $desc, $domains]) {
    if (Db::val('SELECT 1 FROM catalog_services WHERE service_name = ?', [$name])) continue;
    $cat++;
    if ($dry) continue;
    Db::run('INSERT INTO catalog_services (service_name, provider, primary_domain, category, description, data_class, training_exposure, vendor_risk, identity_risk) VALUES (?,?,?,?,?,?,?,?,?)',
        [$name, $prov, $split($domains[0])[0], $category, $desc, $dc, $tr, $vr, $ir]);
    $cid = Db::insertId();
    foreach ($domains as $d) Db::run('INSERT IGNORE INTO catalog_domains (catalog_service_id, domain) VALUES (?, ?)', [$cid, $split($d)[0]]);
}
echo "Template catalogue: $cat service(s) " . ($dry ? 'would be ' : '') . "added.\n";

// 2) each company's inventory + registry
foreach ($tenants as $t) {
    $tid = (int)$t['id']; $added = $skipped = $domainsAdded = 0;
    foreach ($list as [$name, $prov, $category, $dc, [$tr, $vr, $ir], $desc, $domains]) {
        if (Db::val('SELECT 1 FROM ai_services WHERE tenant_id = ? AND service_name = ?', [$tid, $name])) { $skipped++; continue; }
        $free = [];
        foreach ($domains as $d) { [$h, $type] = $split($d); if (!Db::val('SELECT 1 FROM ai_domains WHERE tenant_id = ? AND domain = ?', [$tid, $h])) $free[] = [$h, $type]; }
        if (!$free) { $skipped++; continue; }                        // every domain already belongs to another service
        $added++;
        if ($dry) { $domainsAdded += count($free); continue; }
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            Db::run('INSERT INTO ai_services (tenant_id, service_name, provider, primary_domain, category, sanction_status, description, data_class, training_exposure, vendor_risk, identity_risk, risk_score, owner, lifecycle, source, created_by, updated_by)
                     VALUES (?,?,?,?,?, "unsanctioned", ?,?,?,?,?,?, "Unassigned", "Shadow Usage Detected", "registry", "seed", "seed")',
                [$tid, $name, $prov, $free[0][0], $category, $desc, $dc, $tr, $vr, $ir, Risk::score($dc, $tr, $vr, $ir, 0)]);
            $sid = Db::insertId();
            foreach ($free as $i => [$h, $type]) {
                Db::run('INSERT INTO ai_domains (tenant_id, ai_service_id, domain, domain_type, matching_rule, created_by, updated_by) VALUES (?,?,?,?, "subdomain", "seed", "seed")',
                    [$tid, $sid, $h, $type ?? ($i === 0 ? 'primary' : 'secondary')]);
                $domainsAdded++;
            }
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
    }
    if (!$dry && $added) {
        $v = DomainRegistry::bump($tid);
        Audit::log('cli:load-known-ai', 'service_created', "$added known AI services", ['services' => $added, 'domains' => $domainsAdded, 'config_version' => $v], $tid);
    }
    echo "{$t['slug']}: $added service(s) " . ($dry ? 'would be ' : '') . "added ($domainsAdded domains), $skipped skipped (already present).\n";
}
