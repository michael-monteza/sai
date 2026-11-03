<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Db, DomainRegistry, Risk, ServiceRepo, Validator};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Slim\Routing\RouteCollectorProxy as Group;

/** AI asset inventory: services CRUD, risk recalculation, export. */
final class InventoryModule extends Controller
{
    public static function register(Group $g): void
    {
        $g->get('/services', [self::class, 'list'])->add(new Need('inventory.read'));
        $g->post('/services', [self::class, 'create'])->add(new Need('inventory.write'));
        $g->post('/services/delete', [self::class, 'delete'])->add(new Need('inventory.delete'));
        $g->post('/services/{id:\d+}', [self::class, 'update'])->add(new Need('inventory.write'));
        $g->post('/risk/recalculate', [self::class, 'recalc'])->add(new Need('inventory.write'));
        $g->get('/export/inventory', [self::class, 'export'])->add(new Need('inventory.read'));
    }

    public function list(Request $req, Response $res): Response
    {
        return $this->json($res, ['services' => ServiceRepo::rows($this->tid($req))]);
    }

    public function create(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $u = $this->actor($req); $b = $this->body($req);
        $name = $this->str($b, 'service_name', 100, true);
        $domain = Validator::hostname($b['primary_domain'] ?? null);
        if ($domain === null) throw new ApiException(422, 'validation_failed', 'A valid primary domain is required.', ['primary_domain' => 'invalid']);
        if (Db::val('SELECT 1 FROM ai_services WHERE tenant_id = ? AND service_name = ?', [$t, $name])) throw new ApiException(409, 'duplicate', 'A service with this name already exists.');
        ServiceRepo::assertDomainsFree($t, [$domain], 0);

        $dc = in_array($b['data_class'] ?? 'Internal', ServiceRepo::DATA_CLASSES, true) ? ($b['data_class'] ?? 'Internal') : 'Internal';
        $tr = $this->pct($b, 'training_exposure') ?? 50; $vr = $this->pct($b, 'vendor_risk') ?? 50; $ir = $this->pct($b, 'identity_risk') ?? 50;
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            Db::run('INSERT INTO ai_services (tenant_id, service_name, provider, primary_domain, category, sanction_status, description, data_class,
                     training_exposure, vendor_risk, identity_risk, risk_score, owner, purpose, data_categories, lifecycle, source, website, created_by, updated_by)
                     VALUES (?,?,?,?,?, "unsanctioned", ?,?,?,?,?,?,?,?,?, "Shadow Usage Detected", "manual", ?,?,?)',
                [$t, $name, $this->str($b, 'provider', 100) ?? 'Unknown', $domain, $this->str($b, 'category', 60) ?? 'Generative AI', $this->str($b, 'description', 500),
                 $dc, $tr, $vr, $ir, Risk::score($dc, $tr, $vr, $ir, 0), $this->str($b, 'owner', 120) ?? 'Unassigned', $this->str($b, 'purpose', 500), $this->str($b, 'data_categories', 300),
                 $this->str($b, 'website', 255), $u, $u]);
            $id = Db::insertId();
            Db::run('INSERT INTO ai_domains (tenant_id, ai_service_id, domain, domain_type, created_by, updated_by) VALUES (?, ?, ?, "primary", ?, ?)', [$t, $id, $domain, $u, $u]);
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        $v = DomainRegistry::bump($t);
        Audit::log($u, 'service_created', $name, ['id' => $id, 'config_version' => $v], $t, null, ['service_name' => $name, 'primary_domain' => $domain]);
        return $this->json($res, ['id' => $id], 201);
    }

    public function update(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $u = $this->actor($req); $b = $this->body($req);
        $id = (int)$a['id'];
        $cur = Db::one('SELECT * FROM ai_services WHERE id = ? AND tenant_id = ?', [$id, $t]);
        if (!$cur) throw new ApiException(404, 'not_found', 'Unknown service.');
        $set = [];   // allow-list: no mass assignment of arbitrary columns

        foreach (['service_name' => 100, 'provider' => 100, 'category' => 60, 'description' => 500, 'owner' => 120, 'purpose' => 500, 'data_categories' => 300, 'website' => 255, 'logo_url' => 255] as $k => $max) {
            if (array_key_exists($k, $b)) {
                $v = $this->str($b, $k, $max, in_array($k, ['service_name', 'provider'], true));
                $set[$k] = $v ?? ($k === 'owner' ? 'Unassigned' : null);
            }
        }
        foreach (['website', 'logo_url'] as $k) {
            if (!empty($set[$k]) && !preg_match('#^https?://#i', $set[$k])) throw new ApiException(422, 'validation_failed', "$k must start with http:// or https://.", [$k => 'invalid']);
        }
        if (isset($set['service_name']) && $set['service_name'] !== $cur['service_name'] && Db::val('SELECT 1 FROM ai_services WHERE tenant_id = ? AND service_name = ?', [$t, $set['service_name']])) {
            throw new ApiException(409, 'duplicate', 'A service with this name already exists.');
        }
        if (isset($b['data_class'])) {
            if (!in_array($b['data_class'], ServiceRepo::DATA_CLASSES, true)) throw new ApiException(422, 'validation_failed', 'Invalid data_class.');
            $set['data_class'] = $b['data_class'];
        }
        foreach (['training_exposure', 'vendor_risk', 'identity_risk'] as $k) {
            if (($v = $this->pct($b, $k)) !== null) $set[$k] = $v;
        }
        if (array_key_exists('active', $b)) $set['active'] = $b['active'] ? 1 : 0;
        if (array_key_exists('archived', $b)) $set['archived'] = $b['archived'] ? 1 : 0;

        $lifeChanged = false;
        if (isset($b['lifecycle'])) {
            if (!isset(ServiceRepo::LIFE_TO_STATUS[$b['lifecycle']])) throw new ApiException(422, 'validation_failed', 'Invalid lifecycle.');
            $set['lifecycle'] = $b['lifecycle']; $set['sanction_status'] = ServiceRepo::LIFE_TO_STATUS[$b['lifecycle']]; $lifeChanged = true;
        } elseif (isset($b['sanction_status'])) {
            if (!in_array($b['sanction_status'], ServiceRepo::STATUSES, true)) throw new ApiException(422, 'validation_failed', 'Invalid sanction_status.');
            $set['sanction_status'] = $b['sanction_status'];
            $set['lifecycle'] = match ($b['sanction_status']) {
                'sanctioned' => 'Formally Sanctioned', 'under_review' => 'Under Security Evaluation',
                default => in_array($cur['lifecycle'], ['Prohibited / Blocked', 'Decommissioned'], true) ? $cur['lifecycle'] : 'Shadow Usage Detected',
            };
            $lifeChanged = true;
        }

        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            if (isset($b['domains'])) {
                if (!is_array($b['domains'])) throw new ApiException(422, 'validation_failed', 'domains must be a list.');
                $list = [];
                foreach ($b['domains'] as $d) {
                    $h = Validator::hostname($d);
                    if ($h === null) throw new ApiException(422, 'validation_failed', 'Invalid domain: ' . (is_string($d) ? $d : '?'));
                    $list[$h] = true;
                }
                $list = array_keys($list);
                if (!$list) throw new ApiException(422, 'validation_failed', 'A service needs at least one domain.');
                ServiceRepo::assertDomainsFree($t, $list, $id);
                Db::run('DELETE FROM ai_domains WHERE ai_service_id = ? AND domain NOT IN (' . $this->in($list) . ')', array_merge([$id], $list));
                foreach ($list as $d) Db::run('INSERT IGNORE INTO ai_domains (tenant_id, ai_service_id, domain, created_by, updated_by) VALUES (?, ?, ?, ?, ?)', [$t, $id, $d, $u, $u]);
                $set['primary_domain'] = in_array($cur['primary_domain'], $list, true) ? $cur['primary_domain'] : $list[0];
            }
            $merged = $set + $cur;
            $set['risk_score'] = Risk::score($merged['data_class'], (int)$merged['training_exposure'], (int)$merged['vendor_risk'], (int)$merged['identity_risk'], (int)$merged['usage_volume']);
            $set['updated_at'] = gmdate('Y-m-d H:i:s');
            $set['updated_by'] = $u;
            $cols = implode(', ', array_map(static fn ($k) => "`$k` = ?", array_keys($set)));
            Db::run("UPDATE ai_services SET $cols WHERE id = ? AND tenant_id = ?", array_merge(array_values($set), [$id, $t]));
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        $changes = array_diff_key($set, ['updated_at' => 1, 'updated_by' => 1]);
        $affectsConfig = isset($b['domains']) || array_intersect(['active', 'archived', 'sanction_status', 'service_name'], array_keys($set));
        $v = $affectsConfig ? DomainRegistry::bump($t) : DomainRegistry::version($t);
        Audit::log($u, 'service_updated', $cur['service_name'], $changes + ['config_version' => $v], $t, array_intersect_key($cur, $changes), $changes);
        return $this->json($res, ['service' => ServiceRepo::rows($t, $id)[0]]);
    }

    /** POST services/delete {ids, preview?}: removes the service, its domains and every event recorded against it. */
    public function delete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $ph = $this->in($ids);
        $rows = Db::all("SELECT id, service_name FROM ai_services WHERE tenant_id = ? AND id IN ($ph)", array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching services.');
        $ids = array_map(static fn ($r) => (int)$r['id'], $rows); $ph = $this->in($ids);
        $impact = [
            'records' => count($rows), 'names' => array_column($rows, 'service_name'),
            'domains' => (int)Db::val("SELECT COUNT(*) FROM ai_domains WHERE ai_service_id IN ($ph)", $ids),
            'events' => (int)Db::val("SELECT COUNT(*) FROM ai_usage_events WHERE tenant_id = ? AND ai_service_id IN ($ph)", array_merge([$t], $ids)),
            'network_events' => (int)Db::val("SELECT COUNT(*) FROM network_connection_events WHERE tenant_id = ? AND ai_service_id IN ($ph)", array_merge([$t], $ids)),
        ];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            Db::run("DELETE FROM network_connection_events WHERE tenant_id = ? AND ai_service_id IN ($ph)", array_merge([$t], $ids));
            Db::run("DELETE FROM ai_usage_events WHERE tenant_id = ? AND ai_service_id IN ($ph)", array_merge([$t], $ids));
            Db::run("UPDATE access_requests SET service_id = NULL WHERE tenant_id = ? AND service_id IN ($ph)", array_merge([$t], $ids));
            Db::run("UPDATE discovered_domains SET classified_service_id = NULL, status = 'new' WHERE tenant_id = ? AND classified_service_id IN ($ph)", array_merge([$t], $ids));
            Db::run("DELETE FROM ai_services WHERE tenant_id = ? AND id IN ($ph)", array_merge([$t], $ids));   // ai_domains cascade
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        $v = DomainRegistry::bump($t);
        Audit::log($this->actor($req), 'service_deleted', implode(', ', array_slice($impact['names'], 0, 5)), $impact + ['config_version' => $v], $t, $impact, null);
        return $this->json($res, ['deleted' => $impact, 'config_version' => $v]);
    }

    public function recalc(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $n = Risk::recalculate($t);
        Audit::log($this->actor($req), 'risk_recalculated', null, ['services' => $n], $t);
        return $this->json($res, ['updated' => $n]);
    }

    public function export(Request $req, Response $res): Response
    {
        $rows = array_map(static fn ($s) => [$s['service_name'], $s['provider'], $s['primary_domain'], $s['sanction_status'], $s['lifecycle'], $s['risk_level'], $s['risk_score'],
            $s['data_class'], $s['owner'], $s['workstations_30d'], $s['events_30d'], $s['last_seen']], ServiceRepo::rows($this->tid($req)));
        Audit::log($this->actor($req), 'export_inventory', null, ['rows' => count($rows)], $this->tid($req));
        return $this->raw($res, $this->csv(['Service', 'Provider', 'Primary domain', 'Sanction status', 'Lifecycle', 'Risk level', 'Risk score', 'Data class', 'Owner', 'Workstations (30d)', 'Observed DNS events (30d)', 'Last observed (UTC)'], $rows), 'text/csv; charset=utf-8', 'ai-inventory.csv');
    }
}
