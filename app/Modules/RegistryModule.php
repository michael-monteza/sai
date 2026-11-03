<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{AiCatalogImporter, ApiException, Audit, Db, DomainRegistry, IpIntel};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Slim\Routing\RouteCollectorProxy as Group;

/** AI services & DNS registry (domain CRUD), change history and collector monitoring options. */
final class RegistryModule extends Controller
{
    private const TYPES = ['primary', 'secondary', 'api', 'authentication', 'cdn', 'other'];
    private const RULES = ['exact', 'subdomain'];

    public static function register(Group $g): void
    {
        $g->get('/registry', [self::class, 'index'])->add(new Need('registry.read'));
        $g->get('/registry/history', [self::class, 'history'])->add(new Need('registry.read'));
        $g->get('/registry/domains', [self::class, 'domains'])->add(new Need('registry.read'));
        $g->post('/registry/import', [self::class, 'import'])->add(new Need('registry.write'));
        $g->post('/registry/domains', [self::class, 'domainCreate'])->add(new Need('registry.write'));
        $g->post('/registry/domains/delete', [self::class, 'domainDelete'])->add(new Need('registry.delete'));
        $g->post('/registry/domains/{id:\d+}', [self::class, 'domainUpdate'])->add(new Need('registry.write'));
        $g->get('/monitoring', [self::class, 'monitoring'])->add(new Need('registry.read'));
        $g->post('/monitoring', [self::class, 'monitoringSave'])->add(new Need('monitoring.write'));
        $g->get('/ip-map', [self::class, 'ipStatus'])->add(new Need('registry.read'));
        $g->post('/ip-map/refresh', [self::class, 'ipRefresh'])->add(new Need('monitoring.write'));
    }

    public function index(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $domains = [];
        foreach (Db::all('SELECT d.*, (SELECT COUNT(*) FROM ai_usage_events e WHERE e.tenant_id = d.tenant_id AND e.ai_service_id = d.ai_service_id
                                       AND (e.query_domain = d.domain OR e.query_domain LIKE CONCAT("%.", d.domain))) hits
                          FROM ai_domains d WHERE d.tenant_id = ? ORDER BY d.domain', [$t]) as $r) {
            $domains[$r['ai_service_id']][] = $r;
        }
        $services = Db::all('SELECT id, service_name, provider, primary_domain, category, sanction_status, website, logo_url, description, active, archived,
                                    created_by, updated_by, created_at, updated_at FROM ai_services WHERE tenant_id = ? ORDER BY service_name', [$t]);
        foreach ($services as &$s) $s['domains'] = $domains[$s['id']] ?? [];
        return $this->json($res, ['services' => $services, 'config_version' => DomainRegistry::version($t)]);
    }

    public function history(Request $req, Response $res): Response
    {
        return $this->json($res, ['history' => Db::all(
            "SELECT id, administrator, action, affected_record, timestamp, before_json, after_json, ip_address FROM audit_logs
             WHERE tenant_id = ? AND (action LIKE 'registry\\_%' OR action LIKE 'service\\_%') ORDER BY id DESC LIMIT 300", [$this->tid($req)])]);
    }

    public function domainCreate(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $u = $this->actor($req); $b = $this->body($req);
        $sid = (int)($b['service_id'] ?? 0);
        $svc = Db::one('SELECT id, service_name FROM ai_services WHERE id = ? AND tenant_id = ?', [$sid, $t]);
        if (!$svc) throw new ApiException(404, 'not_found', 'Unknown service.');
        $n = DomainRegistry::normalize($b['domain'] ?? null);
        if (!$n) throw new ApiException(422, 'validation_failed', 'A valid hostname is required (IP addresses are not accepted).', ['domain' => 'invalid']);
        [$host, $implied] = $n;
        $type = in_array($b['domain_type'] ?? 'secondary', self::TYPES, true) ? ($b['domain_type'] ?? 'secondary') : 'secondary';
        $rule = $implied ?? (in_array($b['matching_rule'] ?? 'subdomain', self::RULES, true) ? ($b['matching_rule'] ?? 'subdomain') : 'subdomain');
        $other = Db::one('SELECT s.service_name FROM ai_domains d JOIN ai_services s ON s.id = d.ai_service_id WHERE d.tenant_id = ? AND d.domain = ?', [$t, $host]);
        if ($other) throw new ApiException(409, 'domain_in_use', "$host is already registered under {$other['service_name']}.");
        $notes = isset($b['notes']) && is_string($b['notes']) ? mb_substr(trim($b['notes']), 0, 500) : null;
        [$root, $registrar, $purpose, $category] = $this->meta($b);
        Db::run('INSERT INTO ai_domains (tenant_id, ai_service_id, domain, root_domain, registrar, purpose, category, domain_type, matching_rule, notes, shared, created_by, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
            [$t, $sid, $host, $root, $registrar, $purpose, $category, $type, $rule, $notes, empty($b['shared']) ? 0 : 1, $u, $u]);
        $id = Db::insertId();
        $v = DomainRegistry::bump($t);
        Audit::log($u, 'registry_domain_added', $host, ['service' => $svc['service_name'], 'config_version' => $v], $t, null, ['domain' => $host, 'type' => $type, 'matching_rule' => $rule]);
        return $this->json($res, ['id' => $id, 'config_version' => $v], 201);
    }

    public function domainUpdate(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $u = $this->actor($req); $b = $this->body($req);
        $cur = Db::one('SELECT * FROM ai_domains WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t]);
        if (!$cur) throw new ApiException(404, 'not_found', 'Unknown domain.');
        $set = [];
        if (isset($b['domain_type'])) {
            if (!in_array($b['domain_type'], self::TYPES, true)) throw new ApiException(422, 'validation_failed', 'Invalid domain_type.');
            $set['domain_type'] = $b['domain_type'];
        }
        if (isset($b['matching_rule'])) {
            if (!in_array($b['matching_rule'], self::RULES, true)) throw new ApiException(422, 'validation_failed', 'Invalid matching_rule.');
            $set['matching_rule'] = $b['matching_rule'];
        }
        foreach (['root_domain' => 253, 'registrar' => 150, 'purpose' => 400, 'category' => 100] as $k => $max) {
            if (array_key_exists($k, $b)) $set[$k] = $this->str($b, $k, $max);
        }
        if (isset($b['domain']) && $b['domain'] !== $cur['domain']) {
            $n = DomainRegistry::normalize($b['domain']);
            if (!$n) throw new ApiException(422, 'validation_failed', 'A valid hostname is required (IP addresses are not accepted).', ['domain' => 'invalid']);
            if (Db::val('SELECT 1 FROM ai_domains WHERE tenant_id = ? AND domain = ? AND id <> ?', [$t, $n[0], $cur['id']])) throw new ApiException(409, 'domain_in_use', "{$n[0]} is already registered.");
            $set['domain'] = $n[0];
            if ($n[1]) $set['matching_rule'] = $n[1];
        }
        if (array_key_exists('notes', $b)) $set['notes'] = is_string($b['notes']) && $b['notes'] !== '' ? mb_substr(trim($b['notes']), 0, 500) : null;
        if (array_key_exists('active', $b)) $set['active'] = $b['active'] ? 1 : 0;
        if (array_key_exists('shared', $b)) $set['shared'] = $b['shared'] ? 1 : 0;
        if (!$set) throw new ApiException(422, 'validation_failed', 'Nothing to update.');
        $set['updated_by'] = $u;
        $set['updated_at'] = gmdate('Y-m-d H:i:s');
        $cols = implode(', ', array_map(static fn ($k) => "`$k` = ?", array_keys($set)));
        Db::run("UPDATE ai_domains SET $cols WHERE id = ?", array_merge(array_values($set), [$cur['id']]));
        $v = DomainRegistry::bump($t);
        $keys = array_diff(array_keys($set), ['updated_by', 'updated_at']);
        Audit::log($u, 'registry_domain_updated', $cur['domain'], ['config_version' => $v], $t, array_intersect_key($cur, array_flip($keys)), array_intersect_key($set, array_flip($keys)));
        return $this->json($res, ['config_version' => $v]);
    }

    /** POST registry/domains/delete {ids, preview?}: a service keeps at least one domain. */
    public function domainDelete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $rows = Db::all('SELECT id, domain, ai_service_id FROM ai_domains WHERE tenant_id = ? AND id IN (' . $this->in($ids) . ')', array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching domains.');
        $rid = array_map(static fn ($r) => (int)$r['id'], $rows);
        foreach (array_unique(array_column($rows, 'ai_service_id')) as $sid) {
            $left = (int)Db::val('SELECT COUNT(*) FROM ai_domains WHERE ai_service_id = ? AND id NOT IN (' . $this->in($rid) . ')', array_merge([$sid], $rid));
            if ($left === 0) throw new ApiException(409, 'last_domain', 'A service needs at least one domain. Delete the service instead, or add another domain first.');
        }
        $impact = ['records' => count($rows), 'names' => array_column($rows, 'domain')];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        Db::run('DELETE FROM ai_domains WHERE tenant_id = ? AND id IN (' . $this->in($rid) . ')', array_merge([$t], $rid));
        $v = DomainRegistry::bump($t);
        Audit::log($this->actor($req), 'registry_domain_deleted', implode(', ', array_slice($impact['names'], 0, 5)), $impact + ['config_version' => $v], $t, $impact, null);
        return $this->json($res, ['deleted' => $impact, 'config_version' => $v]);
    }

    /** @return array{0:?string,1:?string,2:?string,3:?string} root_domain, registrar, purpose, category from a request body */
    private function meta(array $b): array
    {
        $root = $this->str($b, 'root_domain', 253);
        if ($root !== null && ($root = \Saip\Validator::hostname($root)) === null) throw new ApiException(422, 'validation_failed', 'Invalid root domain.', ['root_domain' => 'invalid']);
        return [$root, $this->str($b, 'registrar', 150), $this->str($b, 'purpose', 400), $this->str($b, 'category', 100)];
    }

    /** GET registry/domains: the flat FQDN directory (one row per registered domain, with its service, registrar and purpose). */
    public function domains(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        return $this->json($res, ['domains' => Db::all(
            'SELECT d.id, d.domain, d.root_domain, d.registrar, d.purpose, d.category, d.domain_type, d.matching_rule, d.active, d.shared, d.notes, d.first_observed, d.last_observed,
                    d.ai_service_id service_id, s.service_name, s.provider, s.sanction_status, s.archived,
                    (SELECT COUNT(*) FROM ai_usage_events e WHERE e.tenant_id = d.tenant_id AND e.ai_service_id = d.ai_service_id AND (e.query_domain = d.domain OR e.query_domain LIKE CONCAT("%.", d.domain))) hits
             FROM ai_domains d JOIN ai_services s ON s.id = d.ai_service_id WHERE d.tenant_id = ? ORDER BY d.domain', [$t]),
            'config_version' => DomainRegistry::version($t)]);
    }

    /** POST registry/import {rows:[{service, fqdn, root?, registrar?, purpose?, category?, endpoint?}], dry_run?}: bulk add services and FQDNs. */
    public function import(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $rows = $b['rows'] ?? null;
        if (!is_array($rows) || !array_is_list($rows) || !$rows) throw new ApiException(422, 'validation_failed', '"rows" must be a non-empty list.');
        if (count($rows) > 1000) throw new ApiException(413, 'too_many_rows', 'At most 1000 rows per import.');
        $clean = [];
        foreach ($rows as $r) {
            if (!is_array($r)) { $clean[] = []; continue; }
            $clean[] = array_map(static fn ($v) => is_string($v) ? $v : '', array_intersect_key($r, array_flip(['service', 'fqdn', 'root', 'registrar', 'purpose', 'category', 'endpoint'])));
        }
        $result = AiCatalogImporter::import($t, $clean, $this->actor($req), [], !empty($b['dry_run']));
        $result['skipped'] = array_slice($result['skipped'], 0, 100); $result['errors'] = array_slice($result['errors'], 0, 100);
        return $this->json($res, $result + ['dry_run' => !empty($b['dry_run']), 'config_version' => DomainRegistry::version($t)]);
    }

    /** GET ip-map: how many registered-service addresses are known and usable for IP matching of network connections. */
    public function ipStatus(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        return $this->json($res, ['status' => IpIntel::status($t), 'network_events' => DomainRegistry::monitoring($t)['network_events']]);
    }

    /** POST ip-map/refresh: re-resolve the registry's FQDNs. Collectors pick up the new address list on their next sync. */
    public function ipRefresh(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        @set_time_limit(180);
        $r = IpIntel::refresh($t, false);   // fast: reverse-DNS results come from the cache (the scheduled job fills it)
        $v = DomainRegistry::bump($t);
        Audit::log($this->actor($req), 'ip_map_refreshed', null, $r + ['config_version' => $v], $t);
        return $this->json($res, ['refreshed' => $r, 'status' => IpIntel::status($t), 'config_version' => $v]);
    }

    public function monitoring(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        return $this->json($res, ['monitoring' => DomainRegistry::monitoring($t), 'config_version' => DomainRegistry::version($t)]);
    }

    public function monitoringSave(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $before = DomainRegistry::monitoring($t);
        $map = [];
        if (array_key_exists('network_events', $b)) $map['mon_network_events'] = $b['network_events'] ? '1' : '0';
        if (array_key_exists('discovery', $b)) $map['mon_discovery'] = $b['discovery'] ? '1' : '0';
        if (isset($b['discovery_hints'])) {
            $hints = is_array($b['discovery_hints']) ? $b['discovery_hints'] : explode(',', (string)$b['discovery_hints']);
            $hints = array_values(array_unique(array_filter(array_map(static fn ($h) => strtolower(trim((string)$h)), $hints), static fn ($h) => preg_match('/^[a-z0-9-]{2,20}$/', $h))));
            if (count($hints) > 20) throw new ApiException(422, 'validation_failed', 'At most 20 discovery hints.');
            $map['mon_discovery_hints'] = implode(',', $hints);
        }
        if (isset($b['interval_minutes'])) {
            $n = (int)$b['interval_minutes'];
            if ($n < 1 || $n > 1440) throw new ApiException(422, 'validation_failed', 'interval_minutes must be 1-1440.');
            $map['mon_interval_minutes'] = (string)$n;
        }
        foreach ($map as $k => $v) {
            Db::run('INSERT INTO settings (tenant_id, setting_key, setting_value) VALUES (?,?,?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)', [$t, $k, $v]);
        }
        $ver = DomainRegistry::bump($t);
        Audit::log($this->actor($req), 'registry_monitoring_updated', null, ['config_version' => $ver], $t, $before, DomainRegistry::monitoring($t));
        return $this->json($res, ['monitoring' => DomainRegistry::monitoring($t), 'config_version' => $ver]);
    }
}
