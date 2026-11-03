<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Db, DomainRegistry, Tenants, Validator, Xlsx};
use Saip\Http\Controller;
use Saip\Middleware\CollectorAuth;
use Saip\Middleware\RequirePermission as Need;
use Slim\Routing\RouteCollectorProxy as Group;

/** Workstations (per-computer activity, department mapping) and their collectors (lifecycle, credentials, deletion). */
final class FleetModule extends Controller
{
    public static function register(Group $g): void
    {
        $g->get('/workstations', [self::class, 'workstations'])->add(new Need('workstations.read'));
        $g->get('/workstations/history', [self::class, 'history'])->add(new Need('workstations.read'));
        $g->get('/services/{id:\d+}/workstations', [self::class, 'serviceWorkstations'])->add(new Need('inventory.read'));
        $g->get('/activity', [self::class, 'activity'])->add(new Need('workstations.read'));
        $g->post('/workstations/map', [self::class, 'map'])->add(new Need('workstations.write'));
        $g->post('/workstations/unmap', [self::class, 'unmap'])->add(new Need('workstations.write'));
        $g->get('/collectors', [self::class, 'collectors'])->add(new Need('collectors.read'));
        $g->post('/collectors/delete', [self::class, 'delete'])->add(new Need('collectors.delete'));
        $g->post('/collectors/{id:\d+}', [self::class, 'action'])->add(new Need('collectors.write'));
        $g->post('/enrollment/regenerate', [self::class, 'enrollment'])->add(new Need('collectors.write'));
        $g->get('/collector-package', [self::class, 'package'])->add(new Need('collectors.read'));
    }

    public function workstations(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        return $this->json($res, ['workstations' => Db::all(
            "SELECT c.id collector_id, c.computer_name, c.mac_address, c.status collector_status, c.last_seen collector_last_seen, c.collector_version,
                    i.department, i.business_unit, i.employee_reference,
                    COALESCE(a.ev,0) events_30d, COALESCE(a.svc,0) services_30d, COALESCE(a.shadow_ev,0) shadow_events_30d,
                    a.first_seen, a.last_event, COALESCE(a.days,0) active_days_30d
             FROM collectors c
             LEFT JOIN employee_inventory i ON i.tenant_id = c.tenant_id AND i.computer_name = c.computer_name
             LEFT JOIN (SELECT e.computer_name, COUNT(*) ev, COUNT(DISTINCT e.ai_service_id) svc, SUM(s.sanction_status = 'unsanctioned') shadow_ev,
                               MIN(e.event_timestamp) first_seen, MAX(e.event_timestamp) last_event, COUNT(DISTINCT DATE(e.event_timestamp)) days
                        FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id
                        WHERE e.tenant_id = ? AND e.event_timestamp >= UTC_TIMESTAMP() - INTERVAL 30 DAY GROUP BY e.computer_name) a
                    ON a.computer_name = c.computer_name
             WHERE c.tenant_id = ? ORDER BY events_30d DESC, c.computer_name", [$t, $t])]);
    }

    public function history(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $name = Validator::computerName($this->q($req, 'name'));
        if ($name === null) throw new ApiException(422, 'validation_failed', 'Invalid computer name.');
        $daily = Db::all('SELECT DATE(e.event_timestamp) d, s.service_name service, s.sanction_status status, COUNT(*) c
                          FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id
                          WHERE e.tenant_id = ? AND e.computer_name = ? AND e.event_timestamp >= UTC_TIMESTAMP() - INTERVAL 180 DAY
                          GROUP BY d, s.id ORDER BY d', [$t, $name]);
        $recent = Db::all('SELECT e.event_timestamp, s.service_name, e.query_domain, e.process_image FROM ai_usage_events e
                           JOIN ai_services s ON s.id = e.ai_service_id WHERE e.tenant_id = ? AND e.computer_name = ?
                           ORDER BY e.event_timestamp DESC LIMIT 25', [$t, $name]);
        return $this->json($res, ['computer_name' => $name, 'daily' => $daily, 'recent' => $recent]);
    }

    /** Window in days from ?days= (0 = all time). */
    private function window(Request $req): int
    {
        $d = (string)$this->q($req, 'days', '30');
        return $d === 'all' ? 0 : max(1, min(3650, (int)$d ?: 30));
    }

    /** GET services/{id}/workstations?days=: which computers a service was detected on, with consolidated counts. */
    public function serviceWorkstations(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $id = (int)$a['id']; $days = $this->window($req);
        $svc = Db::one('SELECT id, service_name FROM ai_services WHERE id = ? AND tenant_id = ?', [$id, $t]);
        if (!$svc) throw new ApiException(404, 'not_found', 'Unknown service.');
        $since = $days ? ' AND e.event_timestamp >= UTC_TIMESTAMP() - INTERVAL ' . $days . ' DAY' : '';
        $sinceN = $days ? ' AND n.event_timestamp >= UTC_TIMESTAMP() - INTERVAL ' . $days . ' DAY' : '';
        $rows = Db::all("SELECT e.computer_name, i.department, i.business_unit, c.status collector_status,
                    COUNT(*) events, COUNT(DISTINCT e.query_domain) domains, COUNT(DISTINCT DATE(e.event_timestamp)) active_days,
                    MIN(e.event_timestamp) first_seen, MAX(e.event_timestamp) last_seen,
                    (SELECT COUNT(*) FROM network_connection_events n WHERE n.tenant_id = e.tenant_id AND n.ai_service_id = e.ai_service_id AND n.computer_name = e.computer_name $sinceN) connections,
                    SUBSTRING_INDEX(GROUP_CONCAT(e.query_domain ORDER BY e.event_timestamp DESC SEPARATOR ','), ',', 1) last_domain,
                    c.id collector_id
                 FROM ai_usage_events e
                 LEFT JOIN employee_inventory i ON i.tenant_id = e.tenant_id AND i.computer_name = e.computer_name
                 LEFT JOIN collectors c ON c.id = e.collector_id
                 WHERE e.tenant_id = ? AND e.ai_service_id = ? $since
                 GROUP BY e.computer_name, i.department, i.business_unit, c.status, c.id ORDER BY events DESC, e.computer_name", [$t, $id]);
        return $this->json($res, ['service' => $svc, 'days' => $days, 'workstations' => $rows]);
    }

    /**
     * GET activity: the consolidated event log (DNS lookups and, when enabled, network connections), paged on the server.
     * Params: service_id, computer, days (7|30|90|365|all), page, size (10-100), q (search), sort + dir, filters computer_name/service_name/kind/process/host,
     * format=json|csv (csv exports everything matching, up to 50,000 rows). Tenant-scoped; computer names come from the authenticated collector.
     */
    public function activity(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $days = $this->window($req);
        $sid = (int)$this->q($req, 'service_id', 0);
        $pc = Validator::computerName($this->q($req, 'computer'));
        if ($sid && !Db::val('SELECT 1 FROM ai_services WHERE id = ? AND tenant_id = ?', [$sid, $t])) throw new ApiException(404, 'not_found', 'Unknown service.');
        $format = (string)$this->q($req, 'format', 'json');

        // scope shared by both event tables (index-friendly: tenant, service, computer, time)
        $scope = ' WHERE {a}.tenant_id = ?'; $sargs = [$t];
        if ($sid) { $scope .= ' AND {a}.ai_service_id = ?'; $sargs[] = $sid; }
        if ($pc) { $scope .= ' AND {a}.computer_name = ?'; $sargs[] = $pc; }
        if ($days) $scope .= ' AND {a}.event_timestamp >= UTC_TIMESTAMP() - INTERVAL ' . $days . ' DAY';
        $dns = "SELECT e.id, e.computer_name, e.event_timestamp, 'DNS' kind, e.query_domain host, e.process_image, COALESCE(e.query_status, '') detail, e.ai_service_id FROM ai_usage_events e" . str_replace('{a}', 'e', $scope);
        $net = "SELECT n.id + 1000000000000, n.computer_name, n.event_timestamp, 'Connection', COALESCE(n.destination_host, n.destination_ip), n.process_image, TRIM(CONCAT(n.destination_ip, ':', COALESCE(n.destination_port, ''), ' ', COALESCE(n.protocol, ''))), n.ai_service_id FROM network_connection_events n" . str_replace('{a}', 'n', $scope);
        $base = "SELECT y.id, y.computer_name, y.event_timestamp, y.kind, y.host, y.process_image, y.detail, s.service_name,
                        SUBSTRING_INDEX(REPLACE(COALESCE(y.process_image, ''), '\\\\', '/'), '/', -1) process
                 FROM (($dns) UNION ALL ($net)) y JOIN ai_services s ON s.id = y.ai_service_id";
        $args = array_merge($sargs, $sargs);

        // search and column filters
        $where = []; $wargs = [];
        $q = trim((string)$this->q($req, 'q', ''));
        if ($q !== '') { $like = '%' . addcslashes(mb_substr($q, 0, 100), '%_\\') . '%'; $where[] = '(z.host LIKE ? OR z.computer_name LIKE ? OR z.service_name LIKE ? OR z.process LIKE ? OR z.detail LIKE ?)'; array_push($wargs, $like, $like, $like, $like, $like); }
        $filters = (array)($req->getQueryParams()['f'] ?? []);
        $exact = ['computer_name' => 'z.computer_name', 'service_name' => 'z.service_name', 'kind' => 'z.kind', 'process' => 'z.process'];
        foreach ($exact as $k => $col) { if (isset($filters[$k]) && is_string($filters[$k]) && $filters[$k] !== '') { $where[] = "$col = ?"; $wargs[] = $filters[$k]; } }
        if (isset($filters['host']) && is_string($filters['host']) && $filters['host'] !== '') { $where[] = 'z.host LIKE ?'; $wargs[] = '%' . addcslashes($filters['host'], '%_\\') . '%'; }
        $w = $where ? ' WHERE ' . implode(' AND ', $where) : '';
        $cols = ['event_timestamp' => 'z.event_timestamp', 'computer_name' => 'z.computer_name', 'service_name' => 'z.service_name', 'kind' => 'z.kind', 'host' => 'z.host', 'process' => 'z.process', 'detail' => 'z.detail'];
        $sort = $cols[(string)$this->q($req, 'sort', 'event_timestamp')] ?? 'z.event_timestamp';
        $dir = strtolower((string)$this->q($req, 'dir', 'desc')) === 'asc' ? 'ASC' : 'DESC';
        $order = " ORDER BY $sort $dir, z.id DESC";

        if ($format === 'csv') {
            $rows = Db::all("SELECT z.* FROM ($base) z $w $order LIMIT 50000", array_merge($args, $wargs));
            Audit::log($this->actor($req), 'export_activity', null, ['rows' => count($rows), 'service_id' => $sid ?: null, 'computer' => $pc], $t);
            return $this->raw($res, $this->csv(['Time (UTC)', 'Computer', 'Service', 'Type', 'Host', 'Process', 'Detail'], array_map(static fn ($r) => [$r['event_timestamp'], $r['computer_name'], $r['service_name'], $r['kind'], $r['host'], $r['process_image'], $r['detail']], $rows)), 'text/csv; charset=utf-8', 'activity.csv');
        }
        $size = max(10, min(100, (int)$this->q($req, 'size', 25)));
        $page = max(1, (int)$this->q($req, 'page', 1));
        $total = (int)Db::val("SELECT COUNT(*) FROM ($base) z $w", array_merge($args, $wargs));
        $rows = Db::all("SELECT z.* FROM ($base) z $w $order LIMIT $size OFFSET " . (($page - 1) * $size), array_merge($args, $wargs));
        $facets = [];
        foreach (['computer_name', 'service_name', 'kind', 'process'] as $c) {   // distinct values within the scope (not the current filters), capped
            $facets[$c] = array_column(Db::all("SELECT DISTINCT z.$c v FROM ($base) z WHERE z.$c <> '' ORDER BY z.$c LIMIT 200", $args), 'v');
        }
        return $this->json($res, ['events' => $rows, 'total' => $total, 'page' => $page, 'size' => $size, 'facets' => $facets, 'days' => $days]);
    }

    public function map(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $name = Validator::computerName($b['computer_name'] ?? null);
        if ($name === null) throw new ApiException(422, 'validation_failed', 'Invalid computer name.');
        Db::run('INSERT INTO employee_inventory (tenant_id, computer_name, employee_reference, department, business_unit) VALUES (?,?,?,?,?)
                 ON DUPLICATE KEY UPDATE employee_reference = VALUES(employee_reference), department = VALUES(department), business_unit = VALUES(business_unit)',
            [$t, $name, $this->str($b, 'employee_reference', 100), $this->str($b, 'department', 100), $this->str($b, 'business_unit', 100)]);
        Audit::log($this->actor($req), 'inventory_mapped', $name, ['department' => $b['department'] ?? null], $t);
        return $this->json($res, ['status' => 'ok']);
    }

    public function unmap(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $name = Validator::computerName($b['computer_name'] ?? null);
        if ($name === null) throw new ApiException(422, 'validation_failed', 'Invalid computer name.');
        Db::run('DELETE FROM employee_inventory WHERE tenant_id = ? AND computer_name = ?', [$t, $name]);
        Audit::log($this->actor($req), 'inventory_unmapped', $name, null, $t);
        return $this->json($res, ['status' => 'ok']);
    }

    public function collectors(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        return $this->json($res, [
            'collectors' => Db::all("SELECT c.id, c.computer_name, c.mac_address, c.collector_uuid, c.status, c.registered_at, c.last_seen, c.collector_version,
                         c.config_version_applied, c.last_config_sync, c.failed_submissions, c.spool_depth, c.last_error, c.workstation_ip,
                         (c.last_seen IS NOT NULL AND c.last_seen >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE) online
                         FROM collectors c WHERE c.tenant_id = ? ORDER BY c.computer_name", [$t]),
            'config_version' => DomainRegistry::version($t), 'monitoring' => DomainRegistry::monitoring($t)]);
    }

    public function action(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $c = Db::one('SELECT * FROM collectors WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t]);
        if (!$c) throw new ApiException(404, 'not_found', 'Unknown collector.');
        $action = $b['action'] ?? '';
        if ($action === 'rotate') {
            $key = CollectorAuth::newApiKey();
            Db::run('UPDATE collectors SET api_key_hash = ? WHERE id = ?', [CollectorAuth::hashKey($key), $c['id']]);
            Audit::log($this->actor($req), 'credential_rotated', $c['collector_uuid'], ['computer_name' => $c['computer_name']], $t);
            return $this->json($res, ['api_key' => $key, 'note' => 'Shown once. Apply on the workstation with: Collect-AiUsage.ps1 -SetApiKey <key>']);
        }
        $map = ['authorize' => 'authorized', 'suspend' => 'suspended', 'revoke' => 'revoked'];
        if (!isset($map[$action])) throw new ApiException(422, 'validation_failed', 'Invalid action.');
        if ($action === 'authorize' && $c['status'] === 'revoked') throw new ApiException(409, 'revoked', 'A revoked collector cannot be re-authorized; re-register it.');
        Db::run('UPDATE collectors SET status = ? WHERE id = ?', [$map[$action], $c['id']]);
        Audit::log($this->actor($req), 'collector_' . $map[$action], $c['collector_uuid'], ['computer_name' => $c['computer_name'], 'from' => $c['status']], $t, ['status' => $c['status']], ['status' => $map[$action]]);
        return $this->json($res, ['status' => $map[$action]]);
    }

    /** POST collectors/delete {ids, data_only?, preview?}: data_only keeps the collector and clears what it sent. */
    public function delete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $dataOnly = !empty($b['data_only']);
        $rows = Db::all('SELECT id, computer_name FROM collectors WHERE tenant_id = ? AND id IN (' . $this->in($ids) . ')', array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching collectors.');
        $ids = array_map(static fn ($r) => (int)$r['id'], $rows); $ph = $this->in($ids);
        $names = array_values(array_unique(array_column($rows, 'computer_name')));
        $impact = [
            'records' => count($rows), 'names' => $names, 'data_only' => $dataOnly,
            'events' => (int)Db::val("SELECT COUNT(*) FROM ai_usage_events WHERE collector_id IN ($ph)", $ids),
            'network_events' => (int)Db::val("SELECT COUNT(*) FROM network_connection_events WHERE collector_id IN ($ph)", $ids),
            'heartbeats' => $dataOnly ? 0 : (int)Db::val("SELECT COUNT(*) FROM collector_heartbeats WHERE collector_id IN ($ph)", $ids),
        ];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            Db::run("DELETE FROM ai_usage_events WHERE collector_id IN ($ph)", $ids);
            Db::run("DELETE FROM network_connection_events WHERE collector_id IN ($ph)", $ids);
            if (!$dataOnly) {
                Db::run("DELETE FROM collectors WHERE tenant_id = ? AND id IN ($ph)", array_merge([$t], $ids));   // heartbeats cascade
                // Keep department mapping / discovery hits only while another collector still uses the same computer name.
                $gone = [];
                foreach ($names as $n) if (!Db::val('SELECT 1 FROM collectors WHERE tenant_id = ? AND computer_name = ?', [$t, $n])) $gone[] = $n;
                if ($gone) {
                    $gp = $this->in($gone);
                    Db::run("DELETE FROM employee_inventory WHERE tenant_id = ? AND computer_name IN ($gp)", array_merge([$t], $gone));
                    Db::run("DELETE h FROM discovered_domain_hosts h JOIN discovered_domains d ON d.id = h.discovered_id WHERE d.tenant_id = ? AND h.computer_name IN ($gp)", array_merge([$t], $gone));
                }
            }
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        Audit::log($this->actor($req), $dataOnly ? 'collector_data_cleared' : 'collector_deleted', implode(', ', array_slice($names, 0, 5)), $impact, $t, $impact, null);
        return $this->json($res, ['deleted' => $impact]);
    }

    /**
     * GET collector-package: SaipCollector.zip built from the collector/ folder (scripts, Sysmon configs, config template).
     * The template's serverUrl is this server's address as the browser reached it, so a workstation that downloads it has a working address.
     * It never contains the enrollment key (only its hash is stored) and never contains Sysmon64.exe (the installer downloads it from Microsoft).
     */
    public function package(Request $req, Response $res): Response
    {
        $dir = SAIP_ROOT . '/collector';
        $uri = $req->getUri();
        $port = $uri->getPort();
        $api = preg_replace('#/console/collector-package/?$#', '', $uri->getPath());   // e.g. /2026/saip/api/v1
        $url = ($b = \Saip\Config::get('base_url')) ? rtrim((string)$b, '/') . '/api/v1' : $uri->getScheme() . '://' . $uri->getHost() . ($port && !in_array($port, [80, 443], true) ? ":$port" : '') . $api;
        $files = [];
        foreach (glob($dir . '/*') ?: [] as $f) {
            $name = basename($f);
            if (!is_file($f) || !preg_match('/\.(ps1|xml|json)$/i', $name)) continue;
            $files["SaipCollector/$name"] = $name === 'collector.config.json' ? $this->configTemplate($f, $url) : (string)file_get_contents($f);
        }
        if (!isset($files['SaipCollector/Install-Collector.ps1'])) throw new ApiException(500, 'package_missing', 'The collector scripts are not installed on the server.');
        Audit::log($this->actor($req), 'collector_package_downloaded', null, ['files' => count($files)], $this->tid($req));
        return $this->raw($res, Xlsx::zip($files), 'application/zip', 'SaipCollector.zip');
    }

    private function configTemplate(string $file, string $url): string
    {
        $c = json_decode((string)file_get_contents($file), true) ?: [];
        $c['serverUrl'] = $url;
        $c['enrollmentKey'] = 'CHANGE-ME-enrollment-key';
        $c['allowInsecureHttp'] = str_starts_with($url, 'http://');
        return json_encode($c, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }

    public function enrollment(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $key = Tenants::newEnrollmentKey();
        Db::run('UPDATE tenants SET enrollment_key_hash = ? WHERE id = ?', [hash('sha256', $key), $t]);
        Audit::log($this->actor($req), 'enrollment_key_regenerated', null, null, $t);
        return $this->json($res, ['enrollment_key' => $key, 'note' => 'Shown once. Previously issued enrollment keys stop working; registered collectors are unaffected.']);
    }
}
