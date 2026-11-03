<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Db, DomainRegistry, Risk};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Slim\Routing\RouteCollectorProxy as Group;

/** Domain Discovery workflow: New -> Under Review -> Classified | Excluded. */
final class DiscoveryModule extends Controller
{
    private const STATUSES = ['new', 'under_review', 'classified', 'excluded'];

    public static function register(Group $g): void
    {
        $g->get('/discovery', [self::class, 'index'])->add(new Need('discovery.read'));
        $g->post('/discovery/delete', [self::class, 'delete'])->add(new Need('discovery.delete'));
        $g->get('/discovery/{id:\d+}/hosts', [self::class, 'hosts'])->add(new Need('discovery.read'));
        $g->post('/discovery/{id:\d+}', [self::class, 'action'])->add(new Need('discovery.write'));
    }

    public function index(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $status = (string)$this->q($req, 'status', 'open');
        $where = match (true) {
            $status === 'all' => '',
            in_array($status, self::STATUSES, true) => ' AND d.status = ' . Db::pdo()->quote($status),
            default => " AND d.status IN ('new','under_review')",
        };
        $rows = Db::all("SELECT d.id, d.domain, d.status, d.hit_count, d.first_seen, d.last_seen, d.notes, d.classified_service_id, d.updated_by,
                                (SELECT COUNT(*) FROM discovered_domain_hosts h WHERE h.discovered_id = d.id) workstations,
                                (SELECT s.service_name FROM ai_services s WHERE s.id = d.classified_service_id) service_name
                         FROM discovered_domains d WHERE d.tenant_id = ? $where ORDER BY d.hit_count DESC LIMIT 1000", [$t]);
        $counts = [];
        foreach (Db::all('SELECT status, COUNT(*) c FROM discovered_domains WHERE tenant_id = ? GROUP BY status', [$t]) as $r) $counts[$r['status']] = (int)$r['c'];
        return $this->json($res, ['domains' => $rows, 'counts' => $counts]);
    }

    public function hosts(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req);
        if (!Db::val('SELECT 1 FROM discovered_domains WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t])) throw new ApiException(404, 'not_found', 'Unknown domain.');
        return $this->json($res, ['hosts' => Db::all('SELECT computer_name, hit_count, first_seen, last_seen FROM discovered_domain_hosts WHERE discovered_id = ? ORDER BY hit_count DESC', [(int)$a['id']])]);
    }

    public function action(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $who = $this->actor($req); $b = $this->body($req);
        $d = Db::one('SELECT * FROM discovered_domains WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t]);
        if (!$d) throw new ApiException(404, 'not_found', 'Unknown domain.');
        $action = $b['action'] ?? '';
        $notes = isset($b['notes']) && is_string($b['notes']) ? mb_substr(trim($b['notes']), 0, 500) : $d['notes'];

        $simple = ['review' => 'under_review', 'exclude' => 'excluded', 'reopen' => 'new'];
        if (isset($simple[$action])) {
            Db::run('UPDATE discovered_domains SET status = ?, notes = ?, updated_by = ?, updated_at = UTC_TIMESTAMP() WHERE id = ?', [$simple[$action], $notes, $who, $d['id']]);
            Audit::log($who, 'discovery_' . $action, $d['domain'], null, $t, ['status' => $d['status']], ['status' => $simple[$action]]);
            return $this->json($res, ['status' => $simple[$action]]);
        }
        if ($action !== 'classify') throw new ApiException(422, 'validation_failed', 'Invalid action.');
        // Classifying adds registry rows, so it also needs registry.write.
        if (!\Saip\Security\Rbac::can($this->user($req)['role'], 'registry.write')) throw new ApiException(403, 'forbidden', 'Your role does not permit this action.');

        $classification = in_array($b['classification'] ?? 'unsanctioned', ['sanctioned', 'unsanctioned', 'under_review', 'excluded'], true) ? ($b['classification'] ?? 'unsanctioned') : 'unsanctioned';
        if (Db::val('SELECT 1 FROM ai_domains WHERE tenant_id = ? AND domain = ?', [$t, $d['domain']])) throw new ApiException(409, 'domain_in_use', 'This domain is already in the registry.');
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            if (!empty($b['service_id'])) {
                $sid = (int)$b['service_id'];
                if (!Db::val('SELECT 1 FROM ai_services WHERE id = ? AND tenant_id = ?', [$sid, $t])) throw new ApiException(404, 'not_found', 'Unknown service.');
            } else {
                $name = isset($b['service_name']) && is_string($b['service_name']) ? trim($b['service_name']) : '';
                if ($name === '' || mb_strlen($name) > 100) throw new ApiException(422, 'validation_failed', 'service_name is required.', ['service_name' => 'required']);
                if (Db::val('SELECT 1 FROM ai_services WHERE tenant_id = ? AND service_name = ?', [$t, $name])) throw new ApiException(409, 'duplicate', 'A service with this name exists; attach to it instead.');
                $life = ['sanctioned' => 'Formally Sanctioned', 'under_review' => 'Under Security Evaluation'][$classification] ?? 'Shadow Usage Detected';
                Db::run('INSERT INTO ai_services (tenant_id, service_name, provider, primary_domain, category, sanction_status, risk_score, lifecycle, source, created_by, updated_by)
                         VALUES (?,?,?,?, "Generative AI", ?, ?, ?, "discovered", ?, ?)',
                    [$t, $name, isset($b['provider']) && is_string($b['provider']) && $b['provider'] !== '' ? mb_substr($b['provider'], 0, 100) : 'Unknown',
                     $d['domain'], $classification, Risk::score('Internal', 50, 50, 50, 0), $life, $who, $who]);
                $sid = Db::insertId();
            }
            Db::run('INSERT INTO ai_domains (tenant_id, ai_service_id, domain, domain_type, matching_rule, first_observed, last_observed, created_by, updated_by)
                     VALUES (?,?,?, "secondary", "subdomain", ?, ?, ?, ?)', [$t, $sid, $d['domain'], $d['first_seen'], $d['last_seen'], $who, $who]);
            Db::run("UPDATE discovered_domains SET status = 'classified', classified_service_id = ?, notes = ?, updated_by = ?, updated_at = UTC_TIMESTAMP() WHERE id = ?", [$sid, $notes, $who, $d['id']]);
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        $v = DomainRegistry::bump($t);
        Audit::log($who, 'registry_domain_added', $d['domain'], ['from' => 'discovery', 'service_id' => $sid, 'config_version' => $v], $t, ['status' => $d['status']], ['status' => 'classified']);
        return $this->json($res, ['status' => 'classified', 'service_id' => $sid]);
    }

    /** POST discovery/delete {ids, preview?}: a hostname seen again is simply rediscovered. */
    public function delete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $rows = Db::all('SELECT id, domain FROM discovered_domains WHERE tenant_id = ? AND id IN (' . $this->in($ids) . ')', array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching discovery rows.');
        $ids = array_map(static fn ($r) => (int)$r['id'], $rows); $ph = $this->in($ids);
        $impact = ['records' => count($rows), 'names' => array_column($rows, 'domain')];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        Db::run("DELETE FROM discovered_domain_hosts WHERE discovered_id IN ($ph)", $ids);
        Db::run("DELETE FROM discovered_domains WHERE tenant_id = ? AND id IN ($ph)", array_merge([$t], $ids));
        Audit::log($this->actor($req), 'discovery_deleted', implode(', ', array_slice($impact['names'], 0, 5)), $impact, $t, $impact, null);
        return $this->json($res, ['deleted' => $impact]);
    }
}
