<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Db, DomainRegistry, Iso, Risk, ServiceRepo, Validator};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Slim\Routing\RouteCollectorProxy as Group;

/** Governance: AI usage policies, staff access-request queue, ISO/IEC 42001 control register. */
final class GovernanceModule extends Controller
{
    private const POLICY_STATUS = ['Enforced', 'Draft', 'Disabled'];

    public static function register(Group $g): void
    {
        $g->get('/policies', [self::class, 'policies'])->add(new Need('governance.read'));
        $g->post('/policies', [self::class, 'policyCreate'])->add(new Need('governance.write'));
        $g->post('/policies/delete', [self::class, 'policyDelete'])->add(new Need('governance.delete'));
        $g->post('/policies/{id:\d+}', [self::class, 'policyUpdate'])->add(new Need('governance.write'));
        $g->get('/requests', [self::class, 'requests'])->add(new Need('governance.read'));
        $g->post('/requests', [self::class, 'requestCreate'])->add(new Need('governance.write'));
        $g->post('/requests/delete', [self::class, 'requestDelete'])->add(new Need('governance.delete'));
        $g->post('/requests/{id:\d+}', [self::class, 'requestUpdate'])->add(new Need('governance.write'));
        $g->post('/requests/{id:\d+}/decide', [self::class, 'requestDecide'])->add(new Need('governance.write'));
        $g->get('/iso', [self::class, 'iso'])->add(new Need('iso.read'));
        $g->post('/iso/controls/{id:\d+}', [self::class, 'isoControl'])->add(new Need('iso.write'));
        $g->get('/export/iso', [self::class, 'isoExport'])->add(new Need('iso.read'));
    }

    // ---- policies ----
    public function policies(Request $req, Response $res): Response
    {
        return $this->json($res, ['policies' => Db::all('SELECT * FROM policies WHERE tenant_id = ? ORDER BY id', [$this->tid($req)])]);
    }

    private function policyFields(array $b, bool $partial = false): array
    {
        $f = [];
        if (!$partial || array_key_exists('name', $b)) $f['name'] = $this->str($b, 'name', 150, true);
        if (!$partial || array_key_exists('policy_type', $b)) $f['policy_type'] = $this->str($b, 'policy_type', 60) ?? 'General';
        if (!$partial || array_key_exists('description', $b)) $f['description'] = $this->str($b, 'description', 500);
        if (!$partial || array_key_exists('status', $b)) {
            if (!in_array($b['status'] ?? 'Draft', self::POLICY_STATUS, true)) throw new ApiException(422, 'validation_failed', 'Invalid status.', ['status' => 'invalid']);
            $f['status'] = $b['status'] ?? 'Draft';
        }
        return $f;
    }

    public function policyCreate(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $f = $this->policyFields($this->body($req));
        if (Db::val('SELECT 1 FROM policies WHERE tenant_id = ? AND name = ?', [$t, $f['name']])) throw new ApiException(409, 'duplicate', 'A policy with this name exists.');
        Db::run('INSERT INTO policies (tenant_id, name, policy_type, status, description) VALUES (?,?,?,?,?)', [$t, $f['name'], $f['policy_type'], $f['status'], $f['description']]);
        $id = Db::insertId();
        Audit::log($this->actor($req), 'policy_created', $f['name'], null, $t, null, $f);
        return $this->json($res, ['id' => $id], 201);
    }

    public function policyUpdate(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req);
        $pol = Db::one('SELECT * FROM policies WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t]);
        if (!$pol) throw new ApiException(404, 'not_found', 'Unknown policy.');
        $f = $this->policyFields($this->body($req), true);
        if (!$f) throw new ApiException(422, 'validation_failed', 'Nothing to update.');
        if (isset($f['name']) && $f['name'] !== $pol['name'] && Db::val('SELECT 1 FROM policies WHERE tenant_id = ? AND name = ? AND id <> ?', [$t, $f['name'], $pol['id']])) throw new ApiException(409, 'duplicate', 'A policy with this name exists.');
        Db::run('UPDATE policies SET ' . implode(', ', array_map(static fn ($k) => "`$k` = ?", array_keys($f))) . ' WHERE id = ?', array_merge(array_values($f), [$pol['id']]));
        Audit::log($this->actor($req), 'policy_updated', $pol['name'], null, $t, array_intersect_key($pol, $f), $f);
        return $this->json($res, ['status' => 'ok']);
    }

    public function policyDelete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $rows = Db::all('SELECT id, name FROM policies WHERE tenant_id = ? AND id IN (' . $this->in($ids) . ')', array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching policies.');
        $impact = ['records' => count($rows), 'names' => array_column($rows, 'name')];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        $rid = array_map(static fn ($r) => (int)$r['id'], $rows);
        Db::run('DELETE FROM policies WHERE tenant_id = ? AND id IN (' . $this->in($rid) . ')', array_merge([$t], $rid));
        Audit::log($this->actor($req), 'policy_deleted', implode(', ', array_slice($impact['names'], 0, 5)), $impact, $t, $impact, null);
        return $this->json($res, ['deleted' => $impact]);
    }

    // ---- access requests ----
    public function requests(Request $req, Response $res): Response
    {
        return $this->json($res, ['requests' => Db::all("SELECT * FROM access_requests WHERE tenant_id = ? ORDER BY status = 'pending' DESC, created_at DESC LIMIT 500", [$this->tid($req)])]);
    }

    private function requestFields(array $b): array
    {
        $domain = isset($b['domain']) && $b['domain'] !== '' ? Validator::hostname($b['domain']) : null;
        if (isset($b['domain']) && $b['domain'] !== '' && $domain === null) throw new ApiException(422, 'validation_failed', 'Invalid domain.', ['domain' => 'invalid']);
        return ['tool_name' => $this->str($b, 'tool_name', 150, true), 'domain' => $domain, 'requester' => $this->str($b, 'requester', 150, true),
                'justification' => $this->str($b, 'justification', 500, true), 'data_class' => $this->str($b, 'data_class', 80) ?? 'Internal'];
    }

    public function requestCreate(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $f = $this->requestFields($this->body($req));
        Db::run('INSERT INTO access_requests (tenant_id, tool_name, domain, requester, justification, data_class) VALUES (?,?,?,?,?,?)', [$t, $f['tool_name'], $f['domain'], $f['requester'], $f['justification'], $f['data_class']]);
        $id = Db::insertId();
        Audit::log($this->actor($req), 'request_submitted', $f['tool_name'], null, $t, null, $f);
        return $this->json($res, ['id' => $id], 201);
    }

    public function requestUpdate(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req);
        $r = Db::one("SELECT * FROM access_requests WHERE id = ? AND tenant_id = ? AND status = 'pending'", [(int)$a['id'], $t]);
        if (!$r) throw new ApiException(404, 'not_found', 'No such pending request.');
        $f = $this->requestFields($this->body($req));
        Db::run('UPDATE access_requests SET tool_name = ?, domain = ?, requester = ?, justification = ?, data_class = ? WHERE id = ?', [$f['tool_name'], $f['domain'], $f['requester'], $f['justification'], $f['data_class'], $r['id']]);
        Audit::log($this->actor($req), 'request_updated', $r['tool_name'], null, $t, array_intersect_key($r, $f), $f);
        return $this->json($res, ['status' => 'ok']);
    }

    public function requestDelete(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $b = $this->body($req); $ids = $this->ids($b);
        $rows = Db::all('SELECT id, tool_name FROM access_requests WHERE tenant_id = ? AND id IN (' . $this->in($ids) . ')', array_merge([$t], $ids));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching requests.');
        $impact = ['records' => count($rows), 'names' => array_column($rows, 'tool_name')];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        $rid = array_map(static fn ($r) => (int)$r['id'], $rows);
        Db::run('DELETE FROM access_requests WHERE tenant_id = ? AND id IN (' . $this->in($rid) . ')', array_merge([$t], $rid));
        Audit::log($this->actor($req), 'request_deleted', implode(', ', array_slice($impact['names'], 0, 5)), $impact, $t, $impact, null);
        return $this->json($res, ['deleted' => $impact]);
    }

    public function requestDecide(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $u = $this->actor($req); $b = $this->body($req);
        $r = Db::one("SELECT * FROM access_requests WHERE id = ? AND tenant_id = ? AND status = 'pending'", [(int)$a['id'], $t]);
        if (!$r) throw new ApiException(404, 'not_found', 'No such pending request.');
        $decision = $b['decision'] ?? '';
        if (!in_array($decision, ['approve', 'reject'], true)) throw new ApiException(422, 'validation_failed', 'decision must be approve or reject.');
        $serviceId = null;
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            if ($decision === 'approve') {
                $svc = Db::one('SELECT id, primary_domain FROM ai_services WHERE tenant_id = ? AND LOWER(service_name) = LOWER(?)', [$t, $r['tool_name']]);
                if ($svc) {
                    $serviceId = (int)$svc['id'];
                    Db::run("UPDATE ai_services SET sanction_status='sanctioned', lifecycle='Formally Sanctioned', updated_at=UTC_TIMESTAMP(), updated_by=? WHERE id=?", [$u, $serviceId]);
                } else {
                    $domain = Validator::hostname($b['domain'] ?? $r['domain'] ?? null);
                    if ($domain === null) throw new ApiException(422, 'domain_required', 'Enter the service domain so it can be added to the registry.', ['domain' => 'required']);
                    ServiceRepo::assertDomainsFree($t, [$domain], 0);
                    Db::run('INSERT INTO ai_services (tenant_id, service_name, provider, primary_domain, category, sanction_status, data_class, risk_score, owner, purpose, data_categories, lifecycle, source, created_by, updated_by)
                             VALUES (?,?,?,?,?, "sanctioned", "Internal", ?, ?, ?, ?, "Formally Sanctioned", "request", ?, ?)',
                        [$t, $r['tool_name'], 'Unknown', $domain, 'Generative AI', Risk::score('Internal', 50, 50, 50, 0), $r['requester'], $r['justification'], $r['data_class'], $u, $u]);
                    $serviceId = Db::insertId();
                    Db::run('INSERT INTO ai_domains (tenant_id, ai_service_id, domain, created_by, updated_by) VALUES (?,?,?,?,?)', [$t, $serviceId, $domain, $u, $u]);
                }
            }
            Db::run('UPDATE access_requests SET status = ?, decided_at = UTC_TIMESTAMP(), decided_by = ?, service_id = ? WHERE id = ?', [$decision === 'approve' ? 'approved' : 'rejected', $u, $serviceId, $r['id']]);
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        DomainRegistry::bump($t);
        Audit::log($u, 'request_' . $decision . 'd', $r['tool_name'], ['service_id' => $serviceId], $t, ['status' => 'pending'], ['status' => $decision === 'approve' ? 'approved' : 'rejected']);
        return $this->json($res, ['status' => 'ok', 'service_id' => $serviceId]);
    }

    // ---- ISO/IEC 42001 ----
    public function iso(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        return $this->json($res, Iso::summary($t) + ['evidence' => Iso::evidence($t)]);
    }

    public function isoControl(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req); $b = $this->body($req);
        $c = Db::one('SELECT * FROM iso_controls WHERE id = ? AND tenant_id = ?', [(int)$a['id'], $t]);
        if (!$c) throw new ApiException(404, 'not_found', 'Unknown control.');
        $compliant = array_key_exists('compliant', $b) ? ($b['compliant'] ? 1 : 0) : (int)$c['compliant'];
        $evidence = array_key_exists('evidence', $b) ? $this->str($b, 'evidence', 300) : $c['evidence'];
        $notes = array_key_exists('notes', $b) ? $this->str($b, 'notes', 500) : $c['notes'];
        if ($compliant === 1 && ($evidence === null || $evidence === '')) throw new ApiException(422, 'evidence_required', 'Record the evidence before marking a control compliant.', ['evidence' => 'required']);
        Db::run('UPDATE iso_controls SET compliant=?, evidence=?, notes=?, updated_at=UTC_TIMESTAMP(), updated_by=? WHERE id=?', [$compliant, $evidence, $notes, $this->actor($req), $c['id']]);
        Audit::log($this->actor($req), 'iso_control_updated', $c['control_code'], null, $t, ['compliant' => (int)$c['compliant'], 'evidence' => $c['evidence']], ['compliant' => $compliant, 'evidence' => $evidence]);
        return $this->json($res, ['status' => 'ok']);
    }

    public function isoExport(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $tenant = Db::one('SELECT name FROM tenants WHERE id = ?', [$t]);
        $payload = ['company' => $tenant['name'], 'generated_utc' => gmdate('c'), 'readiness' => Iso::summary($t), 'evidence' => Iso::evidence($t),
                    'services' => array_map(static fn ($s) => array_intersect_key($s, array_flip(['service_name', 'provider', 'sanction_status', 'lifecycle', 'risk_score', 'data_class', 'owner'])), ServiceRepo::rows($t))];
        Audit::log($this->actor($req), 'export_iso', null, null, $t);
        return $this->raw($res, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), 'application/json', 'iso42001-evidence.json');
    }
}
