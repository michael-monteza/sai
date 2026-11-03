<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{Adoption, ApiException, Audit, Db, Iso, Reports, Risk, ServiceRepo, Xlsx};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Slim\Routing\RouteCollectorProxy as Group;

/** Executive dashboard, adoption analytics, reports (JSON/CSV/XLSX) and retention settings. */
final class AnalyticsModule extends Controller
{
    public static function register(Group $g): void
    {
        $g->get('/dashboard', [self::class, 'dashboard'])->add(new Need('dashboard.read'));
        $g->get('/dashboard/summary', [self::class, 'summary'])->add(new Need('reports.read'));
        $g->get('/adoption', [self::class, 'adoption'])->add(new Need('adoption.read'));
        $g->post('/adoption/settings', [self::class, 'adoptionSave'])->add(new Need('adoption.write'));
        $g->get('/export/adoption', [self::class, 'adoptionExport'])->add(new Need('adoption.read'));
        $g->get('/reports', [self::class, 'catalog'])->add(new Need('reports.read'));
        $g->get('/reports/{name:[a-z-]+}', [self::class, 'run'])->add(new Need('reports.read'));
        $g->get('/retention', [self::class, 'retention'])->add(new Need('reports.read'));
        $g->post('/retention', [self::class, 'retentionSave'])->add(new Need('retention.write'));
    }

    public function dashboard(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $services = ServiceRepo::rows($t);
        $active = array_values(array_filter($services, static fn ($s) => (int)$s['active'] === 1 && $s['in_inventory']));
        $shadow = array_values(array_filter($active, static fn ($s) => $s['sanction_status'] === 'unsanctioned'));
        $byLevel = ['Low' => 0, 'Medium' => 0, 'High' => 0, 'Critical' => 0];
        foreach ($active as $s) $byLevel[Risk::level((int)$s['risk_score'])]++;
        $sensitive = count(array_filter($active, static fn ($s) => (int)$s['events_30d'] > 0 && in_array($s['data_class'], ['Confidential', 'Restricted / PII'], true)));
        $col = Db::one("SELECT COUNT(*) total, COALESCE(SUM(status='authorized'),0) authorized,
                 COALESCE(SUM(status='authorized' AND last_seen >= UTC_TIMESTAMP() - INTERVAL 15 MINUTE),0) online FROM collectors WHERE tenant_id = ?", [$t]);
        $ev = Db::one('SELECT COUNT(*) events, COUNT(DISTINCT computer_name) workstations, MAX(event_timestamp) last_event FROM ai_usage_events WHERE tenant_id = ? AND event_timestamp >= UTC_TIMESTAMP() - INTERVAL 30 DAY', [$t]);
        $trend = Db::all('SELECT DATE(e.event_timestamp) d, s.sanction_status st, COUNT(*) c FROM ai_usage_events e JOIN ai_services s ON s.id = e.ai_service_id
                 WHERE e.tenant_id = ? AND e.event_timestamp >= UTC_TIMESTAMP() - INTERVAL 30 DAY GROUP BY d, st ORDER BY d', [$t]);
        $recent = array_slice(array_values(array_filter($shadow, static fn ($s) => (int)$s['events_30d'] > 0)), 0, 6);
        usort($recent, static fn ($a, $b) => strcmp((string)$b['last_seen'], (string)$a['last_seen']));
        $iso = Iso::summary($t);
        return $this->json($res, [
            'kpi' => ['total_services' => count($active), 'shadow' => count($shadow), 'shadow_ratio' => count($active) ? round(count($shadow) / count($active) * 100, 1) : 0,
                'critical' => $byLevel['Critical'], 'high' => $byLevel['High'], 'sensitive_active' => $sensitive,
                'iso_score' => $iso['score'], 'iso_tier' => $iso['tier'], 'iso_passed' => $iso['passed'], 'iso_total' => $iso['total']],
            'risk_distribution' => $byLevel, 'collectors' => $col, 'telemetry' => $ev, 'trend' => $trend, 'recent_shadow' => $recent,
            'unknown_domains' => (int)Db::val("SELECT COUNT(*) FROM discovered_domains WHERE tenant_id = ? AND status IN ('new','under_review')", [$t]),
            'pending_requests' => (int)Db::val("SELECT COUNT(*) FROM access_requests WHERE tenant_id = ? AND status = 'pending'", [$t]),
        ]);
    }

    public function summary(Request $req, Response $res): Response
    {
        return $this->json($res, Reports::summary($this->tid($req), Reports::days($this->q($req, 'days'))));
    }

    public function adoption(Request $req, Response $res): Response { return $this->json($res, Adoption::compute($this->tid($req))); }

    public function adoptionSave(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $s = Adoption::save($t, $this->body($req));
        Audit::log($this->actor($req), 'adoption_thresholds_changed', null, $s, $t);
        return $this->json($res, ['settings' => $s]);
    }

    public function adoptionExport(Request $req, Response $res): Response
    {
        $t = $this->tid($req); $d = Adoption::compute($t);
        $rows = array_map(static fn ($r) => [$r['computer_name'], $r['department'], $r['level'], $r['score'], $r['active_days'], $r['services'], $r['events'], $r['sanctioned_events'], $r['last_event']], $d['workstations']);
        Audit::log($this->actor($req), 'export_adoption', null, ['rows' => count($rows)], $t);
        return $this->raw($res, $this->csv(['Computer', 'Department', 'Adoption level', 'Score', 'Active days', 'AI services', 'Observed DNS events', 'Sanctioned-service events', 'Last observed (UTC)'], $rows), 'text/csv; charset=utf-8', 'ai-adoption.csv');
    }

    public function catalog(Request $req, Response $res): Response
    {
        $out = [];
        foreach (Reports::catalog() as $k => [$title, $desc]) $out[] = ['name' => $k, 'title' => $title, 'description' => $desc];
        return $this->json($res, ['reports' => $out]);
    }

    public function run(Request $req, Response $res, array $a): Response
    {
        $t = $this->tid($req);
        $cat = Reports::catalog(); $name = $a['name'];
        if (!isset($cat[$name])) throw new ApiException(404, 'not_found', 'Unknown report.');
        [$title, $desc, $cols] = $cat[$name];
        $days = Reports::days($this->q($req, 'days'));
        $format = (string)$this->q($req, 'format', 'json');
        if (!in_array($format, ['json', 'csv', 'xlsx'], true)) throw new ApiException(422, 'validation_failed', 'format must be json, csv or xlsx.');
        $rows = Reports::rows($name, $t, $days);
        if ($format === 'json') return $this->json($res, ['name' => $name, 'title' => $title, 'description' => $desc, 'days' => $days, 'columns' => $cols, 'rows' => $rows, 'limitations' => Reports::LIMITATIONS]);
        $table = array_map(static fn (array $r) => array_map(static fn ($k) => $r[$k] ?? null, array_keys($cols)), $rows);
        Audit::log($this->actor($req), 'report_export', $name, ['format' => $format, 'days' => $days, 'rows' => count($table)], $t);
        $file = $name . '-' . gmdate('Ymd');
        if ($format === 'xlsx') return $this->raw($res, Xlsx::build($title, array_values($cols), $table), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', "$file.xlsx");
        return $this->raw($res, $this->csv(array_values($cols), $table), 'text/csv; charset=utf-8', "$file.csv");
    }

    public function retention(Request $req, Response $res): Response { return $this->json($res, ['retention' => Reports::retention($this->tid($req))]); }

    public function retentionSave(Request $req, Response $res): Response
    {
        $t = $this->tid($req);
        $before = Reports::retention($t);
        $s = Reports::saveRetention($t, $this->body($req));
        Audit::log($this->actor($req), 'retention_settings_changed', null, $s, $t, $before, $s);
        return $this->json($res, ['retention' => $s]);
    }
}
